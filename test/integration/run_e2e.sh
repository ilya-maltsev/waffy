#!/bin/sh
# ───── waffy full E2E pipeline ─────
#
# Orchestrates: compile rules → start nginx → run tests → cleanup
# All steps run in Docker containers.
#
# Usage from project root:
#   docker build -f docker/Dockerfile.compiler -t waffy-compiler .
#   docker build -f docker/Dockerfile.nginx -t waffy-nginx .
#   sh test/integration/run_e2e.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== waffy E2E Pipeline ==="
echo ""

# ─── Step 1: Compile rules from example YAML profiles ───
echo "[Step 1] Compiling rules..."

# Create temp directory for rules.bin
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

docker run --rm \
    -v "$PROJECT_ROOT/rules/examples:/profiles:ro" \
    -v "$TMPDIR:/output" \
    waffy-compiler \
    --profiles /profiles --output /output/rules.bin

if [ ! -f "$TMPDIR/rules.bin" ]; then
    echo "FAIL: rules.bin not created"
    exit 1
fi
echo "  OK: rules.bin created ($(wc -c < "$TMPDIR/rules.bin") bytes)"
echo ""

# ─── Step 2: Create a minimal nginx config for E2E test ───
# This config doesn't need proxy_pass — uses return directive
cat > "$TMPDIR/e2e.conf" << 'NGINX_CONF'
waffy_rules /var/waffy/rules.bin;

server {
    listen 80;
    server_name _;

    location /api/v1/users {
        waffy on;
        waffy_mode enforce;
        waffy_body_parser json;
        waffy_max_body_size 16k;
        waffy_on_violation 403;

        return 200 '{"status":"ok"}';
        add_header Content-Type application/json;
    }

    location /api/v1/search {
        waffy on;
        waffy_mode enforce;
        waffy_on_violation 403;

        return 200 '{"results":[]}';
        add_header Content-Type application/json;
    }

    location /health {
        waffy off;
        return 200 '{"status":"healthy"}';
        add_header Content-Type application/json;
    }

    location / {
        waffy on;
        waffy_mode detect;
        return 200 '{"status":"ok"}';
        add_header Content-Type application/json;
    }
}
NGINX_CONF

echo "[Step 2] Starting nginx with waffy module..."

# Remove old container if exists
docker rm -f waffy-e2e-nginx 2>/dev/null || true

docker run -d --name waffy-e2e-nginx \
    -v "$TMPDIR/rules.bin:/var/waffy/rules.bin:ro" \
    -v "$TMPDIR/e2e.conf:/etc/nginx/conf.d/default.conf:ro" \
    -p 18080:80 \
    waffy-nginx

# Wait for nginx to be ready
sleep 1

# Verify nginx is running
if ! docker exec waffy-e2e-nginx nginx -t 2>/dev/null; then
    echo "FAIL: nginx config test failed"
    docker logs waffy-e2e-nginx
    docker rm -f waffy-e2e-nginx 2>/dev/null
    exit 1
fi
echo "  OK: nginx running on port 18080"
echo ""

# ─── Step 3: Run E2E tests ───
echo "[Step 3] Running E2E tests..."
echo ""

PASS=0
FAIL=0
URL="http://localhost:18080"

check() {
    desc="$1"; expected="$2"; actual="$3"
    if [ "$actual" = "$expected" ]; then
        PASS=$((PASS + 1))
        printf "  PASS: %s (HTTP %s)\n" "$desc" "$actual"
    else
        FAIL=$((FAIL + 1))
        printf "  FAIL: %s — expected HTTP %s, got HTTP %s\n" "$desc" "$expected" "$actual"
    fi
}

# Test 1: Health (waffy off)
s=$(curl -s -o /dev/null -w "%{http_code}" "$URL/health")
check "GET /health (waffy off)" "200" "$s"

# Test 2: Valid POST
s=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$URL/api/v1/users" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig" \
    -d '{"name":"Alice Smith","email":"alice@test.com","age":30,"role":"user"}')
check "Valid POST /api/v1/users" "200" "$s"

# Test 3: SQL injection in name
s=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$URL/api/v1/users" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig" \
    -d '{"name":"1 UNION SELECT * FROM users--","email":"a@b.com","age":30,"role":"user"}')
check "SQL injection in name blocked" "403" "$s"

# Test 4: Invalid age type
s=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$URL/api/v1/users" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig" \
    -d '{"name":"Bob","email":"bob@test.com","age":"not_a_number","role":"user"}')
check "Non-integer age blocked" "403" "$s"

# Test 5: Invalid enum value
s=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$URL/api/v1/users" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig" \
    -d '{"name":"Bob","email":"bob@test.com","age":25,"role":"superadmin"}')
check "Invalid enum role blocked" "403" "$s"

# Test 6: Age out of range
s=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$URL/api/v1/users" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig" \
    -d '{"name":"Bob","email":"bob@test.com","age":999,"role":"user"}')
check "Age > 150 blocked" "403" "$s"

# Test 7: Missing required header
s=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$URL/api/v1/users" \
    -H "Content-Type: application/json" \
    -d '{"name":"Bob","email":"bob@test.com","age":25,"role":"user"}')
check "Missing Authorization header blocked" "403" "$s"

# Test 8: Detect mode (should pass through even with bad data)
s=$(curl -s -o /dev/null -w "%{http_code}" "$URL/some/other/path?x=<script>alert(1)</script>")
check "Detect mode passes through" "200" "$s"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

# ─── Cleanup ───
docker rm -f waffy-e2e-nginx 2>/dev/null

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
echo ""
echo "All E2E tests passed!"
exit 0
