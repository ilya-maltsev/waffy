#!/bin/sh
# ───── waffy E2E integration test ─────
#
# Runs inside a Docker container with:
#   - compiled rules.bin mounted at /var/waffy/rules.bin
#   - nginx with waffy module running on localhost:80
#   - curl available
#
# Usage: called from docker-compose or directly
#   docker exec waffy-nginx /test/e2e_test.sh
#
# Exit codes: 0 = all passed, 1 = failures

PASS=0
FAIL=0
NGINX_URL="http://localhost:80"

pass() {
    PASS=$((PASS + 1))
    printf "  PASS: %s\n" "$1"
}

fail() {
    FAIL=$((FAIL + 1))
    printf "  FAIL: %s\n" "$1"
}

check_status() {
    local desc="$1"
    local expected="$2"
    local actual="$3"

    if [ "$actual" = "$expected" ]; then
        pass "$desc (HTTP $actual)"
    else
        fail "$desc — expected HTTP $expected, got HTTP $actual"
    fi
}

echo "=== waffy E2E integration tests ==="
echo ""

# ─── Test 1: Health endpoint (waffy off) should return 200 ───
echo "[1] Health endpoint (waffy off)"
status=$(curl -s -o /dev/null -w "%{http_code}" "$NGINX_URL/health")
check_status "GET /health returns 200" "200" "$status"

# ─── Test 2: Valid POST to /api/v1/users should pass ───
echo "[2] Valid POST /api/v1/users"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$NGINX_URL/api/v1/users" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig" \
    -d '{"name":"Alice Smith","email":"alice@test.com","age":30,"role":"user"}')
check_status "Valid JSON body passes" "200" "$status"

# ─── Test 3: SQL injection in name should be blocked ───
echo "[3] SQL injection in name field"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$NGINX_URL/api/v1/users" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig" \
    -d '{"name":"1 UNION SELECT * FROM users--","email":"alice@test.com","age":30,"role":"user"}')
check_status "SQL injection blocked" "403" "$status"

# ─── Test 4: Invalid age (string instead of integer) should be blocked ───
echo "[4] Invalid age type"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$NGINX_URL/api/v1/users" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig" \
    -d '{"name":"Bob","email":"bob@test.com","age":"not_a_number","role":"user"}')
check_status "Non-integer age blocked" "403" "$status"

# ─── Test 5: Invalid role (not in enum) should be blocked ───
echo "[5] Invalid role enum"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$NGINX_URL/api/v1/users" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig" \
    -d '{"name":"Bob","email":"bob@test.com","age":25,"role":"superadmin"}')
check_status "Invalid role value blocked" "403" "$status"

# ─── Test 6: Age out of range should be blocked ───
echo "[6] Age out of range"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$NGINX_URL/api/v1/users" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig" \
    -d '{"name":"Bob","email":"bob@test.com","age":999,"role":"user"}')
check_status "Age > 150 blocked" "403" "$status"

# ─── Test 7: Missing required Authorization header ───
echo "[7] Missing Authorization header"
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$NGINX_URL/api/v1/users" \
    -H "Content-Type: application/json" \
    -d '{"name":"Bob","email":"bob@test.com","age":25,"role":"user"}')
check_status "Missing required header blocked" "403" "$status"

# ─── Summary ───
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
