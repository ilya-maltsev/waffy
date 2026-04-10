# waffy

**WAF for you** — a whitelist application firewall for nginx that learns from your real traffic.

```
Traditional WAF:  "block anything that LOOKS like an attack"    → easy to bypass
waffy:            "only allow what LOOKS like your app"         → must match AND exploit
```

waffy observes actual traffic flowing through nginx, builds strict per-endpoint parameter profiles (types, lengths, patterns, allowed values), and rejects anything that doesn't match. No generic rule sets. No exclusion tuning. Just your app's real behavior, compiled into fast whitelist rules.

## Why not ModSecurity / NAXSI?

| | ModSecurity | NAXSI | waffy |
|---|---|---|---|
| Approach | 3000+ generic blacklist rules | Score-based blacklist | Learned whitelist per endpoint |
| Bypass resistance | Medium | Medium | High — attacker must match app behavior |
| Latency | 10-200ms | 1-10ms | **1-5ms** |
| False positives | High (needs weeks of tuning) | Medium | Low (learned from real traffic) |
| Maintenance | Update CRS, manage exclusions | Manual | Continuous learning |

The fundamental problem: blacklist WAFs try to enumerate everything that's bad. waffy enumerates what's good — which is a much smaller, tighter set.

## How it works

```
  LEARN                          COMPILE                      ENFORCE
  ─────                          ───────                      ───────
  Analyze 1-2 weeks        →     Generate per-location   →    Validate every request
  of real traffic                 whitelist rules               in <5ms

  "POST /api/users sends         name: string, 1-64 chars     name="Alice" → PASS
   name, email, age, role"        email: email pattern          age="young"  → BLOCK
                                  age: integer [0-150]          foo=bar      → BLOCK (unknown param)
                                  role: enum [user,editor]      
```

**Three phases, safe rollout:**

```
Week 1-2:  waffy_mode learn;    →  passive traffic capture
Week 3:    waffy-compile        →  generate rules, human review
Week 3-4:  waffy_mode detect;   →  shadow mode, log violations, don't block
Week 5:    waffy_mode enforce;  →  active blocking
```

## Quick start

### Build nginx with waffy

```bash
# Get nginx source
wget http://nginx.org/download/nginx-1.27.0.tar.gz
tar xzf nginx-1.27.0.tar.gz
cd nginx-1.27.0

# Build with waffy module
./configure --add-module=/path/to/waffy/nginx-module
make && sudo make install
```

Or with Docker:

```bash
cd waffy
docker compose -f docker/docker-compose.yml up
```

### 1. Configure learning

Add the learning log format and enable learn mode in your nginx config:

```nginx
# Capture traffic for learning
log_format waffy_learn escape=json
    '{"method":"$request_method",'
    '"uri":"$uri",'
    '"args":"$args",'
    '"content_type":"$content_type",'
    '"body":"$request_body",'
    '"status":$status,'
    '"headers":{"host":"$host","authorization":"$http_authorization"}}';

server {
    waffy_rules /var/waffy/rules.bin;
    access_log /var/log/nginx/waffy_learn.log waffy_learn;

    location /api/v1/users {
        waffy on;
        waffy_mode learn;
        proxy_pass http://backend;
    }
}
```

### 2. Learn from traffic

```bash
pip install ./learn

# Learn from access log (after 1-2 weeks of traffic)
waffy-learn from-log /var/log/nginx/waffy_learn.log --output ./profiles

# Or bootstrap from a HAR file
waffy-learn from-har recording.har --output ./profiles
```

This produces YAML profiles like:

```yaml
# Auto-generated — review before compiling
location: "/api/v1/users"
method: POST
strict_mode: true
parameters:
  - name: "name"
    source: body
    required: true
    type: string
    constraints:
      min_length: 1
      max_length: 64
      regex: "^[\\p{L}\\s\\-'.,]+$"

  - name: "age"
    source: body
    required: false
    type: integer
    constraints:
      min: 0
      max: 150

  - name: "role"
    source: body
    type: enum
    constraints:
      values: ["user", "editor", "admin"]
```

### 3. Review and compile

```bash
# Inspect what was learned
waffy-ctl rules list --dir ./profiles

# Compile to binary rule store
waffy-compile --profiles ./profiles --output /var/waffy/rules.bin
```

### 4. Enable enforcement

```nginx
location /api/v1/users {
    waffy on;
    waffy_mode enforce;      # or detect for shadow mode first
    waffy_body_parser json;
    waffy_max_body_size 16k;
    waffy_on_violation 403;
    proxy_pass http://backend;
}
```

```bash
nginx -s reload
```

## nginx directives

| Directive | Context | Values | Default |
|---|---|---|---|
| `waffy` | http, server, location | `on` \| `off` | `off` |
| `waffy_rules` | http | path to `rules.bin` | - |
| `waffy_mode` | http, server, location | `enforce` \| `detect` \| `learn` \| `off` | `off` |
| `waffy_body_parser` | location | `json` \| `form` \| `multipart` \| `auto` | `auto` |
| `waffy_max_body_size` | http, server, location | size | `16k` |
| `waffy_on_violation` | http, server, location | HTTP status code | `403` |

## Architecture

```
              ┌───────────────────────┐
              │  nginx + waffy module │
 request ────►  (C, inline, <5ms)    ├────► upstream
              │                       │
              │  mmap'd rule store    │
              └───────────┬───────────┘
                          │
              ┌───────────┴───────────┐
              │   rules.bin (mmap)    │
              └───────────┬───────────┘
                          │ compiled from
           ┌──────────────┴──────────────┐
           │                             │
  ┌────────┴─────────┐      ┌───────────┴────────┐
  │  waffy-learn     │      │  waffy-compile     │
  │  (Python)        │ ───► │  (Go)              │
  │  traffic → YAML  │      │  YAML → binary     │
  └──────────────────┘      └────────────────────┘
```

**Three components, each in the right language:**

| Component | Language | Role |
|---|---|---|
| `nginx-module/` | C | Inline request validation. Zero-alloc hot path, mmap'd rules, PCRE2 regex. |
| `learn/` | Python | Offline traffic analysis. Type inference, pattern generalization, profile export. |
| `compiler/` | Go | Rule compilation. YAML profiles to binary store. CLI management tools. |

## What waffy catches

**Strong coverage** (whitelist-based):
- SQL injection, XSS, command injection in typed parameters
- Parameter tampering and mass assignment (unknown params rejected)
- API schema violations (wrong types, missing required fields)
- Scanner/fuzzer noise (random params blocked immediately)

**Hybrid coverage** (whitelist + targeted blacklist for free-text fields):
- Injection in search queries, comments, and other free-form inputs
- Pattern-based detection as a second layer where whitelisting alone isn't tight enough

## Performance

waffy validates per-location, not globally. Each endpoint has 5-20 specific rules instead of 3000+ generic ones.

```
ModSecurity:  Request → ALL 3000 rules → exclusion checks → decision     10-200ms
waffy:        Request → hash(location) → 5-20 rules → decision           1-5ms
```

The enforcement module makes zero dynamic allocations, zero disk reads, and zero network calls at request time. Rules live in mmap'd shared memory. Regex patterns are pre-compiled DFA (no backtracking, no ReDoS).

## Project structure

```
waffy/
├── nginx-module/           # C — nginx WAF module
│   ├── ngx_http_waffy_module.c
│   ├── waffy_rule_engine.{c,h}
│   ├── waffy_parser.{c,h}
│   ├── waffy_shm.{c,h}
│   └── waffy_types.h
├── learn/                  # Python — traffic learning engine
│   ├── waffy_learn/
│   │   ├── analyzer.py     # Type inference (12 types)
│   │   ├── profiler.py     # Per-location profile builder
│   │   ├── capture.py      # Log/HAR parsers
│   │   ├── patterns.py     # Regex generalization
│   │   └── cli.py
│   └── tests/
├── compiler/               # Go — rule compiler + CLI
│   ├── cmd/waffy-compile/
│   ├── cmd/waffy-ctl/
│   └── internal/
├── rules/examples/         # Example YAML profiles
├── docker/                 # Docker build + compose
└── CONCEPT.md              # Full architecture document
```

## Type inference

The learning engine auto-detects parameter types from observed values:

| Type | Example | Constraint generated |
|---|---|---|
| integer | `42`, `-1`, `9999` | Range: min-max from percentiles |
| enum | `user`, `admin`, `editor` | Exact value set (<50 unique values) |
| uuid | `550e8400-e29b-...` | UUID format regex |
| email | `alice@example.com` | RFC 5322 pattern |
| ipv4 | `192.168.1.1` | Dotted quad validation |
| jwt | `eyJ...` | Three-segment base64url |
| iso_date | `2026-04-10T12:00:00Z` | ISO 8601 pattern |
| boolean | `true`, `false`, `0`, `1` | Exact match |
| string | anything else | Charset regex + length bounds |

Parameters with <50 distinct values are automatically classified as enums. Free-text fields (wide charset, long values) get a hybrid blacklist overlay for injection patterns.

## Status

This project is in **active development**. The architecture is designed and scaffolded. See [CONCEPT.md](CONCEPT.md) for the full design document.

**Current state:**
- nginx C module: scaffold complete, core validation engine implemented
- Learning engine: fully functional (type inference, profiling, YAML export)
- Rule compiler: profile-to-binary serialization implemented
- Docker setup: build and compose files ready

## License

Apache 2.0 — see [LICENSE](LICENSE).
