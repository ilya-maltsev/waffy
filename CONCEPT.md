# waffy — WAF for you

> **W**hitelisted **A**pp **F**ire**w**all — adaptive, per-endpoint, learned from your real traffic

## Problem Statement

Existing open-source WAFs (ModSecurity, NAXSI, Coraza) rely on **generic blacklist rules** — signatures of known attack patterns (SQLi, XSS, path traversal, etc.). This approach has fundamental weaknesses:

1. **Bypass-friendly** — A skilled attacker only needs to find ONE encoding/mutation that the signature misses.
2. **High false-positive rate** — Generic rules don't understand the protected application, so legitimate requests get blocked.
3. **Rule exclusion hell** — Operators spend weeks writing exclusion rules per endpoint to suppress false positives, effectively poking holes in coverage.
4. **No application awareness** — The WAF doesn't know that `/api/users?id=` should only accept an integer, or that `/search?q=` has a max length of 200 characters.

## Core Idea

**Flip the model: whitelist instead of blacklist.**

waffy operates in two phases:

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1 — LEARNING (offline, out-of-band)                      │
│                                                                  │
│  Analyze real traffic flowing through nginx to build a strict    │
│  profile of every parameter, header, and body for each           │
│  location + method combination.                                  │
│                                                                  │
│  Output: compiled per-location rule sets                         │
└─────────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 2 — ENFORCEMENT (inline, in nginx request path)          │
│                                                                  │
│  For every incoming request, validate against the learned        │
│  whitelist. If any parameter violates its profile → BLOCK.       │
│                                                                  │
│  Unknown parameters not seen during learning → BLOCK.            │
│  Budget: < 100ms added latency per request.                      │
└─────────────────────────────────────────────────────────────────┘
```

This is fundamentally harder to bypass: the attacker must craft a payload that **simultaneously**:
- Matches the exact parameter names the application expects
- Conforms to the type/length/pattern constraints learned from real traffic
- AND still exploits a vulnerability

## Architecture Overview

```
                    ┌──────────────────────┐
                    │   nginx + waffy      │
                    │   C module           │
     request ──────►  (enforcement)       ├──────► upstream app
                    │                      │
                    │  shared memory:       │
                    │  per-location rules   │
                    └──────────┬───────────┘
                               │ reads compiled rules
                               │
                    ┌──────────┴───────────┐
                    │   Rule Store         │
                    │   (mmap files)       │
                    └──────────┬───────────┘
                               │ written by
                               │
          ┌────────────────────┴────────────────────┐
          │                                         │
┌─────────┴──────────┐                  ┌───────────┴─────────┐
│  waffy-learn       │                  │  waffy-compile      │
│  (traffic analyzer)│ ──── profiles ──►│  (rule compiler)    │
│  Python/Go daemon  │                  │  Go binary          │
└─────────┬──────────┘                  └─────────────────────┘
          │ reads
          │
┌─────────┴──────────┐
│  Traffic capture    │
│  (nginx access log  │
│   or mirror tap)    │
└────────────────────┘
```

### Components

#### 1. `ngx_http_waffy_module` — nginx C module (enforcement, inline)

The hot path. This is a **content-phase handler** that runs for every request matching a configured location. It:

- Looks up the rule set for the current `location + method` from shared memory
- Parses and validates: URI args, POST body (form-urlencoded, multipart, JSON), headers, cookies
- Each parameter is checked against its whitelist profile (type, regex, length, allowed values)
- Unknown/unexpected parameters are rejected
- Decision: PASS, BLOCK, or LOG (detection-only mode)
- Writes decision + metadata to a ring buffer for async logging

**Performance contract:** The module does NO dynamic memory allocation after initialization, NO disk I/O, NO network calls. Rules are pre-compiled DFA regexes in shared memory. Target: **< 5ms** per request for typical API endpoints (well under the 100ms budget).

#### 2. `waffy-learn` — Traffic Learning Engine (offline)

A daemon (Python or Go) that analyzes captured traffic to build parameter profiles. Input sources:

- nginx access logs (with request body logging enabled)
- Traffic mirror/tap (nginx `mirror` directive)
- HAR files / pcap imports for initial bootstrapping

For each `location + method` it builds a **Parameter Profile**:

```
Location: POST /api/v1/users
Parameters:
  name:
    source: body
    type: string
    min_length: 1
    max_length: 64
    pattern: ^[a-zA-Z\s\-']+$
    required: true
    
  age:
    source: body
    type: integer
    min: 0
    max: 150
    required: false
    
  email:
    source: body  
    type: email
    max_length: 254
    required: true

  X-Request-ID:
    source: header
    type: uuid
    required: false
```

The learner uses **statistical analysis** over a training window:
- Type inference: integer, float, uuid, email, base64, hex, ISO date, JWT, enum, free-text
- Pattern generalization: groups observed values into the tightest regex that covers 99.5% of traffic
- Length distribution: min/max with percentile-based outlier removal
- Value enumeration: if a parameter has < 50 distinct values, store as enum
- Cardinality tracking: detect parameters that should be constrained vs. free-form

#### 3. `waffy-compile` — Rule Compiler

Transforms learned profiles into an optimized binary rule format:

- Converts regex patterns to DFA (using RE2 or Hyperscan for SIMD acceleration)
- Packs rules into a memory-mapped file format for zero-copy loading by nginx
- Generates per-location rule lookup table (hash map: `location_hash + method → rule_set_offset`)
- Produces human-readable rule files for review/audit before deployment

#### 4. `waffy-ctl` — Management CLI

```bash
waffy-ctl learn start --config /etc/waffy/learn.yaml   # start learning
waffy-ctl learn status                                   # show learning progress
waffy-ctl compile --profile /var/waffy/profiles/ --out /var/waffy/rules.bin
waffy-ctl rules show /api/v1/users POST                  # inspect rules
waffy-ctl rules diff                                     # compare current vs. new
waffy-ctl reload                                         # hot-reload rules in nginx
waffy-ctl audit --log /var/log/waffy/blocks.log          # review blocks
```

## Per-Location Rule Architecture

This is the key differentiator. Unlike ModSecurity which applies the same ruleset globally (then carves out exclusions), waffy generates **independent rule sets per nginx location**.

### nginx configuration

```nginx
http {
    # Global: path to compiled rule store
    waffy_rules /var/waffy/rules.bin;
    
    # Global: default action
    waffy_default_action block;  # block | detect | off

    server {
        listen 443 ssl;
        server_name app.example.com;
        
        # API endpoint — strict whitelist, JSON body
        location /api/v1/users {
            waffy on;
            waffy_mode enforce;           # enforce | detect | learn
            waffy_body_parser json;        # json | form | multipart | auto
            waffy_max_body_size 16k;
            waffy_on_violation return 403;
            
            proxy_pass http://backend;
        }
        
        # Search — moderate constraints
        location /search {
            waffy on;
            waffy_mode enforce;
            waffy_body_parser form;
            waffy_on_violation return 403;
            
            proxy_pass http://backend;
        }
        
        # Static assets — no WAF needed
        location /static/ {
            waffy off;
            root /var/www;
        }
        
        # File upload — different profile
        location /api/v1/upload {
            waffy on;
            waffy_mode enforce;
            waffy_body_parser multipart;
            waffy_max_body_size 50m;
            waffy_on_violation return 403;
            
            proxy_pass http://backend;
        }
    }
}
```

### Why per-location matters for performance

**Generic WAF approach (ModSecurity):**
```
Request → Run ALL 3000+ rules → Check exclusions → Decision
          ~50-200ms for complex rule sets
```

**waffy approach:**
```
Request → Hash(location + method) → Load 5-20 specific rules → Validate → Decision
          ~1-5ms for typical endpoints
```

By scoping rules to each location, we:
1. **Reduce rule count per request by 100-1000x** — only check what's relevant
2. **Eliminate exclusion logic entirely** — rules are already specific
3. **Enable aggressive optimization** — compiler can merge and simplify per-location rules
4. **Make auditing tractable** — review rules for one endpoint at a time

## Rule Format (DSL)

Human-readable rule files generated by the compiler for review:

```yaml
# Auto-generated by waffy-compile. Source: traffic analysis 2026-04-01 to 2026-04-08
# Location: POST /api/v1/users
# Training samples: 48,293 requests
# Coverage: 99.7% of observed traffic

location: "/api/v1/users"
method: POST
content_type: "application/json"

parameters:
  - name: "name"
    source: body
    required: true
    type: string
    constraints:
      min_length: 1
      max_length: 64
      regex: "^[\\p{L}\\s\\-'.,]+$"
      
  - name: "email"
    source: body
    required: true
    type: string
    constraints:
      max_length: 254
      regex: "^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$"
      
  - name: "age"
    source: body
    required: false
    type: integer
    constraints:
      min: 0
      max: 150
      
  - name: "role"
    source: body
    required: false
    type: enum
    constraints:
      values: ["user", "editor", "admin"]

  - name: "Authorization"
    source: header
    required: true
    type: string
    constraints:
      regex: "^Bearer [A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_]+$"

  - name: "Content-Type"
    source: header
    required: true
    type: enum
    constraints:
      values: ["application/json", "application/json; charset=utf-8"]

# Reject any parameter not listed above
strict_mode: true

# Action on violation
on_violation:
  action: block
  status: 403
  log: true
  include_violation_detail: true
```

## Request Processing Pipeline (Hot Path)

```
 ┌─ nginx receives request ────────────────────────────────────────┐
 │                                                                  │
 │  1. LOCATION LOOKUP                                      ~0.1ms │
 │     hash(location_path + method) → rule_set pointer              │
 │     if no rules → PASS (uncovered endpoint)                      │
 │                                                                  │
 │  2. CONTENT-TYPE CHECK                                   ~0.01ms │
 │     if content_type not in allowed set → BLOCK                   │
 │                                                                  │
 │  3. PARSE REQUEST                                        ~0.5ms  │
 │     URI args → key-value pairs                                   │
 │     Body (based on content_type):                                │
 │       form-urlencoded → key-value pairs                          │
 │       JSON → flattened dotpath key-value pairs                   │
 │       multipart → field names + metadata                         │
 │     Headers → filtered key-value pairs                           │
 │     Cookies → key-value pairs                                    │
 │                                                                  │
 │  4. STRICT MODE CHECK                                    ~0.1ms  │
 │     if strict_mode:                                              │
 │       for each parsed param not in rule_set → BLOCK              │
 │       "unknown parameter 'callback' in query"                    │
 │                                                                  │
 │  5. PARAMETER VALIDATION                                 ~1-3ms  │
 │     for each rule in rule_set:                                   │
 │       a. presence check (required/optional)                      │
 │       b. type check (integer? → fast atoi path)                  │
 │       c. length check (min_len <= len <= max_len)                │
 │       d. constraint check:                                       │
 │          - enum: hash lookup in value set                        │
 │          - regex: DFA match (pre-compiled, no backtracking)      │
 │          - range: numeric comparison                             │
 │       on first violation → BLOCK (fail-fast)                     │
 │                                                                  │
 │  6. DECISION                                              ~0.01ms│
 │     PASS → continue to proxy_pass                                │
 │     BLOCK → return 403 + log violation detail                    │
 │     DETECT → log violation but continue to proxy_pass            │
 │                                                                  │
 │  Total budget: 1-5ms typical, <100ms worst case                  │
 └──────────────────────────────────────────────────────────────────┘
```

## Learning Engine — Deep Dive

### Traffic Capture Strategy

```
Option A: Enhanced access log (simplest)
──────────────────────────────────────
nginx log_format with $request_body, $args, $http_* variables
+ Custom log_format that captures everything needed
- Limited: $request_body only available after proxy reads it
- No streaming for large bodies

Option B: Mirror tap (recommended for production)
─────────────────────────────────────────────────
nginx `mirror` directive sends request copy to waffy-learn
+ Non-blocking, full request fidelity
+ Can handle streaming bodies
- Doubles upstream connections during learning

Option C: Lua/njs tap (flexible)
────────────────────────────────
OpenResty or njs script captures and forwards to waffy-learn
+ Full control over what's captured
+ Can filter/sample
- Adds slight latency during learning phase
```

### Type Inference Algorithm

```
For each parameter value observed during learning:

1. Try exact type matchers (fast path):
   integer    → /^-?\d+$/
   float      → /^-?\d+\.\d+$/
   boolean    → /^(true|false|0|1)$/
   uuid       → /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
   email      → RFC 5322 simplified
   ipv4       → /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/
   iso_date   → /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2})?/
   jwt        → /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/
   base64     → /^[A-Za-z0-9+/]+=*$/
   hex        → /^[0-9a-fA-F]+$/

2. If >95% of values match a type → assign that type

3. If no exact match, classify as string and compute:
   - character class distribution
   - length histogram  
   - common prefix/suffix
   - generate tightest regex covering 99.5% of samples

4. If distinct_count < 50 → classify as enum, store value set

5. Compute numeric ranges (for integer/float types):
   - p1, p99.5 percentiles → min, max
   
6. Compute length bounds:
   - p0.5, p99.5 percentiles → min_length, max_length
```

### Pattern Generalization

The learner must generalize observed values into patterns without being too loose:

```
Observed values for parameter "product_id":
  PRD-001, PRD-002, PRD-100, PRD-999, PRD-1234

Step 1: Align by structure
  PRD-\d{3,4}

Step 2: Verify coverage
  100% of training data matches → accept

Step 3: Tighten if possible
  All start with PRD- → anchored
  Digits range 001-1234 → \d{1,4} is sufficient
  
Result: ^PRD-\d{1,4}$
```

For free-text fields (search queries, comments), the learner generates **character class + length** constraints rather than value patterns:

```
parameter "q" (search query):
  type: string
  charset: [\p{L}\p{N}\s\-_.,"'!?@#]   # characters observed in training
  min_length: 1
  max_length: 500
  
  # Additionally, apply generic attack pattern detection:
  deny_patterns:
    - <script          # XSS
    - union\s+select   # SQLi
    - \.\./            # path traversal
```

This hybrid approach is key: **tight whitelists where possible, surgical blacklists only for inherently free-form fields**.

## Deployment Modes

### Mode 1: Learning (passive)
```
waffy_mode learn;
```
All traffic passes through. Module captures request metadata to learning engine. No blocking.

### Mode 2: Detection (shadow)
```
waffy_mode detect;
```
Rules are evaluated but violations only logged, never blocked. Use this to validate rules before enforcement.

### Mode 3: Enforcement (active)
```
waffy_mode enforce;
```
Full blocking mode. Violations return configured error status.

### Recommended rollout:

```
Week 1-2:  learn    → collect traffic, build profiles
Week 3:    compile  → generate rules, human review
Week 3-4:  detect   → shadow mode, monitor false positives  
Week 5:    enforce  → activate blocking
Ongoing:   continuous learning in parallel, periodic rule refresh
```

## Continuous Learning and Rule Drift

Applications change. New parameters get added, value ranges shift. waffy handles this with **continuous background learning**:

```
┌──────────────────────────────────────────────────────────────┐
│  CONTINUOUS LEARNING LOOP                                     │
│                                                               │
│  1. Background learner always runs, building "candidate"      │
│     profiles alongside the active rule set                    │
│                                                               │
│  2. Weekly diff: compare candidate profiles vs. active rules  │
│     - New parameters discovered?                              │
│     - Value ranges expanded?                                  │
│     - New endpoints appeared?                                 │
│                                                               │
│  3. If drift detected:                                        │
│     a. Generate diff report for operator review               │
│     b. Optionally auto-approve "safe" expansions              │
│        (new optional param, range widened by <10%)             │
│     c. Flag "risky" changes for manual review                 │
│        (new required param, constraint loosened significantly) │
│                                                               │
│  4. Operator approves → recompile → hot-reload                │
└──────────────────────────────────────────────────────────────┘
```

## Comparison with Existing WAFs

| Feature | ModSecurity | NAXSI | waffy |
|---------|-------------|-------|-------|
| Approach | Blacklist (CRS rules) | Score-based blacklist | Learned whitelist |
| Rules | ~3000 generic | ~50 generic | 5-20 per endpoint |
| Per-endpoint tuning | Manual exclusions | Manual whitelists | Auto-generated |
| False positives | High (needs tuning) | Medium | Low (learned from real traffic) |
| Bypass resistance | Medium (known patterns) | Medium | High (must match app behavior) |
| Setup time | Hours (rules exist) | Hours | Days (learning period) |
| Latency impact | 10-200ms | 1-10ms | 1-5ms |
| Maintenance | Update CRS rules | Manual | Continuous learning |
| Body parsing | Full | Limited | Full (JSON, form, multipart) |

## Security Considerations

### What waffy defends against well:
- SQLi, XSS, command injection in typed/constrained parameters
- Parameter tampering (adding unexpected params, changing types)
- Mass assignment attacks (unknown params rejected in strict mode)
- API abuse (enforces expected schema)
- Scanner/fuzzer noise (random params rejected immediately)

### What requires the hybrid blacklist overlay:
- Attacks within free-text fields (search, comments)
- Stored XSS in legitimate string parameters
- Business logic flaws (valid params, malicious intent)
- Zero-day in upstream application code

For free-text fields, waffy applies a **minimal targeted blacklist** (SQLi/XSS patterns) as an additional layer on top of the whitelist constraints. This is far smaller and more focused than a full CRS ruleset.

### Learning phase security:
- If an attacker poisons the training data during learning, they could widen the whitelist
- Mitigation: operator review of generated rules before enforcement
- Mitigation: anomaly detection to flag suspicious training samples
- Mitigation: baseline from API documentation / OpenAPI spec, not just traffic

## Technology Stack

| Component | Language | Why |
|-----------|----------|-----|
| nginx module | C | Required by nginx module API. Zero-overhead inline processing. |
| Rule compiler | Go | Strong regex/DFA libraries, good for CLI tools. |
| Learning engine | Python | NumPy/pandas for statistical analysis, rapid prototyping. |
| Rule store | mmap'd flatbuffers | Zero-copy, zero-parse loading from nginx. |
| Management CLI | Go | Single binary distribution. |
| Dashboard (optional) | Go + htmx | Lightweight, no JS build step. |

## File Structure

```
waffy/
├── CONCEPT.md                  # This document
├── LICENSE                     # Apache 2.0
├── README.md
├── nginx-module/               # nginx C module
│   ├── config                  # nginx build system integration
│   ├── ngx_http_waffy_module.c  # Main module: handler, config directives
│   ├── waffy_rule_engine.c      # Rule matching engine
│   ├── waffy_rule_engine.h
│   ├── waffy_parser.c           # Request body parsers (JSON, form, multipart)
│   ├── waffy_parser.h
│   ├── waffy_shm.c              # Shared memory rule store interface
│   ├── waffy_shm.h
│   └── tests/
│       ├── test_rule_engine.c
│       └── test_parser.c
├── learn/                      # Traffic learning engine (Python)
│   ├── waffy_learn/
│   │   ├── __init__.py
│   │   ├── capture.py          # Traffic capture adapters
│   │   ├── analyzer.py         # Parameter type inference
│   │   ├── profiler.py         # Per-location profile builder
│   │   ├── patterns.py         # Pattern generalization
│   │   └── config.py
│   ├── tests/
│   └── pyproject.toml
├── compiler/                   # Rule compiler (Go)
│   ├── cmd/
│   │   ├── waffy-compile/
│   │   └── waffy-ctl/
│   ├── internal/
│   │   ├── profile/            # Profile format parser
│   │   ├── compiler/           # Profile → binary rule compiler
│   │   ├── dfa/                # Regex → DFA compilation
│   │   └── store/              # Binary rule store format
│   ├── go.mod
│   └── go.sum
├── rules/                      # Example rule files
│   └── examples/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DEPLOYMENT.md
│   └── RULE_FORMAT.md
├── docker/
│   ├── Dockerfile.nginx        # nginx + waffy module
│   ├── Dockerfile.learn        # Learning engine
│   └── docker-compose.yml      # Full stack for testing
└── test/
    ├── integration/            # End-to-end tests
    ├── fixtures/               # Sample traffic data
    └── benchmark/              # Latency benchmarks
```

## MVP Scope

Phase 1 (MVP):
1. nginx module — query string + form body validation, per-location rules
2. Learning engine — type inference for query/form params from access logs
3. Rule compiler — YAML profiles → shared memory binary format
4. CLI — learn, compile, reload, show commands

Phase 2:
5. JSON body deep parsing and validation
6. Multipart/file upload handling
7. Cookie and header validation
8. Continuous learning daemon
9. Detection mode with detailed violation logging

Phase 3:
10. OpenAPI/Swagger spec import (bootstrap rules without learning)
11. Dashboard for rule review and violation monitoring
12. Hybrid blacklist overlay for free-text fields
13. Distributed rule sync (multi-node deployments)
14. Rate limiting integration (L4 awareness)
