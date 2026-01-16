# Toy STS Implementation Plan

## Overview

A minimal Security Token Service (STS) for JWT issuance, using a **Functional Core, Imperative Shell (FCIS)** architecture:

- **Imperative Shell** (C): Handles all I/O (HTTP, async networking, database), cryptography (token validation, signing, encryption), and orchestration.
- **Functional Core** (JavaScript via QuickJS): Pure policy evaluation scripts that decide whether to issue tokens and what claims to include.

The key insight: policy scripts *describe* effects rather than *perform* them. The shell interprets these descriptions.

## Architecture

```
                    ┌─────────────────────────────────────────────────┐
                    │              Imperative Shell (C)               │
                    │                                                 │
  HTTP Request ────►│  ┌─────────┐    ┌──────────┐    ┌───────────┐  │
                    │  │  HTTP   │    │  Crypto  │    │   Async   │  │
                    │  │ Parser  │    │  Engine  │    │   I/O     │  │
                    │  └────┬────┘    └────┬─────┘    └─────┬─────┘  │
                    │       │              │                │        │
                    │       ▼              ▼                ▼        │
                    │  ┌─────────────────────────────────────────┐   │
                    │  │           Shell Orchestrator            │   │
                    │  │  - Validates input token signatures     │   │
                    │  │  - Calls policy engine                  │   │
                    │  │  - Interprets data requests             │   │
                    │  │  - Signs/encrypts output tokens         │   │
                    │  └──────────────────┬──────────────────────┘   │
                    │                     │                          │
                    └─────────────────────┼──────────────────────────┘
                                          │
                    ┌─────────────────────▼──────────────────────────┐
                    │            Functional Core (QuickJS)           │
                    │                                                │
                    │   function evaluate(request, context) {        │
                    │     // Pure policy logic                       │
                    │     return { error | needData | issue };       │
                    │   }                                            │
                    │                                                │
                    └────────────────────────────────────────────────┘
```

## Policy Script Interface

### Input

The shell calls the policy function with two arguments:

```javascript
evaluate(request, context)
```

**`request`** - Immutable, derived from HTTP request:
```javascript
{
  // Token exchange parameters (RFC 8693)
  grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
  subject_token: { /* validated claims from input JWT */ },
  subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
  actor_token: { /* optional, validated claims */ },
  audience: "https://api.example.com",
  scope: ["read", "write"],

  // Channel bindings (if present)
  channel_bindings: {
    type: "tls-server-end-point",
    hash: "base64url-encoded-hash"
  },

  // HTTP metadata
  http: {
    method: "POST",
    path: "/token",
    client_ip: "192.168.1.100",
    tls: {
      cipher: "TLS_AES_256_GCM_SHA384",
      client_cert: { /* if mTLS, validated cert info */ }
    }
  },

  // Authentication (shell validates, script sees claims)
  auth: {
    method: "basic" | "bearer" | "negotiate" | "mtls",
    principal: "user@EXAMPLE.COM",  // Validated by shell
    claims: { /* if bearer token */ }
  }
}
```

**`context`** - Mutable accumulator for fetched data:
```javascript
{
  // Populated by shell based on needData requests
  db: { /* query results */ },
  dns: { /* lookup results */ },
  ldap: { /* search results */ },
  http: { /* fetch results */ },

  // Iteration tracking (shell-managed)
  _iteration: 0,
  _max_iterations: 10
}
```

### Output

The policy function returns exactly one of three shapes:

#### 1. Error - Reject the request
```javascript
return {
  error: {
    code: "invalid_grant",           // OAuth error code
    description: "Token expired",    // Human-readable
    status: 400                      // HTTP status (optional, default 400)
  }
};
```

#### 2. Need Data - Suspend and fetch
```javascript
return {
  needData: [
    {
      type: "db",
      key: "user",                   // Key in context.db
      query: "SELECT * FROM users WHERE principal = $1",
      params: ["user@EXAMPLE.COM"]
    },
    {
      type: "dns",
      key: "srv",
      name: "_kerberos._tcp.example.com",
      rrtype: "SRV"
    },
    {
      type: "ldap",
      key: "groups",
      base: "ou=groups,dc=example,dc=com",
      filter: "(member=uid=user,ou=people,dc=example,dc=com)",
      attrs: ["cn"]
    },
    {
      type: "http",
      key: "metadata",
      url: "https://internal.example.com/user-metadata",
      method: "GET",
      headers: { "X-Request-Id": "..." }
    }
  ]
};
```

The shell fetches all requested data (in parallel where possible), adds results to `context`, and re-invokes the policy.

#### 3. Issue - Describe the token to create
```javascript
return {
  issue: {
    // Standard JWT claims (shell adds iat, jti)
    sub: "user@example.com",
    aud: request.audience,
    exp: Math.floor(Date.now() / 1000) + 3600,
    iss: "https://sts.example.com",  // Optional, shell has default

    // Custom claims
    groups: ["admin", "developers"],
    scope: "read write",

    // Channel bindings (echo back if present)
    cb: request.channel_bindings ?
        `${request.channel_bindings.type}:${request.channel_bindings.hash}` :
        undefined,

    // Delegation chain (RFC 8693 act claim)
    act: request.actor_token ? {
      sub: request.actor_token.sub,
      iss: request.actor_token.iss
    } : undefined
  },

  // Token options (optional)
  options: {
    lifetime: 3600,                  // Override exp calculation
    sign_alg: "RS256",               // Signing algorithm
    encrypt: false,                  // JWE wrap?
    encrypt_alg: "RSA-OAEP-256"      // If encrypting
  }
};
```

## Threading Model

Multi-threaded with NPROC worker threads. No shared mutable state between requests.

```
    ┌────────────────────────────────────────────────────────────────────┐
    │                         Shared (read-only after init)              │
    │  - Configuration                                                   │
    │  - Compiled JS bytecode                                            │
    │  - Signing keys                                                    │
    │  - SQLite connection (thread-safe with SQLITE_OPEN_FULLMUTEX)      │
    └────────────────────────────────────────────────────────────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────┐
         │                            │                            │
         ▼                            ▼                            ▼
   ┌───────────────┐           ┌───────────────┐           ┌───────────────┐
   │   Worker 0    │           │   Worker 1    │    ...    │  Worker N-1   │
   │               │           │               │           │               │
   │ ┌───────────┐ │           │ ┌───────────┐ │           │ ┌───────────┐ │
   │ │ JSContext │ │           │ │ JSContext │ │           │ │ JSContext │ │
   │ └───────────┘ │           │ └───────────┘ │           │ └───────────┘ │
   │               │           │               │           │               │
   │  Own listen   │           │  Own listen   │           │  Own listen   │
   │  socket (via  │           │  socket (via  │           │  socket (via  │
   │ SO_REUSEPORT) │           │ SO_REUSEPORT) │           │ SO_REUSEPORT) │
   └───────┬───────┘           └───────┬───────┘           └───────┬───────┘
           │                           │                           │
           └───────────────────────────┴───────────────────────────┘
                                       │
                              Kernel load-balances
                              incoming connections
```

### Design Rationale

1. **SO_REUSEPORT**: Each worker thread creates its own listen socket bound to the same port. The kernel distributes incoming connections across workers. No dispatcher thread needed.

2. **One JSRuntime + JSContext per worker**: QuickJS has no multi-threading within a JSRuntime. Each worker gets its own fully isolated JSRuntime and JSContext. No locks needed during request handling.

3. **Class IDs allocated at startup**: QuickJS has a global `js_class_id_alloc` counter. All `JS_NewClassID()` calls must happen during single-threaded initialization (before spawning workers) to avoid races.

4. **No JS globals between requests**: Each `evaluate()` call gets fresh `request` and `context` objects. No state persists across requests within a JSContext.

5. **SQLite is synchronous**: SQLite with `SQLITE_OPEN_FULLMUTEX` is thread-safe and fast enough for local queries. No async needed.

6. **LDAP has dedicated I/O threads**: LDAP operations are handled by a small pool of LDAP I/O threads that block on `ldap_result()` and signal completion back to the requesting worker via a pipe or eventfd.

7. **DNS can be synchronous or async**: For simple lookups, synchronous `getaddrinfo()` / `res_query()` is fine. For SRV/complex lookups, use `lib/roken` resolver or dedicated threads.

### LDAP I/O Thread Pool

```
   Worker Thread                    LDAP I/O Thread Pool
   ─────────────                    ────────────────────
        │                                   │
        │  needData: ldap query             │
        ├──────────────────────────────────►│
        │  (queue work item)                │
        │                                   │
        │                          ┌────────┴────────┐
        │                          │ ldap_search()   │
        │                          │ ldap_result()   │  ◄── blocks here
        │                          │ (blocking)      │
        │                          └────────┬────────┘
        │                                   │
        │  signal completion (eventfd)      │
        │◄──────────────────────────────────┤
        │                                   │
        │  (worker resumes, re-evals policy)│
```

The worker thread submits LDAP requests to a queue, then either:
- Blocks waiting for all needData results (simple), or
- Returns to accept() and picks up the request later when signaled (complex but more efficient)

For a toy STS, blocking is fine since we have N workers.

## Shell Components

### 1. HTTP Server

Each worker thread runs its own accept/handle loop:

```c
void *worker_thread(void *arg) {
    worker_ctx *ctx = arg;

    // Create listen socket with SO_REUSEPORT
    int listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int));
    bind(listen_fd, ...);
    listen(listen_fd, SOMAXCONN);

    // Initialize per-worker JSContext from shared bytecode
    ctx->jsctx = JS_NewContext(shared_runtime);
    load_policy_bytecode(ctx->jsctx, shared_bytecode);

    while (!shutdown_requested) {
        int conn_fd = accept(listen_fd, ...);
        if (conn_fd < 0) continue;

        // TLS handshake, HTTP parse, policy eval, response
        handle_request(ctx, conn_fd);
        close(conn_fd);
    }

    JS_FreeContext(ctx->jsctx);
    return NULL;
}
```

HTTP features:
- Parse `application/x-www-form-urlencoded` and `application/json` bodies
- Route `/token` endpoint (RFC 8693)
- Route `/.well-known/openid-configuration` (discovery)
- Route `/jwks` (public keys)

### 2. Input Token Validator

Before calling the policy, the shell validates input tokens:

```c
typedef struct sts_validated_token {
    heim_dict_t claims;        // Parsed claims as heim objects
    const char *issuer;        // Validated issuer
    const char *subject;       // Subject claim
    time_t expiry;             // Expiration time
    int signature_valid;       // Signature verified
} sts_validated_token;

// Validate JWT signature and extract claims
// Does NOT check policy (that's the script's job)
int sts_validate_jwt(sts_context ctx,
                     const char *token,
                     sts_validated_token *out);
```

Signature validation uses hx509/JOSE infrastructure. The shell loads trusted JWKS from configuration.

### 3. QuickJS Integration

```c
#include "quickjs.h"

/*
 * Global state - initialized once during single-threaded startup.
 * Class IDs must be allocated before spawning worker threads to
 * avoid races on QuickJS's global js_class_id_alloc counter.
 */
static JSClassID js_request_class_id;
static JSClassID js_context_class_id;
static uint8_t *compiled_bytecode;      // Compiled policy script
static size_t compiled_bytecode_len;

// Called once from main() before spawning workers
int sts_policy_init_global(const char *script_path) {
    JS_NewClassID(&js_request_class_id);
    JS_NewClassID(&js_context_class_id);

    // Compile script to bytecode (can be loaded into any runtime)
    JSRuntime *rt = JS_NewRuntime();
    JSContext *ctx = JS_NewContext(rt);
    // ... compile script, JS_WriteObject() to get bytecode ...
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
    return 0;
}

/*
 * Per-worker policy engine - each worker thread has its own.
 */
typedef struct sts_policy_engine {
    JSRuntime *rt;             // Own runtime (thread-isolated)
    JSContext *ctx;            // Own context
    JSValue evaluate_func;     // Cached reference to evaluate()
} sts_policy_engine;

// Called by each worker thread during its initialization
int sts_policy_init_worker(sts_policy_engine *engine) {
    engine->rt = JS_NewRuntime();
    engine->ctx = JS_NewContext(engine->rt);

    // Register classes using pre-allocated IDs
    JS_NewClass(engine->rt, js_request_class_id, &js_request_class);
    JS_NewClass(engine->rt, js_context_class_id, &js_context_class);

    // Load compiled bytecode into this context
    JSValue obj = JS_ReadObject(engine->ctx, compiled_bytecode,
                                compiled_bytecode_len, JS_READ_OBJ_BYTECODE);
    JS_EvalFunction(engine->ctx, obj);

    // Cache reference to evaluate()
    JSValue global = JS_GetGlobalObject(engine->ctx);
    engine->evaluate_func = JS_GetPropertyStr(engine->ctx, global, "evaluate");
    JS_FreeValue(engine->ctx, global);

    return 0;
}

// Convert C request to JS object, call evaluate(), convert result
int sts_policy_evaluate(sts_policy_engine *engine,
                        const sts_request *request,
                        heim_dict_t context,
                        sts_policy_result *result);

// Called by worker thread during shutdown
void sts_policy_free_worker(sts_policy_engine *engine) {
    JS_FreeValue(engine->ctx, engine->evaluate_func);
    JS_FreeContext(engine->ctx);
    JS_FreeRuntime(engine->rt);
}
```

### 4. Data Fetchers

Data fetchers handle the `needData` requests from policy scripts. Different data sources have different threading models:

#### SQLite (synchronous, thread-safe)

```c
// Direct synchronous query - SQLite handles locking internally
int sts_fetch_db(sts_context ctx,
                 const char *key,
                 const char *query,
                 heim_array_t params,
                 heim_object_t *result_out);
```

SQLite is opened with `SQLITE_OPEN_FULLMUTEX` for full thread safety. Queries block the worker thread briefly but this is acceptable for local database access.

#### LDAP (async via I/O thread pool)

```c
// Submit to LDAP I/O thread pool, block until complete
int sts_fetch_ldap(sts_context ctx,
                   const char *key,
                   const char *base,
                   const char *filter,
                   heim_array_t attrs,
                   heim_object_t *result_out);
```

Internally:
1. Worker submits request to LDAP work queue
2. LDAP I/O thread picks it up, calls `ldap_search_ext()` / `ldap_result()`
3. On completion, signals worker via eventfd or pipe
4. Worker unblocks and receives results

Future optimization: Use Heimdal's ASN.1 compiler to generate an async LDAP client that doesn't require dedicated threads.

#### DNS (synchronous for now)

```c
// Synchronous DNS lookup - blocks worker thread
int sts_fetch_dns(sts_context ctx,
                  const char *key,
                  const char *name,
                  const char *rrtype,
                  heim_object_t *result_out);
```

Uses `res_query()` or `getaddrinfo()`. For SRV records, uses `lib/roken` resolver. Blocking is acceptable since DNS is typically fast with local caching resolver.

#### HTTP (optional, for federation)

```c
// Synchronous HTTP fetch - use sparingly!
int sts_fetch_http(sts_context ctx,
                   const char *key,
                   const char *url,
                   const char *method,
                   heim_dict_t headers,
                   heim_object_t *result_out);
```

**Warning**: Allowing policy scripts to trigger arbitrary HTTP requests is dangerous (SSRF, resource exhaustion). If implemented:
- Whitelist allowed destination hosts in config
- Strict timeouts
- Consider whether this belongs in the shell at all vs. out-of-band federation

### 5. Token Issuer

```c
typedef struct sts_token_options {
    const char *sign_alg;      // "RS256", "ES256", etc.
    hx509_private_key sign_key;
    int encrypt;
    const char *encrypt_alg;
    hx509_cert encrypt_cert;   // Recipient's cert for JWE
} sts_token_options;

// Sign (and optionally encrypt) a JWT
int sts_issue_token(sts_context ctx,
                    heim_dict_t claims,
                    const sts_token_options *options,
                    char **token_out);
```

## Request Processing Flow

```
1. HTTP request arrives
   │
2. Shell parses request, extracts grant_type, tokens, audience
   │
3. Shell validates input token signatures (crypto in C)
   │  - Signature invalid? → Return 401
   │  - Token expired? → Pass expiry info to script, let it decide
   │
4. Shell builds request object with validated claims
   │
5. Shell calls policy: result = evaluate(request, {})
   │
   ├─► result.error? → Return HTTP error response
   │
   ├─► result.needData?
   │   │
   │   ├─ Check iteration count (prevent infinite loops)
   │   │
   │   ├─ Dispatch async fetches for all requested data
   │   │
   │   ├─ When all complete, add to context
   │   │
   │   └─ Goto step 5 with updated context
   │
   └─► result.issue?
       │
       ├─ Shell adds iat, jti, default iss if not specified
       │
       ├─ Shell signs token (crypto in C)
       │
       ├─ Shell optionally encrypts (JWE)
       │
       └─ Return HTTP 200 with token response
```

## Configuration

```
[sts]
    # HTTP listener
    listen = 0.0.0.0:8443
    tls_certificate = FILE:/etc/sts/server.pem
    tls_private_key = FILE:/etc/sts/server-key.pem

    # Policy script
    policy_script = /etc/sts/policy.js
    policy_reload = true           # Hot-reload on change
    max_policy_iterations = 10     # Prevent infinite loops

    # Token signing
    issuer = https://sts.example.com
    signing_key = FILE:/etc/sts/signing-key.pem
    signing_algorithm = RS256
    default_token_lifetime = 3600

    # Trusted token issuers (for validating input tokens)
    trusted_issuer = https://login.example.com
    trusted_jwks = https://login.example.com/.well-known/jwks.json

    # Data sources
    database = postgres://sts@localhost/sts
    ldap_uri = ldaps://ldap.example.com
```

## Example Policy Script

```javascript
// /etc/sts/policy.js

function evaluate(request, context) {
  // Reject if not a token exchange
  if (request.grant_type !== "urn:ietf:params:oauth:grant-type:token-exchange") {
    return {
      error: {
        code: "unsupported_grant_type",
        description: "Only token exchange is supported"
      }
    };
  }

  // Require a subject token
  if (!request.subject_token) {
    return {
      error: {
        code: "invalid_request",
        description: "subject_token required"
      }
    };
  }

  // Check token expiry (shell validated signature, we check claims)
  const now = Math.floor(Date.now() / 1000);
  if (request.subject_token.exp && request.subject_token.exp < now) {
    return {
      error: {
        code: "invalid_grant",
        description: "subject_token expired"
      }
    };
  }

  // Fetch user info from database if not already present
  if (!context.db?.user) {
    return {
      needData: [{
        type: "db",
        key: "user",
        query: "SELECT principal, allowed_audiences, groups FROM users WHERE principal = $1",
        params: [request.subject_token.sub]
      }]
    };
  }

  // Check if user exists
  const user = context.db.user[0];
  if (!user) {
    return {
      error: {
        code: "invalid_grant",
        description: "Unknown subject",
        status: 403
      }
    };
  }

  // Check if user is allowed to get tokens for this audience
  const allowedAudiences = user.allowed_audiences || [];
  if (!allowedAudiences.includes(request.audience) &&
      !allowedAudiences.includes("*")) {
    return {
      error: {
        code: "invalid_target",
        description: `Not authorized for audience: ${request.audience}`,
        status: 403
      }
    };
  }

  // Build token claims
  const claims = {
    sub: user.principal,
    aud: request.audience,
    groups: user.groups || [],

    // Preserve channel bindings
    cb: request.channel_bindings ?
        `${request.channel_bindings.type}:${request.channel_bindings.hash}` :
        undefined,

    // Include actor claim if delegating
    act: request.actor_token ? {
      sub: request.actor_token.sub,
      iss: request.actor_token.iss
    } : undefined
  };

  // Issue the token
  return {
    issue: claims,
    options: {
      lifetime: 3600
    }
  };
}
```

## File Structure

```
lib/uquickjs/
├── quickjs.c                # Amalgamated QuickJS source
├── quickjs.h                # QuickJS public API
├── Makefile.am
└── README                   # License, version info

kdc/
├── sts.c                    # Main STS daemon entry point, worker threads
├── sts.h                    # Public interface
├── sts-http.c               # HTTP/1.1 parser, request routing
├── sts-http.h
├── sts-policy.c             # QuickJS integration, evaluate() wrapper
├── sts-policy.h
├── sts-token.c              # JWT validation (input) and signing (output)
├── sts-token.h
├── sts-fetch-db.c           # SQLite data fetcher
├── sts-fetch-ldap.c         # LDAP data fetcher (with I/O thread pool)
├── sts-fetch-dns.c          # DNS data fetcher
├── sts-fetch.h              # Common fetcher interface
├── sts-config.c             # Configuration parsing
├── sts-config.h
├── stsd.8                   # Man page
└── test-policy.js           # Example/test policy script

tests/sts/
├── check-sts.in             # Test script
├── test-policy-basic.js     # Basic policy for testing
└── test-tokens/             # Pre-signed test JWTs
```

## Build Integration

### QuickJS (Micro QuickJS)

Import Fabrice Bellard's QuickJS as an amalgamation in `lib/uquickjs/`:

```
lib/uquickjs/
├── quickjs.c              # Amalgamated source (~200KB)
├── quickjs.h              # Public API
├── quickjs-libc.h         # Optional: std library bindings (NOT used in STS)
├── Makefile.am
└── README                 # License, version, upstream URL
```

Build configuration:
- **No CONFIG_BIGNUM**: Crypto stays in C/OpenSSL, not JS. Avoids side-channel concerns.
- **No quickjs-libc**: Policy scripts don't get `std`, `os`, `console`. Pure sandboxed evaluation.
- Compile as a static convenience library linked into STS.

```makefile
# lib/uquickjs/Makefile.am
noinst_LTLIBRARIES = libuquickjs.la
libuquickjs_la_SOURCES = quickjs.c
libuquickjs_la_CFLAGS = -DCONFIG_VERSION=\"2024-01-13\"
```

### SQLite

Already bundled in `lib/sqlite/`. Reuse existing build integration.

### LDAP

Link against system OpenLDAP (`-lldap -llber`) or use Heimdal's internal LDAP if available.

## Security Considerations

1. **QuickJS sandboxing** - No filesystem, network, or OS access by default. Only expose the `evaluate` function; don't expose `console`, `print`, etc. in production.

2. **Script validation** - On load, verify the script exports an `evaluate` function.

3. **Resource limits**:
   - Max script execution time (QuickJS supports interrupts)
   - Max memory per evaluation
   - Max iterations for needData loops

4. **Input sanitization** - The shell controls what goes into the `request` object. Never pass raw HTTP headers without validation.

5. **Crypto in C only** - Scripts cannot access signing keys or perform crypto operations directly.

## Future Extensions

1. **Token caching** - Cache issued tokens keyed by (subject, audience, scope) hash
2. **Rate limiting** - Per-client, per-subject limits in the shell
3. **Audit logging** - Log all token issuance with request/response details
4. **Multiple policies** - Route different audiences to different scripts
5. **Async LDAP** - Use Heimdal's ASN.1 compiler to generate a proper async LDAP client
6. **Windows support** - Replace SO_REUSEPORT with completion ports / thread pool

## JGT (JWT-Granting JWT) Pattern

A "JWT-Granting JWT" (JGT) is a token whose audience is the STS itself, used to obtain tokens for other services. This is analogous to Kerberos's TGT but using JWT.

**Not a protocol change** - just documentation and policy convention:

```javascript
// Policy script recognizing JGT pattern
function evaluate(request, context) {
  const STS_AUDIENCE = "https://sts.example.com";

  // If requesting a token for the STS itself, issue a JGT
  if (request.audience === STS_AUDIENCE) {
    return {
      issue: {
        sub: request.subject_token.sub,
        aud: STS_AUDIENCE,
        // JGT-specific claim: what audiences can be requested with this JGT
        "sts:allowed_audiences": ["*"]  // Or specific list
      },
      options: { lifetime: 86400 }  // JGTs can be longer-lived
    };
  }

  // For other audiences, require a JGT as subject_token
  if (request.subject_token.aud !== STS_AUDIENCE) {
    return { error: { code: "invalid_grant", description: "JGT required" } };
  }

  // ... normal token issuance logic
}
```

## Resolved Design Decisions

1. **Threading model**: NPROC worker threads, each with own JSRuntime + JSContext, SO_REUSEPORT for accept distribution
2. **QuickJS class IDs**: Allocated once during single-threaded init (before spawning workers) to avoid races on global counter
3. **JS state**: No globals persist between requests (fresh objects per `evaluate()` call)
4. **Crypto in JS**: No. QuickJS compiled without CONFIG_BIGNUM. All crypto in C/OpenSSL.
5. **LDAP I/O**: Dedicated thread pool blocking on `ldap_result()`, signaling workers on completion
6. **SQLite I/O**: Synchronous with SQLITE_OPEN_FULLMUTEX (thread-safe, fast for local)
7. **Policy errors**: JS exceptions map to HTTP 500 with logged stack trace; distinct from policy rejections (4xx)
