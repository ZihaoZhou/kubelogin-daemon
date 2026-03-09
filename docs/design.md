# kubelogin-daemon: Design Philosophy & Architecture

## 1. Problem Statement

### What breaks

Kubernetes uses an [exec credential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins) model for OIDC authentication. The dominant implementation, [int128/kubelogin](https://github.com/int128/kubelogin), follows this model faithfully: kubectl spawns a short-lived kubelogin process, which outputs a token to stdout and exits.

This model has a fundamental conflict with OAuth2 refresh token rotation:

1. Two `kubectl` commands run concurrently (common in scripts, Helm, parallel operations)
2. Each spawns a separate kubelogin process
3. Both read the same cached refresh token (RT1) from disk
4. Both send RT1 to the Identity Provider (IdP) for refresh
5. The IdP, following [OAuth2 security best practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.14.2), detects refresh token reuse
6. The IdP revokes the entire session as a potential token theft indicator
7. **All tokens are permanently invalidated** — only a full browser re-authentication can recover

This is not a theoretical concern. On NRP Nautilus (National Research Platform), we observed:
- 65+ `invalid_grant` complaints on the community Matrix channel
- Admin confirmation (2022) that concurrent kubectl breaks token exchange
- Standard "fix" is always: delete cache, re-authenticate via browser
- Our own experiments: 3 token corruptions in 12 hours of automated kubectl usage

### Why kubelogin's existing mitigation fails

kubelogin uses `gofrs/flock` (file-based advisory locking) to serialize cache access. The code is correct in isolation — lock is acquired before cache read and held through write. However:

- **NFS/network filesystems**: `flock(2)` on Linux NFS is emulated as POSIX locks with known reliability issues. Many shared lab environments (including NRP) mount home directories over NFS.
- **Stale lock files**: Users (and tools) delete `.lock` files to recover from hung kubectl. This creates a new inode, breaking the lock for any process holding the old inode.
- **Cross-machine sharing**: Token caches shared via NFS between machines have no cross-host flock coordination.

### Who is affected

Only users who authenticate interactively (browser/device code flow) AND run concurrent kubectl. This is precisely:
- Researchers running automated experiment scripts
- Users of tools that make parallel k8s API calls (Helm, Argo, custom controllers)
- Anyone with kubectl aliases/scripts that pipeline multiple commands

CI/CD pipelines are NOT affected — they use service account tokens or client credentials (static secrets, no rotation).

## 2. Design Goals

1. **Zero token corruption** — concurrent kubectl must never invalidate tokens
2. **Zero-latency token serving** — kubectl should never wait for a refresh
3. **Zero configuration** — drop-in replacement, no systemd/launchd setup required
4. **Cross-platform** — Linux, macOS, Windows
5. **Backward compatible** — same kubeconfig flags, same auth flows
6. **Minimal codebase** — reuse kubelogin's battle-tested OIDC/OAuth2 libraries

## 3. Architecture

### Overview

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────┐
│   kubectl    │────▶│  kubelogin-daemon│────▶│   OIDC IdP   │
│              │     │  (get-token shim)│     │  (authentik)  │
│  exec plugin │     │        │         │     │              │
│  protocol    │◀────│        ▼         │     │              │
│  (stdout)    │     │   daemon process │◀───▶│  token       │
└─────────────┘     │   (Unix socket)  │     │  endpoint    │
                    └─────────────────┘     └──────────────┘
```

### Two-process model

**Daemon process** (long-running background process):
- Holds tokens in memory (no file cache needed for active tokens)
- Proactively refreshes at ~80% of token lifetime (e.g., every 12 min for 15-min tokens)
- Uses `singleflight` to coalesce concurrent refresh requests
- Listens on a Unix socket (Linux/macOS) or named pipe (Windows)
- Auto-exits after idle timeout (default: 30 minutes no requests)

**Shim process** (short-lived, called by kubectl):
- Implements the exec credential plugin protocol (read env, write JSON to stdout)
- Connects to daemon via Unix socket
- If daemon is not running, auto-starts it (fork + detach)
- Receives token from daemon, formats as ExecCredential, exits

### Token lifecycle

```
Daemon starts
  │
  ├─▶ Initial auth (device code / browser / cached refresh token)
  │     │
  │     ▼
  │   Token in memory ◀──────────────────────┐
  │     │                                     │
  │     ├─▶ kubectl request → return token    │
  │     │   (from memory, ~nanoseconds)       │
  │     │                                     │
  │     ├─▶ 80% of token lifetime reached     │
  │     │   → proactive refresh ──────────────┘
  │     │   (background, invisible to kubectl)
  │     │
  │     └─▶ 30 min no kubectl requests
  │         → daemon exits cleanly
  │         → refresh token persisted to disk
  │
  └─▶ Next kubectl call
        → shim finds no daemon
        → auto-starts daemon
        → daemon reads persisted refresh token
        → refreshes → serves token
```

### Concurrency model

```go
type tokenManager struct {
    current atomic.Pointer[tokenEntry]   // lock-free read
    group   singleflight.Group           // coalesces refreshes
}

// Called by every kubectl request — lock-free, nanoseconds
func (m *tokenManager) GetToken() *oidc.TokenSet {
    return m.current.Load().tokenSet
}

// Called by proactive refresh timer AND on-demand if token expired
func (m *tokenManager) Refresh(ctx context.Context) (*oidc.TokenSet, error) {
    v, err, _ := m.group.Do("refresh", func() (any, error) {
        // Exactly one goroutine executes this
        newTokenSet, err := m.oidcClient.Refresh(ctx, m.currentRefreshToken())
        if err != nil {
            return nil, err
        }
        m.current.Store(&tokenEntry{tokenSet: newTokenSet, obtainedAt: time.Now()})
        m.persistRefreshToken(newTokenSet.RefreshToken)
        return newTokenSet, nil
    })
    if err != nil {
        return nil, err
    }
    return v.(*oidc.TokenSet), nil
}
```

**Why this cannot break:**
- `atomic.Pointer` — lock-free reads, no mutex contention
- `singleflight.Group` — in-process coordination, no filesystem dependency
- Single refresh token holder — only the daemon process ever touches the refresh token
- No concurrent refresh possible — singleflight guarantees exactly one in-flight refresh

### IPC protocol

JSON over Unix socket (or named pipe on Windows):

```
→ Request:  {"command": "get-token", "provider": "https://authentik.example.com/..."}
← Response: {"token": "eyJ...", "expiry": "2026-03-01T15:30:00Z"}

→ Request:  {"command": "health"}
← Response: {"status": "ok", "token_expiry": "2026-03-01T15:30:00Z", "uptime": "3h25m"}
```

### Socket location & permissions

| Platform | Path | Permissions |
|----------|------|-------------|
| Linux | `$XDG_RUNTIME_DIR/kubelogin-daemon/sock` or `/tmp/kubelogin-daemon-$UID/sock` | Dir: `0700`, Socket: `0600` |
| macOS | `/tmp/kubelogin-daemon-$UID/sock` | Dir: `0700`, Socket: `0600` |
| Windows | `\\.\pipe\kubelogin-daemon-$USERNAME` | Current user ACL only |

`$XDG_RUNTIME_DIR` (typically `/run/user/$UID` on systemd systems) is ideal: tmpfs, per-user, auto-cleaned on logout.

## 4. Rejected Alternatives

### 4a. Status quo: flock + stateless CLI

**What it is**: Current kubelogin approach. Each kubectl call spawns a new process, uses `flock(2)` on cache file for mutual exclusion.

**Why rejected**:
- flock fails on NFS (common in shared lab environments)
- flock fails when lock files are deleted (common "recovery" action)
- Even when flock works, every kubectl call pays the cost of: process startup → OIDC discovery → cache read → expiration check → potential refresh → cache write → process exit
- Fundamentally incompatible with refresh token rotation under concurrent access

**Verdict**: The root cause. Not a mitigation option.

### 4b. flock wrapper around kubectl

**What it is**: Our interim fix. A shell wrapper at `~/.local/bin/kubectl` that uses `flock` to serialize all kubectl calls globally.

```bash
exec flock -w 120 "$LOCK" /usr/bin/kubectl "$@"
```

**Why it works (partially)**:
- Prevents concurrent kubelogin invocations by preventing concurrent kubectl entirely
- Lock file is on local filesystem (`$HOME/.kube/`), not NFS

**Why rejected as permanent solution**:
- Serializes ALL kubectl calls, even reads that don't need tokens
- Adds latency to every kubectl command (flock syscall overhead)
- Still uses file-based locking (same class of fragility)
- Doesn't solve proactive refresh (token still expires on the critical path)
- Doesn't help if user bypasses wrapper (direct `/usr/bin/kubectl`)

**Verdict**: Good interim fix. Not a real solution.

### 4c. systemd/launchd managed daemon

**What it is**: Install the daemon as a proper system service (`systemd --user` on Linux, LaunchAgent on macOS, Windows Service on Windows).

**Advantages**:
- OS guarantees restart on crash
- Proper logging via journald/syslog
- Starts on boot (if enabled)
- Well-understood operational model

**Why rejected as default**:
- Requires installation step (`systemctl --user enable`, writing plist files)
- Different mechanism per OS (systemd vs launchd vs Windows Service)
- Daemon runs even when not needed (wastes resources)
- Some environments don't have systemd (containers, minimal Linux, WSL1)
- Higher barrier to adoption — users want `brew install` and done

**Verdict**: Offered as opt-in (`kubelogin-daemon install-service`), not the default. For users who want it, `kardianos/service` abstracts the cross-platform differences.

### 4d. kubectl-level caching improvement

**What it is**: Propose changes to kubectl's exec credential plugin caching to avoid redundant plugin invocations.

**Why rejected**:
- Requires upstream Kubernetes changes (slow, multi-year KEP process)
- kubectl already caches based on `expirationTimestamp`, but separate kubectl processes don't share cache
- Doesn't solve the fundamental refresh-token-rotation problem
- We have no influence over k8s SIG Auth

**Verdict**: Correct long-term fix for the ecosystem, but not actionable for us.

### 4e. Patch the IdP to not rotate refresh tokens

**What it is**: Configure authentik (or ask NRP admins) to disable refresh token rotation.

**Why rejected**:
- Reduces security (refresh token reuse detection is a security feature)
- Requires admin action (NRP admins are unresponsive)
- Doesn't fix the problem for other clusters/IdPs
- Violates OAuth2 security best practices

**Verdict**: Wrong direction. We should work WITH rotation, not against it.

### 4f. Pinniped

**What it is**: VMware's credential management solution for Kubernetes. Includes a "Concierge" server-side component and client-side credential exchange.

**Why rejected**:
- Requires server-side installation (Concierge on every cluster) — not possible on NRP
- Heavyweight operator model (CRDs, controllers, webhooks)
- Fundamentally different architecture from exec credential plugins
- Overkill for the specific problem we're solving

**Verdict**: Right idea (centralized credential management), wrong scope (requires cluster admin cooperation).

## 5. Why kubelogin Doesn't Already Have a Daemon

This is the question that nags: are we missing something? Is there a good reason the most popular OIDC kubectl plugin (4k+ GitHub stars) hasn't implemented daemon mode in 7+ years?

### Reasons we can confirm:

1. **The exec credential plugin spec assumes stateless tools.** The Kubernetes API literally defines the protocol as: invoke binary → read stdout → binary exits. kubelogin faithfully implements this spec. Adding a daemon means going outside the spec (the shim still conforms, but the architecture is non-standard).

2. **Most IdPs don't rotate refresh tokens.** Google, Azure AD, Okta — the biggest OIDC providers — issue stable refresh tokens. Concurrent refresh with a stable token is idempotent. The problem only manifests with IdPs that implement rotation (authentik, Keycloak with rotation enabled, etc.). This makes it a minority pain point.

3. **The affected user base is small.** You need: interactive OIDC auth + concurrent kubectl + rotating refresh tokens + unreliable flock (NFS). Each condition narrows the population. Most kubelogin users are on a laptop with local disk, running one kubectl at a time.

4. **Daemon adds operational complexity.** Process lifecycle, socket management, crash recovery, cross-platform IPC, idle timeout — these are real concerns that the current model avoids entirely. For a tool that "just works" 95% of the time, adding a daemon feels like overengineering.

5. **kubelogin's issue tracker confirms awareness but not urgency.** Issues #628, #734, #909, #1144, #1485 all relate to concurrent access problems. The maintainer's responses focus on improving flock reliability, not architectural changes. This suggests a conscious choice to iterate within the current model.

### Reasons we're uncertain about:

6. **Is there an OAuth2/OIDC reason not to hold tokens in a long-running process?** We haven't found one. `ssh-agent` and `gpg-agent` hold sensitive keys in memory indefinitely. A daemon holding OIDC tokens is arguably less sensitive (tokens expire, keys don't).

7. **Does the exec credential plugin spec technically prohibit a daemon?** No. The spec only defines the stdin/stdout/env interface. What happens behind the scenes (including talking to a daemon) is an implementation detail. The shim is fully spec-compliant.

8. **Are there security implications of a Unix socket serving tokens?** Yes, but manageable. Socket in a `0700` directory, owned by the user. Same security model as `ssh-agent`. An attacker with access to your Unix socket already has access to your `~/.kube/cache/` files anyway.

### Reasons discovered in external review (March 2026):

6. **kubelogin already got burned by local server components.** The authcode flow starts a local HTTP callback server (default port 8000/18000). Concurrent kubectl hits port conflicts; users report "server already running but new process can't connect" ([#389](https://github.com/int128/kubelogin/issues/389)). This direct history of pain with long-running local server components makes the maintainer understandably conservative about adding another one (a daemon).

7. **Keyring persistence is a minefield.** kubelogin added OS keyring support, and immediately hit: tokens too large for keyring entry limits, Linux secret service unlock failures, platform-specific bugs ([#1255](https://github.com/int128/kubelogin/issues/1255)). If daemon reliability depends on keyring, we inherit the same minefield. Our mitigation: use plain file persistence as primary, keyring as opt-in.

8. **Maintainer is still actively iterating within the current model.** v1.36.0 expanded cache key parameters. The approach is "keep fixing edge cases in the stateless model" rather than "rearchitect." This is a deliberate, rational strategy: incremental fixes are cheaper to maintain and review than architectural changes.

9. **RFC 6819 explicitly models concurrent refresh token use as a threat.** Our analysis of why concurrent refresh causes session revocation is correct per the OAuth2 threat model ([RFC 6819](https://www.rfc-editor.org/rfc/rfc6819.html)). But this means IdPs that do rotation are *working as designed* — the "bug" is in the client architecture, not the server.

### Our updated assessment:

The kubelogin maintainer's position is rational. Their objective function optimizes for "simple, portable, low support cost" across a broad user base where 95% never hit the concurrent refresh problem. Our objective function optimizes for "absolute reliability in hostile environments" (NFS, rotating refresh tokens, automated concurrent kubectl). Both are valid — we serve different audiences.

There is no fundamental technical or security reason prohibiting a daemon approach. The exec credential plugin spec ([k8s docs](https://kubernetes.io/docs/reference/config-api/client-authentication.v1/)) only specifies the stdin/stdout interface; what happens behind the scenes is an implementation detail.

**Strategy**: Ship as independent project. Prove value with hard data ("100 concurrent kubectl, zero invalid_grant"). If upstream interest develops, propose as opt-in daemon mode (default off). Do not bind the upstream maintainer's complexity budget.

## 6. What We Reuse From kubelogin

kubelogin's codebase is ~3,351 lines of production Go code, cleanly modularized:

| Package | Lines | Reuse? | Notes |
|---------|-------|--------|-------|
| `pkg/oidc/client/` | 544 | **Yes** | OIDC discovery, token refresh, verification |
| `pkg/usecases/authentication/` | 941 | **Yes** | Auth code (browser), device code, ROPC, client credentials |
| `pkg/tokencache/` | 247 | **Partial** | Cache key computation reused; file I/O replaced with in-memory |
| `pkg/credentialplugin/` | 127 | **Partial** | Writer reused for shim; Reader reused for env parsing |
| `pkg/infrastructure/` | 201 | **Yes** | Logging, clock, browser opener |
| `pkg/cmd/` | 663 | **No** | CLI flag parsing — replaced with daemon config |
| `pkg/di/` | ~100 | **No** | Wire dependency injection — simplified for daemon |

**Reused: ~1,900 lines** (as library imports, not copy-paste)
**New code: ~500 lines** (daemon server, shim, IPC protocol, lifecycle management)

## 7. New Components

### 7a. Daemon server (~200 lines)

- Unix socket listener (Linux/macOS) / named pipe (Windows)
- Request dispatcher (get-token, health, shutdown)
- Token manager (atomic pointer + singleflight + proactive refresh timer)
- Graceful shutdown on SIGTERM/SIGINT
- Idle timeout auto-exit

### 7b. Shim (exec credential plugin) (~100 lines)

- Connect to daemon socket
- If connection refused: fork daemon, wait for socket ready, retry
- Send get-token request, receive response
- Format as ExecCredential JSON, write to stdout
- Exit

### 7c. IPC protocol (~50 lines)

- JSON request/response over Unix socket
- Framing: newline-delimited JSON (one request, one response, close)
- No streaming, no multiplexing — keep it simple

### 7d. Daemon lifecycle (~100 lines)

- PID file for status checks (optional, socket existence is sufficient)
- `daemon start` — start in background (fork + setsid + redirect stdio)
- `daemon stop` — connect to socket, send shutdown command
- `daemon status` — connect to socket, send health check
- Auto-start from shim on first kubectl call

### 7e. Configuration (~50 lines)

- Read kubeconfig exec args (same flags as kubelogin)
- Additional daemon-specific flags: `--idle-timeout`, `--refresh-margin`, `--socket-path`
- Config file support (optional): `~/.config/kubelogin-daemon/config.yaml`

## 8. External Review Findings

An independent review (GPT Codex, March 2026) identified the following. Items are categorized by our response.

### Accepted and incorporated:

1. **Persist refresh token on every successful refresh, not just daemon exit.** A crash between refresh and exit loses the only authoritative token. Fixed: `persistRefreshToken()` is called inside the singleflight callback immediately after successful refresh (see Section 3, Concurrency model).

2. **Dual-daemon startup race.** Two shims may simultaneously discover no daemon and fork two instances. Mitigation: `bind()` on Unix socket is atomic — second daemon gets `EADDRINUSE`, detects this, exits. Shim retries connection with backoff.

3. **Cache key must match kubelogin's full semantics.** Using only issuer + client_id is insufficient. Different scopes, extra params, or usernames with the same issuer would collide. Fixed: reuse kubelogin's `tokencache.Key` struct and `computeChecksum()` for exact compatibility.

4. **Add `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS) verification on socket.** Beyond directory permissions, explicitly verify connecting process UID matches daemon UID. Defense in depth.

5. **Protocol versioning.** All requests include `"version": 1`. Daemon rejects unknown versions with a clear error.

### Acknowledged but out of scope:

6. **Cross-host NFS token sharing.** Our architecture explicitly requires each host to authenticate independently. NFS-shared caches are the root cause of the original problem — we eliminate them, not accommodate them.

7. **Tokens in RAM have longer exposure.** True, but same threat model as `ssh-agent`/`gpg-agent`. Tokens expire (unlike SSH keys), limiting blast radius. Users who need stronger isolation can use the keyring backend.

8. **Same-user process can read socket.** True, but same-user can also read `~/.kube/cache/` files today. No change in threat model.

### Considered but not acted on:

9. **"Maintainers will object."** Expected. We ship as an independent project first. Upstream merge is a non-goal for v1.

10. **Windows ACL details.** Deferred to implementation phase. Named pipe ACLs are well-documented; not an architectural risk.

## 9. Edge Cases & Failure Modes

This section enumerates every failure scenario we have identified, with the planned mitigation for each.

### 9a. Daemon Lifecycle

| Scenario | What happens | Mitigation |
|----------|-------------|------------|
| **Stale socket file** (daemon died without cleanup) | Shim `connect()` fails with `ECONNREFUSED` | Shim detects this, `unlink()` stale socket, forks new daemon |
| **Two shims race to start daemon** | Both fork; second daemon's `bind()` gets `EADDRINUSE` | Second daemon logs and exits. Shim retries connect with 50ms backoff, max 3 retries |
| **Daemon crashes mid-refresh** | In-memory token lost. Refresh token was persisted on last successful refresh | New daemon reads persisted RT from disk, attempts refresh. If RT is stale (IdP already rotated it), falls back to browser re-auth |
| **Daemon OOM-killed** | Same as crash | Same as crash. Daemon should have low memory footprint (~10MB) |
| **Fork fails** (ulimit, permissions) | Shim gets error from `os.StartProcess` | Shim returns error to kubectl. User sees "could not start daemon: [reason]" |
| **Daemon cannot bind socket** (path too long, permissions) | `bind()` fails | Daemon exits with clear error. Unix socket path limit is ~104 bytes (macOS) / ~108 bytes (Linux). Default paths are well within limit: `/tmp/kubelogin-daemon-$UID/sock` (~35 chars) |
| **`/tmp` cleaned by tmpwatch/systemd-tmpfiles** | Socket disappears while daemon runs | Daemon's `Accept()` starts failing. Daemon detects this (accept error loop), exits. Next shim call auto-starts new daemon |
| **User runs `daemon stop` while kubectl is in flight** | In-progress shim connections get EOF | Daemon completes in-flight requests before shutdown (graceful shutdown with 5s deadline). Shim handles EOF by auto-restarting daemon |

### 9b. Token Management

| Scenario | What happens | Mitigation |
|----------|-------------|------------|
| **Proactive refresh fails (network blip)** | Timer fires, refresh returns error | Retry with exponential backoff (1s, 2s, 4s, max 30s). Continue serving current token until it actually expires. Log warnings. |
| **Proactive refresh fails repeatedly until token expires** | Current ID token expires, no valid token to serve | Return error to shim/kubectl. User sees auth error, needs to re-auth. Daemon attempts browser/device-code flow if possible. |
| **IdP returns very short token lifetime (< 1 min)** | Proactive refresh fires very frequently | Minimum refresh interval of 10 seconds. If token lifetime < 30s, log warning: "IdP is issuing very short-lived tokens" |
| **IdP returns very long token lifetime (> 24 hours)** | Daemon may idle-exit before refresh is due | On idle-exit, persist both refresh token AND current ID token. On restart, serve persisted ID token immediately while refreshing in background. |
| **Refresh token itself expires** (typical: 7-90 days) | `Refresh()` returns `invalid_grant` | Fall back to full authentication flow (device code / browser). Daemon logs "refresh token expired, re-authentication required". |
| **Persist-to-disk fails** (disk full, permissions) | Refresh succeeds but can't save RT | Log error. Continue serving from memory. If daemon crashes, user needs re-auth. Acceptable degradation. |
| **IdP OIDC metadata changes** (endpoints rotate) | Cached provider metadata becomes stale | Re-discover OIDC metadata on refresh failure. If still fails, periodic re-discovery every 1 hour. |
| **Clock skew** | Proactive refresh fires too early/late | Use token's `exp` claim minus margin, not wall-clock interval. If local clock jumps, worst case is one refresh slightly early/late — not catastrophic. |

### 9c. Network

| Scenario | What happens | Mitigation |
|----------|-------------|------------|
| **Network down during proactive refresh** | HTTP request times out | Retry with backoff. Serve current token until expiry. Network recovery → next retry succeeds. |
| **VPN connect/disconnect** | HTTP client may have stale proxy/DNS | Create new `http.Client` on each refresh attempt (don't cache transport). Slight overhead, but refresh is infrequent (~4x/hour). |
| **DNS failure during OIDC discovery** | `gooidc.NewProvider()` fails | Retry with backoff. If initial startup, daemon exits with error. If mid-operation, continue with cached provider metadata. |
| **IdP is temporarily down** | All refreshes fail | Exponential backoff up to 60s. Continue serving current token until expiry. |

### 9d. Platform-Specific

| Scenario | What happens | Mitigation |
|----------|-------------|------------|
| **macOS App Nap** freezes daemon | Timer callbacks delayed, refresh doesn't fire on time | Disable App Nap via `NSProcessInfo.beginActivity()` or the Go equivalent (`mdls` activity assertion). Or: rely on on-demand refresh as fallback. |
| **macOS Gatekeeper / notarization** | Unsigned binary blocked | Sign and notarize release binaries. Or: users `xattr -d com.apple.quarantine` on download. Document in README. |
| **Linux SELinux/AppArmor** blocks socket | `bind()` fails with `EACCES` | Socket is in `/tmp` or `$XDG_RUNTIME_DIR`, which are typically allowed. Document SELinux context if needed. |
| **Windows named pipe** ACL issues | Pipe created with wrong permissions | Use `windows.SECURITY_ATTRIBUTES` with explicit user-only ACL. Test on Windows CI. |
| **WSL1** (no real Unix sockets) | `bind()` may behave differently | WSL1 is legacy; WSL2 has full socket support. Document WSL1 as unsupported. |

### 9e. Multi-Provider / Multi-Context

| Scenario | What happens | Mitigation |
|----------|-------------|------------|
| **User has 3 clusters on 2 different IdPs** | Daemon needs multiple token sets | Daemon maintains a `map[cacheKey]*tokenManager`. Each provider+scope combo gets its own manager, refresh timer, and singleflight group. |
| **Same IdP, different scopes** | Could collide if keying is wrong | Use kubelogin's full `tokencache.Key` (issuer + client_id + scopes + extra_params + username). Already covered in review finding #3. |
| **One provider fails, others work** | Partial failure | Each token manager is independent. Failure in one doesn't affect others. Shim request specifies which provider key it needs. |

### 9f. Upgrade & Versioning

| Scenario | What happens | Mitigation |
|----------|-------------|------------|
| **Shim v2 connects to daemon v1** | Protocol mismatch | Protocol version in every request. Daemon returns `{"error": "unsupported protocol version 2"}`. Shim detects this, sends `shutdown` to old daemon, starts new one. |
| **User upgrades binary while daemon running** | Old daemon still running with old code | Shim checks daemon version via health endpoint. If mismatch, gracefully restarts daemon. |
| **Persisted token format changes between versions** | Can't read old cache | Version field in persisted file. Migration code reads old format. If unreadable, treat as missing (triggers re-auth). |

### 9g. Security Hardening

| Concern | Mitigation |
|---------|------------|
| **Core dumps contain tokens** | Set `RLIMIT_CORE` to 0 on daemon startup (`syscall.Setrlimit`). Alternatively, use `mlock` for token memory. |
| **`/proc/$PID/mem` readable by same user** | Same threat model as `ssh-agent`. Accepted risk. |
| **Log sanitization** | Never log token values, refresh tokens, or full HTTP response bodies. Log only: token expiry time, issuer URL, error messages (sanitized). |
| **Symlink attacks on `/tmp`** | Create socket directory with `O_NOFOLLOW` semantics. Check directory ownership after creation. Refuse to use pre-existing directory owned by different user. |
| **Request flooding (local DoS)** | Rate limit socket connections: max 100/second. Max 10 concurrent connections. More than enough for any kubectl usage pattern. |

## 10. Design Principles (Hard Rules)

Derived from kubelogin's history, our own debugging, and two independent reviews.

### P1: Never persist to NFS

Refresh token persistence MUST default to a per-machine local directory:
- Linux: `$XDG_RUNTIME_DIR/kubelogin-daemon/` (typically `/run/user/$UID/`, tmpfs)
- macOS: `/tmp/kubelogin-daemon-$UID/`
- Fallback: accept "restart requires re-auth" over writing to NFS home

If `$XDG_RUNTIME_DIR` is not set (non-systemd systems), fall back to `/tmp/kubelogin-daemon-$UID/`.

Keyring is opt-in, never default. We will not debug keyring bugs as a blocking issue.

### P2: No file locks, anywhere, ever

The entire motivation for this project is that file locks are unreliable. We must not reintroduce them in any form:
- Daemon singleton: via socket `bind()` atomicity, not lockfiles
- Token storage: via in-memory atomic pointer, not file locks
- Startup coordination: via connect-or-fork, not lock-then-start

### P3: Prefer slow over broken

State mutation rules:
- New token obtained → store in memory first (atomic pointer swap)
- Then persist to disk (best-effort; failure logged, not fatal)
- Refresh failure → continue serving old token until actual expiry
- Never delete/overwrite persisted state before new state is confirmed valid
- Never clear old token then write new token (crash between = empty state)

Write pattern for persistence:
```
write to temp file → fsync → rename over old file (atomic on POSIX)
```

### P4: Startup storm must converge without locks

100 concurrent kubectl calls, daemon not running → 100 shims try to start daemon:
1. Each shim tries `connect()` → fails
2. Each shim tries `fork daemon`
3. Each forked daemon tries `bind(socket)` → exactly one succeeds
4. 99 daemons get `EADDRINUSE` → exit silently
5. 99 shims retry `connect()` with jittered backoff (50-200ms) → succeed

No lockfile. No PID file for coordination. Socket bind is the election.

### P5: Verify peer identity on every connection

- Linux: `SO_PEERCRED` → check `uid` matches daemon's `uid`
- macOS: `getpeereid()` → check uid
- Windows: named pipe security descriptor with user-only ACL
- Reject connections from different UIDs, even if socket permissions somehow allow them

### P6: Protocol must be forward-compatible

Every request includes `"version": N`. Rules:
- Daemon receiving unknown version → return error with `{"error": "unsupported version", "daemon_version": M}`
- Shim receiving version mismatch → send `shutdown` to old daemon, start new one, retry
- Persisted token file includes format version → migration on read, not on write

## 11. Open Questions

1. **Should persisted token format be compatible with kubelogin's cache?** If yes, users can seamlessly switch between kubelogin and kubelogin-daemon. If no, we get a cleaner format but require re-auth on first use. Leaning yes for adoption.

2. **What is the right idle timeout default?** 30 minutes feels right for interactive use. But during long experiments (12+ hours), kubectl calls may be spaced > 30 min apart. Should the daemon detect "active experiment" patterns and extend timeout? Or just let it restart — restart cost is low (1-2 seconds).

3. **Should daemon log to file by default?** Pro: debuggability. Con: log rotation, disk usage, sensitive data risk. Leaning: log to stderr (captured if launched via systemd), plus `--log-file` flag for explicit opt-in.

4. **How to handle "daemon needs browser auth but has no TTY"?** If daemon was auto-started by shim and needs initial auth (no cached refresh token), it can't open a browser from a detached process. Options: (a) shim detects this and does the browser flow itself before forking daemon, (b) daemon writes URL to a well-known file, shim reads and displays it, (c) require initial `kubelogin-daemon login` from terminal.

5. **Should we support kubelogin's `--listen-address` equivalent?** The authcode flow needs a local callback server. If daemon handles this, we inherit the port conflict problems kubelogin already has ([#389](https://github.com/int128/kubelogin/issues/389)). Mitigation: use random port with SO_REUSEADDR, or prefer device-code flow for daemon (no local server needed).

## 12. Logging Strategy

### Daemon logging

The daemon runs detached (no TTY). Logging must be explicit:

- **Default**: Write to `$RUNTIME_DIR/daemon.log` (same directory as socket)
- **Max size**: 1MB ring buffer (overwrite oldest entries). No log rotation dependency.
- **Default level**: WARN and above. INFO only with `--verbose` / `-v`.
- **Never log**: token values, refresh tokens, full HTTP response bodies, authorization headers
- **Always log**: token expiry times, issuer URLs, error messages (sanitized), refresh success/failure, daemon start/stop/crash recovery

### Shim logging

The shim's stderr is passed through by kubectl to the user's terminal:
- Errors (daemon unreachable, auth required) → stderr
- Device-code flow prompts ("Please visit https://... and enter code XXXX") → stderr
- Normal operation → silent (no output except ExecCredential JSON on stdout)

### systemd/launchd mode

When run via service manager, daemon logs to stderr (captured by journald/syslog). `--log-file` flag overrides for explicit file output.

## 13. Module Strategy

**Approach: Full fork of int128/kubelogin.**

Rationale:
- Architectural changes too large for upstream acceptance (daemon is a fundamental model shift)
- Need to modify core packages (`pkg/usecases/credentialplugin/`, `pkg/tokencache/`)
- Want full control over dependencies and release cadence
- Module path: `github.com/$USER/kubelogin-daemon`

What changes from upstream:
- `pkg/cmd/` → rewritten for daemon CLI (`daemon start/stop/status`, `get-token` shim)
- `pkg/usecases/credentialplugin/` → rewritten (socket client instead of direct auth)
- `pkg/tokencache/repository/` → replaced with in-memory store + file persistence
- `pkg/di/` → simplified (no Wire, direct construction)
- New: `pkg/daemon/` (socket server, token manager, lifecycle)
- New: `pkg/shim/` (exec credential plugin shim, auto-start logic)

What stays unchanged:
- `pkg/oidc/client/` (OIDC discovery, refresh, verification)
- `pkg/usecases/authentication/` (all auth flows)
- `pkg/infrastructure/` (logging, clock, browser)
- `pkg/credentialplugin/writer/` (ExecCredential formatting)

## 14. Implementation Plan

| Phase | Scope | Effort |
|-------|-------|--------|
| 1 | Core daemon + shim + Unix socket (Linux/macOS only) | 1 day |
| 2 | Proactive refresh + singleflight + idle timeout | 0.5 day |
| 3 | Auto-start from shim (gpg-agent model) | 0.5 day |
| 4 | Windows named pipe support | 0.5 day |
| 5 | `install-service` command (kardianos/service) | 0.5 day |
| 6 | Testing + documentation + GitHub release | 1 day |
| **Total** | | **4 days** |

## 15. Success Criteria

1. Run 100 concurrent `kubectl get pods` — zero `invalid_grant` errors
2. Token refresh invisible to user (< 1ms latency for cached token serving)
3. `brew install kubelogin-daemon` + change one line in kubeconfig = done
4. Works on Linux (amd64, arm64), macOS (arm64), Windows (amd64)
5. Daemon auto-starts, auto-exits, auto-recovers — zero manual lifecycle management
