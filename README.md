# kubelogin-daemon

A daemon-based OIDC credential plugin for kubectl. Drop-in replacement for [int128/kubelogin](https://github.com/int128/kubelogin) that eliminates concurrent token corruption, adds defense-in-depth security, and works in headless/AI agent environments.

## Why kubelogin-daemon?

The upstream kubelogin spawns a **new process for every kubectl call**. Each process independently reads the same refresh token from disk and sends it to the OIDC provider. This architecture has three fundamental problems:

### 1. Concurrent kubectl calls corrupt tokens

When an AI agent, CI pipeline, or shell script runs multiple kubectl commands in parallel, each kubelogin process races to refresh the same token. Per [OAuth2 security best practice (RFC draft-ietf-oauth-security-topics)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.14.2), reuse of a rotation-based refresh token is treated as token theft — the provider revokes the entire session. The user must re-authenticate.

**kubelogin-daemon** runs a single background daemon that holds tokens in memory. All kubectl calls connect to the daemon over a Unix socket (or Windows named pipe). A `singleflight` coalescer ensures that 100 concurrent refresh requests produce exactly **one** OIDC call. No token is ever used twice.

### 2. File-based token cache is fragile

Upstream kubelogin coordinates access to `~/.kube/cache/` via `flock`. This breaks on NFS, fails with stale lock files, and provides no protection against symlink attacks on the cache directory.

**kubelogin-daemon** stores tokens in memory with an `atomic.Pointer` (lock-free, nanosecond reads) and persists to a `0700` runtime directory using atomic temp+fsync+rename writes. Every file open uses `O_NOFOLLOW` (Unix) or reparse point detection (Windows) to reject symlinks.

### 3. Interactive auth blocks automation

Upstream kubelogin tries to open a browser on every login. This fails in SSH sessions, containers, CI/CD, and any headless environment.

**kubelogin-daemon** uses device-code flow by default: it prints a URL and code, you authenticate from any browser on any device. The daemon runs headless, the browser runs wherever you want.

## Quick Start

### Install

**Linux / macOS** (one-line):
```sh
curl -fsSL https://raw.githubusercontent.com/ZihaoZhou/kubelogin-daemon/daemon-mode/install.sh | sh
```

**Windows** (PowerShell):
```powershell
irm https://raw.githubusercontent.com/ZihaoZhou/kubelogin-daemon/daemon-mode/install.ps1 | iex
```

Or download the binary manually from [GitHub Releases](https://github.com/ZihaoZhou/kubelogin-daemon/releases).

### Migrate from upstream kubelogin

If you already have kubelogin configured:

```sh
kubelogin-daemon setup migrate
```

This scans your kubeconfig, replaces `kubectl-oidc_login` / `kubelogin` entries with `kubelogin-daemon`, and creates a backup. Use `--dry-run` to preview changes.

### Upgrade

Re-run the same install command — it detects the existing installation and upgrades automatically:

```sh
# Linux/macOS
curl -fsSL https://raw.githubusercontent.com/ZihaoZhou/kubelogin-daemon/daemon-mode/install.sh | sh

# Windows (PowerShell)
irm https://raw.githubusercontent.com/ZihaoZhou/kubelogin-daemon/daemon-mode/install.ps1 | iex
```

Or if you placed the new binary at a different path manually:

```sh
kubelogin-daemon setup upgrade
```

This updates kubeconfig, stops the old daemon, and deletes the old binary. Use `--dry-run` to preview.

### Fresh install

```sh
kubelogin-daemon setup install \
  --oidc-issuer-url=https://YOUR_ISSUER \
  --oidc-client-id=YOUR_CLIENT_ID
```

### Authenticate

```sh
kubelogin-daemon login
```

This prints a device-code URL. Open it in any browser, authenticate, done. The daemon starts automatically in the background.

### Use kubectl

```sh
kubectl get pods
```

That's it. The daemon starts on demand, refreshes tokens proactively, and shuts down after 30 minutes of inactivity. You never interact with it directly.

## How It Works

```
kubectl ──exec──▶ kubelogin-daemon get-token ──socket──▶ daemon process
                   (shim, ~1ms)                          (long-lived, holds tokens)
                                                          │
                                                          ├─ atomic.Pointer[token]  ← lock-free reads
                                                          ├─ singleflight.Group     ← coalesced refreshes
                                                          └─ proactive refresh      ← 80% of token lifetime
```

1. kubectl calls `kubelogin-daemon get-token` as a credential plugin (same as upstream)
2. The shim connects to the daemon over a Unix socket / named pipe (~1ms)
3. If no daemon is running, the shim auto-starts one (transparent, <3s cold start)
4. The daemon returns the cached token or triggers a single coalesced refresh
5. Token is returned to kubectl as an ExecCredential

## Performance

| Metric | kubelogin-daemon | upstream kubelogin |
|--------|-----------------|-------------------|
| Token read latency | ~nanoseconds (atomic pointer) | ~milliseconds (disk read + JSON parse) |
| 100 concurrent kubectl calls | 1 OIDC refresh (singleflight) | 100 OIDC refreshes (token corruption) |
| Memory overhead | 1 daemon process (~10-20MB) | N short-lived processes |
| Proactive refresh | Yes, at 80% of token lifetime | No, refreshes on demand |
| Cold start to token | <3 seconds (auto-start + cached refresh token) | N/A (no daemon) |

## Security

kubelogin-daemon implements defense-in-depth security with labeled audit points (`SEC-CRIT-*`, `SEC-HIGH-*`, `ROB-*`) throughout the codebase, backed by adversarial tests.

| Layer | Mechanism |
|-------|-----------|
| **Socket authentication** | `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS) verifies connecting process UID. Rejects cross-user connections. |
| **Nonce mutual auth** | Daemon writes crypto-random nonce to `0700` runtime dir. Shim reads nonce and includes it in every request. Constant-time comparison prevents timing attacks. |
| **Symlink protection** | `O_NOFOLLOW` (Unix) / `FILE_FLAG_OPEN_REPARSE_POINT` (Windows) on every file open. Rejects symlinks atomically — no TOCTOU gap. |
| **Atomic persistence** | `CreateTemp` + `Chmod(0600)` + `Write` + `Fsync` + `Rename`. Crash-safe: interrupted writes leave the original file intact. |
| **Runtime dir hardening** | `os.Mkdir` (not `MkdirAll`) with UID ownership + `0700` permission checks. Rejects pre-created attacker directories. |
| **Log sanitization** | All JWT tokens (`eyJ...`) redacted from logs. OIDC provider errors masked to prevent credential leaks. |
| **Resource limits** | 256 max concurrent connections, 256 max token managers with LRU eviction, 1MB request size limit, 10MB file size limit. |
| **Core dump disabled** | `RLIMIT_CORE=0` on startup prevents tokens from appearing in core dumps. |
| **Cache key validation** | Hex-only regex (`^[a-fA-F0-9]{1,128}$`) prevents path traversal in cache key parameters. |

### Compared to upstream

| Aspect | kubelogin-daemon | upstream kubelogin |
|--------|-----------------|-------------------|
| Socket auth | Peer UID verification + nonce | None |
| Token storage | In-memory + atomic writes to `0700` dir | File-based cache in `~/.kube/cache/` |
| Symlink protection | `O_NOFOLLOW` on every open | None |
| Directory security | UID ownership validation | Implicit chmod |
| Log sanitization | JWT redaction + error masking | None |
| Connection limits | 256 semaphore | None (one process per call) |
| Core dumps | Disabled | Not disabled |

## AI Agent & Automation Support

kubelogin-daemon was designed for environments where kubectl is called programmatically:

- **No token corruption under concurrency**: Singleflight ensures 1 OIDC call regardless of concurrent kubectl volume
- **No browser required**: Device-code flow works over SSH, in containers, in CI/CD
- **No manual daemon management**: Auto-start on first kubectl call, auto-shutdown on idle
- **Proactive refresh**: Tokens refreshed at 80% of lifetime in the background — agents never see "token expired"
- **Multi-provider**: Single daemon serves up to 256 different OIDC configurations simultaneously
- **Detached refresh context**: If the first kubectl caller times out, in-flight refresh continues for subsequent callers instead of cancelling

## Commands

| Command | Purpose |
|---------|---------|
| `login` | Authenticate via device-code flow (reads config from kubeconfig) |
| `check` | Show token status (`--json` for machine-readable output) |
| `refresh` | Force an immediate token refresh |
| `setup migrate` | Migrate kubeconfig from upstream kubelogin |
| `setup install` | Fresh kubeconfig setup |
| `setup upgrade` | Update kubeconfig to new binary path, stop old daemon, clean old binary |
| `clean` / `logout` | Remove cached tokens and stop daemon |
| `daemon start` | Manually start daemon (usually not needed — auto-starts) |
| `daemon stop` | Manually stop daemon |
| `daemon status` | Check daemon health |

Normal users only need `login`. Everything else is automatic.

## Platform Support

| Platform | Socket | Auth |
|----------|--------|------|
| Linux amd64/arm64 | Unix domain socket + `SO_PEERCRED` | Device code, browser |
| macOS amd64/arm64 | Unix domain socket + `LOCAL_PEERCRED` | Device code, browser |
| Windows amd64/arm64 | Named pipe + SDDL ACL | Device code, browser |

## Troubleshooting

**"Not authenticated. Run 'kubelogin-daemon login' to log in."**

You haven't logged in yet, or the daemon isn't running. Run `kubelogin-daemon login`.

**"Session expired. Run 'kubelogin-daemon login' to re-authenticate."**

Your refresh token expired or was revoked. Run `kubelogin-daemon login` to re-authenticate.

**Token works but kubectl says Forbidden**

Your OIDC token may be missing group claims. Ensure your kubeconfig includes `--oidc-extra-scope=profile,offline_access` (or whatever scopes your provider requires for group claims).

**Migrating from upstream kubelogin**

```sh
kubelogin-daemon setup migrate --dry-run  # preview changes
kubelogin-daemon setup migrate            # apply changes
kubelogin-daemon login                    # authenticate with new daemon
```

**Upgraded binary but kubectl uses old version**

If you placed a new binary at a different path, kubeconfig still points to the old one:

```sh
/path/to/new/kubelogin-daemon setup upgrade  # updates kubeconfig, stops old daemon, cleans old binary
```

## License

Apache License 2.0. Forked from [int128/kubelogin](https://github.com/int128/kubelogin).
