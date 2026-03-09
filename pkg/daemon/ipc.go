package daemon

import (
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/tlsclientconfig"
)

// ProtocolVersion is the current protocol version for daemon<->shim communication.
const ProtocolVersion = 2

// Structured error codes for agent-parseable stderr output.
const (
	ErrCodeTokenExpired        = "TOKEN_EXPIRED"
	ErrCodeTokenRevoked        = "TOKEN_REVOKED"
	ErrCodeLoginInProgress     = "LOGIN_IN_PROGRESS"
	ErrCodeRefreshFailed       = "REFRESH_FAILED"
	ErrCodeProviderUnreachable = "PROVIDER_UNREACHABLE"
	ErrCodeDaemonStartFailed   = "DAEMON_START_FAILED"
	ErrCodeDaemonTimeout       = "DAEMON_TIMEOUT"
	ErrCodeConfigError         = "CONFIG_ERROR"
	ErrCodeNeedsLogin          = "NEEDS_LOGIN"
)

// Request represents a JSON request from shim to daemon.
//
// SEC-7: client_secret is sent on every get-token/store-token call because the
// daemon needs it to create TokenManagers (which use it for refresh). This is
// consistent with how credential helpers work — the secret is passed in the
// kubeconfig exec args and the daemon needs it for token lifecycle management.
// The socket is protected by 0600 permissions + peer UID verification (Unix)
// or ACLs (Windows), same as ssh-agent and gpg-agent.
type Request struct {
	Version  int    `json:"version"`
	Command  string `json:"command"` // "get-token", "store-token", "health", "shutdown", "begin-login", "cancel-login", "check", "refresh"
	CacheKey string `json:"cache_key,omitempty"`

	// Nonce for mutual authentication. The shim reads the nonce file from the
	// runtime dir and includes it in requests. The daemon verifies it matches
	// the nonce it wrote on startup. This proves the shim can read files in the
	// 0700 runtime directory (same user) and that the daemon is the one that
	// created the nonce file (not a rogue process that hijacked the socket).
	// SEC-CRIT-1: Nonce is required — empty nonce is rejected.
	Nonce string `json:"nonce,omitempty"`

	// Provider config for get-token requests.
	// The shim passes these so the daemon knows which provider to serve.
	IssuerURL      string            `json:"issuer_url,omitempty"`
	ClientID       string            `json:"client_id,omitempty"`
	ClientSecret   string            `json:"client_secret,omitempty"`
	ExtraScopes    []string          `json:"extra_scopes,omitempty"`
	ExtraParams    map[string]string `json:"extra_params,omitempty"`
	Username       string            `json:"username,omitempty"`
	UseAccessToken bool              `json:"use_access_token,omitempty"`
	GrantType      string            `json:"grant_type,omitempty"` // "device-code", "authcode-browser", etc.
	RequestHeaders map[string]string `json:"request_headers,omitempty"`
	// COMPAT-CRIT-1: Some OIDC providers (Keycloak with strict redirect URI
	// validation) require redirect_uri on refresh token requests. Without this,
	// refresh fails with invalid_grant for users with --oidc-redirect-url.
	RedirectURL string `json:"redirect_url,omitempty"`
	// COMPAT-CRIT-3: ForceRefresh skips the token cache and performs an immediate
	// OIDC refresh. Maps from upstream kubelogin's --force-refresh flag.
	ForceRefresh bool `json:"force_refresh,omitempty"`

	// COMPAT-CRIT-2: TLS configuration for OIDC provider connections.
	// Required for token refresh when kubeconfig specifies custom CA certs,
	// skip-verify, or TLS renegotiation policy. Without this, the daemon's
	// OIDCRefresher uses a bare HTTP transport and TLS handshakes fail against
	// providers with custom/internal CAs.
	TLSConfig tlsclientconfig.Config `json:"tls_config"`

	// Fields for store-token command (shim sends freshly obtained tokens to daemon)
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// Response represents a JSON response from daemon to shim.
//
// SEC-1: The Token field contains the full JWT in plaintext. This is an accepted
// design decision consistent with all Unix credential helpers (ssh-agent sends
// raw keys, gpg-agent sends passphrases, Docker credential helpers send passwords).
// Root can intercept any Unix socket traffic (strace, recvmsg), but root can also
// read process memory, ptrace, and access any file — so encrypting IPC provides
// no additional security against a root attacker. Mitigations: socket 0600 perms,
// peer UID verification, runtime dir 0700, core dump disabled.
type Response struct {
	Version       int        `json:"version"`
	DaemonVersion int        `json:"daemon_version"`
	Status        string     `json:"status"` // "ok", "error", "needs-auth", "login-in-progress"
	Token         string     `json:"token,omitempty"`
	Expiry        time.Time  `json:"expiry,omitempty"`
	Error         string     `json:"error,omitempty"`
	ErrorCode     string     `json:"error_code,omitempty"` // structured error code
	Uptime        string     `json:"uptime,omitempty"`
	TokenExpiry   *time.Time `json:"token_expiry,omitempty"`

	// check command response fields
	Ready             *bool      `json:"ready,omitempty"`
	State             string     `json:"state,omitempty"` // AuthState string
	AccessTokenExpiry *time.Time `json:"access_token_expires,omitempty"`
	RefreshTokenValid *bool      `json:"refresh_token_valid,omitempty"`
	DaemonRunning     *bool      `json:"daemon_running,omitempty"`
	Message           string     `json:"message,omitempty"`
	Action            string     `json:"action,omitempty"`
	LoginStartedAt    *time.Time `json:"login_started_at,omitempty"`

	// refresh command response fields
	Refreshed *bool `json:"refreshed,omitempty"`

	// health command response fields (enhanced status)
	PID           int    `json:"pid,omitempty"`
	LogPath       string `json:"log_path,omitempty"`
	RuntimeDir    string `json:"runtime_dir,omitempty"`
	BinaryPath    string `json:"binary_path,omitempty"`
	TokenCount    int    `json:"token_count,omitempty"`
	UptimeSeconds int    `json:"uptime_seconds,omitempty"`
}

func errorResponse(msg string) Response {
	return Response{
		Version:       ProtocolVersion,
		DaemonVersion: ProtocolVersion,
		Status:        "error",
		Error:         msg,
	}
}

func errorCodeResponse(code, msg, action string) Response {
	return Response{
		Version:       ProtocolVersion,
		DaemonVersion: ProtocolVersion,
		Status:        "error",
		Error:         msg,
		ErrorCode:     code,
		Action:        action,
	}
}

func tokenResponse(token string, expiry time.Time) Response {
	return Response{
		Version:       ProtocolVersion,
		DaemonVersion: ProtocolVersion,
		Status:        "ok",
		Token:         token,
		Expiry:        expiry,
	}
}

func needsAuthResponse() Response {
	return Response{
		Version:       ProtocolVersion,
		DaemonVersion: ProtocolVersion,
		Status:        "needs-auth",
		ErrorCode:     ErrCodeNeedsLogin,
		Message:       "No valid token. Authentication required.",
		Action:        "Run 'kubelogin-daemon login' in a terminal",
	}
}
