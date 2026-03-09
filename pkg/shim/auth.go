package shim

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/infrastructure/browser"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/infrastructure/clock"
	infralogger "github.com/ZihaoZhou/kubelogin-daemon/pkg/infrastructure/logger"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/oidc"
	oidcclient "github.com/ZihaoZhou/kubelogin-daemon/pkg/oidc/client"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/tlsclientconfig"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/tlsclientconfig/loader"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/usecases/authentication/authcode"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/usecases/authentication/devicecode"
	"github.com/spf13/pflag"
)

// AuthOptions carries upstream-compatible authentication options.
// These mirror the flags from upstream kubelogin's authentication.go.
type AuthOptions struct {
	SkipOpenBrowser            bool
	AuthenticationTimeout      int // seconds, 0 = default (180s)
	ListenAddress              []string
	BrowserCommand             string
	LocalServerCertFile        string
	LocalServerKeyFile         string
	OpenURLAfterAuthentication string
	AuthRequestExtraParams     map[string]string
	// COMPAT-5: TLS config for OIDC provider connections during login.
	// Passed through to the OIDC client factory so custom CAs, skip-verify,
	// and renegotiation policy are honored during initial authentication.
	TLSConfig tlsclientconfig.Config
}

// PerformAuth performs the initial OIDC authentication flow in the foreground.
// The user interaction (browser/device-code prompt) happens via stderr.
// Returns the obtained TokenSet.
func PerformAuth(ctx context.Context, provider oidc.Provider, grantType string, opts ...AuthOptions) (*oidc.TokenSet, error) {
	var opt AuthOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	// SEC-CRIT-2: Filter dangerous request headers before passing to OIDC client.
	// The daemon's refresh path (refresher.go) has filterRequestHeaders, but the
	// login path through factory.go was unfiltered. A poisoned kubeconfig with
	// Authorization=xxx would override the oauth2 library's client authentication.
	provider.RequestHeaders = filterBlockedRequestHeaders(provider.RequestHeaders)

	factory := &oidcclient.Factory{
		Loader: loader.Loader{},
		Clock:  &clock.Real{},
		Logger: &stderrLogger{},
	}

	// COMPAT-5: Pass the caller's TLS config instead of empty config.
	// Without this, login against providers with custom CAs or skip-verify
	// fails with TLS handshake errors.
	oidcClient, err := factory.New(ctx, provider, opt.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("create OIDC client: %w", err)
	}

	switch grantType {
	case "device-code":
		return doDeviceCode(ctx, oidcClient, opt)
	case "authcode-browser":
		return doAuthCodeBrowser(ctx, oidcClient, opt)
	default:
		return nil, fmt.Errorf("unsupported grant type for initial auth: %s", grantType)
	}
}

func doDeviceCode(ctx context.Context, oidcClient oidcclient.Interface, opts AuthOptions) (*oidc.TokenSet, error) {
	dc := &devicecode.DeviceCode{
		Browser: &browser.Browser{},
		Logger:  &stderrLogger{},
	}
	dcOpt := &devicecode.Option{
		SkipOpenBrowser: opts.SkipOpenBrowser,
		BrowserCommand:  opts.BrowserCommand,
	}
	return dc.Do(ctx, dcOpt, oidcClient)
}

func doAuthCodeBrowser(ctx context.Context, oidcClient oidcclient.Interface, opts AuthOptions) (*oidc.TokenSet, error) {
	ab := &authcode.Browser{
		Browser: &browser.Browser{},
		Logger:  &stderrLogger{},
	}

	timeout := 180 * time.Second
	if opts.AuthenticationTimeout > 0 {
		timeout = time.Duration(opts.AuthenticationTimeout) * time.Second
	}

	bindAddr := []string{"127.0.0.1:8000", "127.0.0.1:18000"}
	if len(opts.ListenAddress) > 0 {
		bindAddr = opts.ListenAddress
	}

	browserOpt := &authcode.BrowserOption{
		SkipOpenBrowser:            opts.SkipOpenBrowser,
		BrowserCommand:             opts.BrowserCommand,
		BindAddress:                bindAddr,
		AuthenticationTimeout:      timeout,
		LocalServerCertFile:        opts.LocalServerCertFile,
		LocalServerKeyFile:         opts.LocalServerKeyFile,
		OpenURLAfterAuthentication: opts.OpenURLAfterAuthentication,
		AuthRequestExtraParams:     filterBlockedOAuthParams(opts.AuthRequestExtraParams),
	}
	return ab.Do(ctx, browserOpt, oidcClient)
}

// blockedAuthCodeParams mirrors the blocklist in pkg/daemon/refresher.go.
// These OAuth2/OIDC protocol parameters must not be overridden by user-provided
// ExtraParams. On the authorization endpoint, the most dangerous injection is
// redirect_uri (redirects the authorization code to an attacker-controlled URL).
var blockedAuthCodeParams = map[string]bool{
	"scope":         true,
	"client_id":     true,
	"client_secret": true,
	"redirect_uri":  true,
	"grant_type":    true,
	"code":          true,
	"code_verifier": true,
	"refresh_token": true,
	"response_type": true,
}

// filterBlockedOAuthParams returns a copy of extraParams with blocked keys removed.
func filterBlockedOAuthParams(extraParams map[string]string) map[string]string {
	if len(extraParams) == 0 {
		return extraParams
	}
	filtered := make(map[string]string, len(extraParams))
	for k, v := range extraParams {
		if blockedAuthCodeParams[strings.ToLower(k)] {
			fmt.Fprintf(os.Stderr, "[KUBELOGIN] WARNING: blocked dangerous extra param %q (would override OAuth protocol field)\n", k)
			continue
		}
		filtered[k] = v
	}
	return filtered
}

// blockedHeaders mirrors the blocklist in pkg/daemon/refresher.go.
// HTTP headers that must not be overridden by user-provided RequestHeaders.
var blockedHeaders = map[string]bool{
	"authorization": true,
	"host":          true,
	"cookie":        true,
}

// filterBlockedRequestHeaders returns a copy of headers with blocked entries removed.
func filterBlockedRequestHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return headers
	}
	filtered := make(map[string]string, len(headers))
	for k, v := range headers {
		if blockedHeaders[strings.ToLower(k)] {
			fmt.Fprintf(os.Stderr, "[KUBELOGIN] WARNING: blocked dangerous request header %q (would override HTTP protocol field)\n", k)
			continue
		}
		filtered[k] = v
	}
	return filtered
}

// stderrLogger implements logger.Interface, writing to stderr
// so it doesn't pollute the ExecCredential JSON on stdout.
type stderrLogger struct{}

var _ infralogger.Interface = &stderrLogger{}

func (*stderrLogger) AddFlags(f *pflag.FlagSet) {}

func (*stderrLogger) Printf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func (*stderrLogger) V(level int) infralogger.Verbose {
	if level <= 0 {
		return &verboseLogger{}
	}
	return &silentLogger{}
}

func (*stderrLogger) IsEnabled(level int) bool {
	return level <= 0
}

// verboseLogger prints to stderr.
type verboseLogger struct{}

func (*verboseLogger) Infof(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// silentLogger discards output.
type silentLogger struct{}

func (*silentLogger) Infof(format string, args ...interface{}) {}
