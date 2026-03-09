package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/jwt"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/oidc"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/oidc/client/transport"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/tlsclientconfig"
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCRefresher implements Refresher using the standard OIDC refresh_token grant.
// A new http.Client is created on each refresh to handle VPN reconnect / DNS changes.
type OIDCRefresher struct {
	Provider    oidc.Provider
	TLSConfig   tlsclientconfig.Config // COMPAT-CRIT-2: custom CA/skip-verify/renegotiation
	ExtraParams map[string]string      // COMPAT-HIGH-1: extra token request params (e.g. audience)
	Logger      *Logger
}

// Refresh exchanges a refresh token for a new token set.
// Creates a new HTTP client and OIDC provider on each call to avoid stale connections.
func (r *OIDCRefresher) Refresh(ctx context.Context, refreshToken string) (idToken, newRefreshToken string, expiry time.Time, err error) {
	// COMPAT-CRIT-2: Build TLS config from the provider's TLS settings.
	// This handles custom CA certs, skip-verify, and renegotiation policy
	// that users may have set in their kubeconfig.
	tlsCfg, err := buildTLSConfig(r.TLSConfig)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("build TLS config: %w", err)
	}

	// SEC-HIGH-3: Warn when TLS verification is disabled. The login command warns on
	// stderr, but get-token (kubectl exec) is non-interactive and produces no output.
	// Log here so the daemon log captures the risk for post-mortem analysis.
	if r.TLSConfig.SkipTLSVerify {
		r.Logger.Warnf("TLS verification disabled for %s — refresh is MITM-vulnerable", r.Provider.IssuerURL)
	}

	// Create a fresh HTTP client for each refresh (handles VPN reconnect, DNS changes).
	// ROB-1: Close idle connections when done to prevent connection pool accumulation.
	// Without this, each refresh leaks an http.Transport with its own connection pool.
	// SEC-1: Filter request headers to block dangerous overrides (Authorization, Host, Cookie).
	safeHeaders := filterRequestHeaders(r.Provider.RequestHeaders, r.Logger)
	httpClient := &http.Client{
		Transport: &transport.WithHeader{
			Base: &http.Transport{
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: tlsCfg,
			},
			RequestHeaders: safeHeaders,
		},
		Timeout: 30 * time.Second,
	}
	defer httpClient.CloseIdleConnections()

	// Discover the OIDC provider (token endpoint, JWKS, etc.)
	// ROB-6: Use a separate 10s timeout for discovery so it can't consume
	// the entire 30s refresh budget. If discovery is slow, we still have
	// time left for the actual token exchange.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	discoveryCtx, discoveryCancel := context.WithTimeout(ctx, 10*time.Second)
	provider, err := gooidc.NewProvider(discoveryCtx, r.Provider.IssuerURL)
	discoveryCancel()
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("oidc discovery: %w", err)
	}

	endpoint := provider.Endpoint()
	if r.Provider.ClientSecret == "" {
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}

	// COMPAT-HIGH-1: Append extra params (e.g. audience) to the token endpoint URL.
	// Some providers (Auth0, Okta) require audience on refresh requests to issue
	// tokens with the correct audience claim. The oauth2 library's TokenSource
	// doesn't support extra body params on refresh, so we encode them as query
	// parameters on the TokenURL, which the library sends as POST form data.
	//
	// SEC-1: Block OAuth-critical parameters that could be injected via ExtraParams
	// to override the daemon's intended token request semantics (scope escalation,
	// client identity spoofing, redirect hijacking). ExtraParams come from kubeconfig
	// exec args (user-controlled) and are forwarded unvalidated through the IPC socket.
	if len(r.ExtraParams) > 0 {
		u, parseErr := url.Parse(endpoint.TokenURL)
		if parseErr == nil {
			q := u.Query()
			for k, v := range r.ExtraParams {
				if isBlockedOAuthParam(k) {
					r.Logger.Warnf("blocked dangerous extra param %q (would override OAuth protocol field)", k)
					continue
				}
				q.Set(k, v)
			}
			u.RawQuery = q.Encode()
			endpoint.TokenURL = u.String()
		}
	}

	// COMPAT-LOW-1: Copy the slice before appending to avoid mutating
	// r.Provider.ExtraScopes if its backing array has spare capacity.
	scopes := make([]string, len(r.Provider.ExtraScopes)+1)
	copy(scopes, r.Provider.ExtraScopes)
	scopes[len(r.Provider.ExtraScopes)] = gooidc.ScopeOpenID

	oauth2Config := oauth2.Config{
		Endpoint:     endpoint,
		ClientID:     r.Provider.ClientID,
		ClientSecret: r.Provider.ClientSecret,
		RedirectURL:  r.Provider.RedirectURL, // COMPAT-CRIT-1: Keycloak requires redirect_uri on refresh
		Scopes:       scopes,
	}

	// Exchange the refresh token
	currentToken := &oauth2.Token{
		Expiry:       time.Now(), // force refresh
		RefreshToken: refreshToken,
	}
	source := oauth2Config.TokenSource(ctx, currentToken)
	token, err := source.Token()
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("refresh token exchange: %w", err)
	}

	// Extract the token to use (ID token or access token)
	var resultToken string
	if r.Provider.UseAccessToken {
		accessToken, ok := token.Extra("access_token").(string)
		if !ok {
			return "", "", time.Time{}, fmt.Errorf("access_token missing in response")
		}
		// Verify the access token
		verifier := provider.Verifier(&gooidc.Config{
			ClientID:          "",
			SkipClientIDCheck: true,
		})
		if _, err := verifier.Verify(ctx, accessToken); err != nil {
			return "", "", time.Time{}, fmt.Errorf("verify access token: %w", err)
		}
		resultToken = accessToken
	} else {
		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			return "", "", time.Time{}, fmt.Errorf("id_token missing in response")
		}
		// Verify the ID token
		verifier := provider.Verifier(&gooidc.Config{ClientID: r.Provider.ClientID})
		if _, err := verifier.Verify(ctx, rawIDToken); err != nil {
			return "", "", time.Time{}, fmt.Errorf("verify id token: %w", err)
		}
		resultToken = rawIDToken
	}

	// Parse expiry from the JWT
	claims, err := jwt.DecodeWithoutVerify(resultToken)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("decode token claims: %w", err)
	}

	// Preserve the old refresh token if the provider didn't return a new one.
	// Some providers (e.g., CILogon) don't always include refresh_token in
	// refresh responses. Without this, an empty string would overwrite the
	// valid refresh token, causing the next refresh to fail.
	newRT := token.RefreshToken
	if newRT == "" {
		newRT = refreshToken // keep the old one
	}

	return resultToken, newRT, claims.Expiry, nil
}

// blockedOAuthParams are OAuth2/OIDC protocol parameters that must not be
// overridden by user-provided ExtraParams. Allowing these would enable:
//   - scope: escalate scopes beyond what was configured
//   - client_id/client_secret: impersonate a different client
//   - redirect_uri: redirect tokens to an attacker-controlled endpoint
//   - grant_type: change the token exchange semantics
//   - code/code_verifier: interfere with PKCE or authcode exchange
//   - refresh_token: substitute a different refresh token
//
// These params are set by the oauth2 library from oauth2.Config fields;
// allowing overrides via query params would silently replace them.
var blockedOAuthParams = map[string]bool{
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

func isBlockedOAuthParam(key string) bool {
	// HIGH-3: OAuth2 param names are case-sensitive per RFC 6749, but some
	// providers accept them case-insensitively. Normalize for defense-in-depth.
	return blockedOAuthParams[strings.ToLower(key)]
}

// blockedRequestHeaders are HTTP headers that must not be overridden by
// user-provided RequestHeaders. Allowing these would enable:
//   - Authorization: inject credentials for a different identity
//   - Host: redirect requests to a different server (virtual host routing)
//   - Cookie: inject session cookies
var blockedRequestHeaders = map[string]bool{
	"authorization": true,
	"host":          true,
	"cookie":        true,
}

func isBlockedRequestHeader(key string) bool {
	// HTTP headers are case-insensitive; normalize to lowercase for comparison.
	lower := strings.ToLower(key)
	return blockedRequestHeaders[lower]
}

// filterRequestHeaders returns a copy of headers with blocked entries removed.
func filterRequestHeaders(headers map[string]string, logger *Logger) map[string]string {
	if len(headers) == 0 {
		return headers
	}
	filtered := make(map[string]string, len(headers))
	for k, v := range headers {
		if isBlockedRequestHeader(k) {
			logger.Warnf("blocked dangerous request header %q (would override HTTP protocol field)", k)
			continue
		}
		filtered[k] = v
	}
	return filtered
}

// buildTLSConfig creates a *tls.Config from the tlsclientconfig.Config.
// Returns nil if no custom TLS configuration is needed (use Go defaults).
func buildTLSConfig(cfg tlsclientconfig.Config) (*tls.Config, error) {
	if len(cfg.CACertFilename) == 0 && len(cfg.CACertData) == 0 &&
		!cfg.SkipTLSVerify && cfg.Renegotiation == 0 {
		return nil, nil
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.SkipTLSVerify,
		Renegotiation:      cfg.Renegotiation,
	}

	if len(cfg.CACertFilename) > 0 || len(cfg.CACertData) > 0 {
		pool := x509.NewCertPool()
		for _, filename := range cfg.CACertFilename {
			data, err := os.ReadFile(filename)
			if err != nil {
				return nil, fmt.Errorf("read CA cert %s: %w", filename, err)
			}
			if !pool.AppendCertsFromPEM(data) {
				return nil, fmt.Errorf("no valid certificates in %s", filename)
			}
		}
		// CRIT-1: CACertData arrives as base64-encoded PEM (from kubeconfig's
		// certificate-authority-data field). Must decode before AppendCertsFromPEM,
		// which expects raw PEM with -----BEGIN CERTIFICATE----- headers.
		// The login path (loader/load.go:63) correctly decodes; this path did not.
		for _, data := range cfg.CACertData {
			decoded, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				return nil, fmt.Errorf("decode base64 CA data: %w", err)
			}
			if !pool.AppendCertsFromPEM(decoded) {
				return nil, fmt.Errorf("no valid certificates in inline CA data")
			}
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}
