// Package client provides a client of OpenID Connect.
package client

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/wire"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/infrastructure/clock"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/infrastructure/logger"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/oidc"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/oidc/client/transport"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/pkce"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/tlsclientconfig"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/tlsclientconfig/loader"
	"golang.org/x/oauth2"
)

var Set = wire.NewSet(
	wire.Struct(new(Factory), "*"),
	wire.Bind(new(FactoryInterface), new(*Factory)),
)

type FactoryInterface interface {
	New(ctx context.Context, prov oidc.Provider, tlsClientConfig tlsclientconfig.Config) (Interface, error)
}

type Factory struct {
	Loader loader.Loader
	Clock  clock.Interface
	Logger logger.Interface
}

// New returns an instance of infrastructure.Interface with the given configuration.
func (f *Factory) New(ctx context.Context, prov oidc.Provider, tlsClientConfig tlsclientconfig.Config) (Interface, error) {
	rawTLSClientConfig, err := f.Loader.Load(tlsClientConfig)
	if err != nil {
		return nil, fmt.Errorf("could not load the TLS client config: %w", err)
	}
	httpClient := &http.Client{
		Transport: &transport.WithHeader{
			Base: &transport.WithLogging{
				Base: &http.Transport{
					TLSClientConfig: rawTLSClientConfig,
					Proxy:           http.ProxyFromEnvironment,
				},
				Logger: f.Logger,
			},
			RequestHeaders: prov.RequestHeaders,
		},
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	provider, err := gooidc.NewProvider(ctx, prov.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery error: %w", err)
	}
	supportedPKCEMethods, err := extractSupportedPKCEMethods(provider)
	if err != nil {
		return nil, fmt.Errorf("could not determine supported PKCE methods: %w", err)
	}

	endpoint := provider.Endpoint()
	if prov.ClientSecret == "" {
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}

	// SEC-CRIT-1: Copy the slice before appending to avoid mutating
	// prov.ExtraScopes if its backing array has spare capacity.
	// Same pattern as refresher.go (COMPAT-LOW-1).
	scopes := make([]string, len(prov.ExtraScopes)+1)
	copy(scopes, prov.ExtraScopes)
	scopes[len(prov.ExtraScopes)] = gooidc.ScopeOpenID

	return &client{
		httpClient: httpClient,
		provider:   provider,
		oauth2Config: oauth2.Config{
			Endpoint:     endpoint,
			ClientID:     prov.ClientID,
			ClientSecret: prov.ClientSecret,
			RedirectURL:  prov.RedirectURL,
			Scopes:       scopes,
		},
		clock:                f.Clock,
		logger:               f.Logger,
		negotiatedPKCEMethod: determinePKCEMethod(supportedPKCEMethods, prov.PKCEMethod),
		useAccessToken:       prov.UseAccessToken,
	}, nil
}

func determinePKCEMethod(supportedMethods []string, preferredMethod oidc.PKCEMethod) pkce.Method {
	switch preferredMethod {
	case oidc.PKCEMethodNo:
		return pkce.NoMethod
	case oidc.PKCEMethodS256:
		return pkce.MethodS256
	default:
		if slices.Contains(supportedMethods, "S256") {
			return pkce.MethodS256
		}
		return pkce.NoMethod
	}
}

func extractSupportedPKCEMethods(provider *gooidc.Provider) ([]string, error) {
	var claims struct {
		CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	}
	if err := provider.Claims(&claims); err != nil {
		return nil, fmt.Errorf("invalid discovery document: %w", err)
	}
	return claims.CodeChallengeMethodsSupported, nil
}
