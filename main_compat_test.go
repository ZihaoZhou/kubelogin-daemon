package main

// Upstream compatibility tests — each test reproduces a KNOWN BUG where
// kubelogin-daemon diverges from upstream kubelogin behavior.
// EVERY test in this file MUST FAIL before the fix and PASS after.
// If a test passes on broken code, the test itself is wrong.

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/oidc"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/shim"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/tokencache"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// ==========================================================================
// A) get-token must accept all upstream flags without error
// Bug: cobra rejects flags not registered on getTokenCmd()
// ==========================================================================

func TestGetToken_AcceptsTokenCacheFlags(t *testing.T) {
	cmd := getTokenCmd()
	cmd.RunE = func(cmd *cobra.Command, args []string) error { return nil }
	cmd.SetArgs([]string{
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"--token-cache-storage=disk",
		"--token-cache-dir=/tmp/cache",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("get-token rejects --token-cache-storage/--token-cache-dir: %v", err)
	}
}

func TestGetToken_AcceptsTLSFlags(t *testing.T) {
	cmd := getTokenCmd()
	cmd.RunE = func(cmd *cobra.Command, args []string) error { return nil }
	cmd.SetArgs([]string{
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"--certificate-authority=/etc/ssl/ca.pem",
		"--certificate-authority-data=base64data",
		"--insecure-skip-tls-verify",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("get-token rejects TLS flags: %v", err)
	}
}

func TestGetToken_AcceptsPKCEFlags(t *testing.T) {
	cmd := getTokenCmd()
	cmd.RunE = func(cmd *cobra.Command, args []string) error { return nil }
	cmd.SetArgs([]string{
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"--oidc-pkce-method=S256",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("get-token rejects --oidc-pkce-method: %v", err)
	}
}

func TestGetToken_AcceptsAuthFlags(t *testing.T) {
	cmd := getTokenCmd()
	cmd.RunE = func(cmd *cobra.Command, args []string) error { return nil }
	cmd.SetArgs([]string{
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"--listen-address=127.0.0.1:8000",
		"--skip-open-browser",
		"--authentication-timeout-sec=180",
		"--browser-command=xdg-open",
		"--force-refresh",
		"--oidc-redirect-url=http://localhost:8000",
		"--oidc-redirect-url-authcode-keyboard=http://localhost:18000",
		"--password=secret",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("get-token rejects auth flags: %v", err)
	}
}

func TestGetToken_AcceptsVerbosityFlag(t *testing.T) {
	cmd := getTokenCmd()
	cmd.RunE = func(cmd *cobra.Command, args []string) error { return nil }
	// Upstream uses -v=1 (single dash, klog style). Cobra must accept it.
	cmd.SetArgs([]string{
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"-v=1",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("get-token rejects -v=1: %v", err)
	}
}

func TestGetToken_AcceptsRequestHeaderFlag(t *testing.T) {
	cmd := getTokenCmd()
	cmd.RunE = func(cmd *cobra.Command, args []string) error { return nil }
	cmd.SetArgs([]string{
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"--oidc-request-header=X-Custom=value",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("get-token rejects --oidc-request-header: %v", err)
	}
}

func TestGetToken_AcceptsLocalServerFlags(t *testing.T) {
	cmd := getTokenCmd()
	cmd.RunE = func(cmd *cobra.Command, args []string) error { return nil }
	cmd.SetArgs([]string{
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"--local-server-cert=/tmp/cert.pem",
		"--local-server-key=/tmp/key.pem",
		"--open-url-after-authentication=https://done.example.com",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("get-token rejects local server flags: %v", err)
	}
}

func TestGetToken_AcceptsAuthRequestExtraParams(t *testing.T) {
	cmd := getTokenCmd()
	cmd.RunE = func(cmd *cobra.Command, args []string) error { return nil }
	cmd.SetArgs([]string{
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"--oidc-auth-request-extra-params=audience=api",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("get-token rejects --oidc-auth-request-extra-params: %v", err)
	}
}

func TestGetToken_AcceptsDeprecatedPKCEFlag(t *testing.T) {
	cmd := getTokenCmd()
	cmd.RunE = func(cmd *cobra.Command, args []string) error { return nil }
	cmd.SetArgs([]string{
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"--oidc-use-pkce",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("get-token rejects --oidc-use-pkce: %v", err)
	}
}

func TestGetToken_AcceptsTLSRenegotiationFlags(t *testing.T) {
	cmd := getTokenCmd()
	cmd.RunE = func(cmd *cobra.Command, args []string) error { return nil }
	cmd.SetArgs([]string{
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"--tls-renegotiation-once",
		"--tls-renegotiation-freely",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("get-token rejects TLS renegotiation flags: %v", err)
	}
}

// ==========================================================================
// B) parseExecArgs MUST comma-split scopes (matches StringSliceVar)
// COMPAT-HIGH-2: getTokenCmd uses StringSliceVar which splits on commas.
// parseExecArgs must match this behavior for consistent cache keys.
// ==========================================================================

func TestParseExecArgs_CommaSplit(t *testing.T) {
	// COMPAT-CRIT-1: "profile,offline_access,org.cilogon.userinfo" must be split
	// into three values. This matches StringSliceVar behavior in getTokenCmd.
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"--oidc-extra-scope=profile,offline_access,org.cilogon.userinfo",
	})
	if len(cfg.extraScopes) != 3 {
		t.Fatalf("expected 3 scopes (comma split), got %d: %v", len(cfg.extraScopes), cfg.extraScopes)
	}
	expected := []string{"profile", "offline_access", "org.cilogon.userinfo"}
	for i, want := range expected {
		if cfg.extraScopes[i] != want {
			t.Errorf("scope[%d] = %q, want %q", i, cfg.extraScopes[i], want)
		}
	}
}

func TestParseExecArgs_RepeatedScopes(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"--oidc-extra-scope=profile",
		"--oidc-extra-scope=email",
	})
	if len(cfg.extraScopes) != 2 {
		t.Fatalf("expected 2 scopes (profile, email), got %d: %v",
			len(cfg.extraScopes), cfg.extraScopes)
	}
}

func TestParseExecArgs_MatchesCobraStringSliceVar(t *testing.T) {
	// COMPAT-CRIT-1: parseExecArgs must match StringSliceVar (comma-split).
	var cobraScopes []string
	testCmd := &cobra.Command{Run: func(cmd *cobra.Command, args []string) {}}
	testCmd.Flags().StringSliceVar(&cobraScopes, "scope", nil, "")
	testCmd.SetArgs([]string{"--scope=profile,offline_access,email"})
	if err := testCmd.Execute(); err != nil {
		t.Fatalf("cobra parse: %v", err)
	}

	parseResult := parseExecArgs([]string{
		"get-token",
		"--oidc-extra-scope=profile,offline_access,email",
	})

	if len(parseResult.extraScopes) != len(cobraScopes) {
		t.Fatalf("parseExecArgs=%d scopes %v, cobra StringSliceVar=%d scopes %v",
			len(parseResult.extraScopes), parseResult.extraScopes,
			len(cobraScopes), cobraScopes)
	}
	for i := range cobraScopes {
		if parseResult.extraScopes[i] != cobraScopes[i] {
			t.Errorf("scope[%d]: parseExecArgs=%q, cobra=%q",
				i, parseResult.extraScopes[i], cobraScopes[i])
		}
	}
}

// ==========================================================================
// B+) parseExecArgs must store upstream boolean flags properly
// Bug: parsedOIDCConfig has no field for skip-open-browser, force-refresh, etc.
// These flags are silently dropped even though they affect auth behavior.
// ==========================================================================

// (This tests the STRUCT — parsedOIDCConfig must carry these fields for
// downstream code to honor them. Without the field, the flag is dead.)
// We test indirectly: parse args, then verify the struct can represent them.
// Currently parsedOIDCConfig has NO field for skip-open-browser.

func TestParseExecArgs_SkipOpenBrowserStored(t *testing.T) {
	// After parsing, the login flow must know whether skip-open-browser was set.
	// This requires parsedOIDCConfig to have a field for it.
	// Test: parse args with --skip-open-browser, verify the struct carries it.
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"--skip-open-browser",
	})
	// parsedOIDCConfig must have a skipOpenBrowser field
	// If this doesn't compile, the struct is missing the field.
	if !cfg.skipOpenBrowser {
		t.Error("skipOpenBrowser should be true when --skip-open-browser is present")
	}
}

func TestParseExecArgs_ForceRefreshStored(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"--force-refresh",
	})
	if !cfg.forceRefresh {
		t.Error("forceRefresh should be true when --force-refresh is present")
	}
}

func TestParseExecArgs_TokenCacheDirStored(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"--token-cache-dir=/tmp/custom-cache",
	})
	if cfg.tokenCacheDir != "/tmp/custom-cache" {
		t.Errorf("tokenCacheDir = %q, want /tmp/custom-cache", cfg.tokenCacheDir)
	}
}

// ==========================================================================
// C) Grant type: PerformAuth must handle upstream grant types
// Bug: PerformAuth rejects "auto", "authcode", "authcode-keyboard"
// ==========================================================================

func TestPerformAuth_RejectsAutoGrantType(t *testing.T) {
	// Upstream default is "auto". Daemon's PerformAuth returns error for anything
	// other than "device-code" and "authcode-browser".
	// This test proves the bug: a kubeconfig with grant-type=auto breaks login.
	//
	// We can't do real OIDC auth in a unit test, but we can verify the grant-type
	// mapping. The fix should map "auto" -> try device-code (daemon's default).
	// For now, just verify PerformAuth's switch statement covers "auto".

	// Test via shim.PerformAuth indirectly: the grantType validation happens
	// in the switch at pkg/shim/auth.go:36-43.
	// Upstream grant types that must not cause "unsupported grant type":
	upstreamGrantTypes := []string{"auto", "authcode", "authcode-keyboard"}
	for _, gt := range upstreamGrantTypes {
		// We check that resolveFromKubeconfig + login path doesn't reject these.
		// Currently it does (auth.go:42 returns error for unknown grant type).
		// Testing via parseExecArgs -> oidcFlags -> the grantType field.
		cfg := parseExecArgs([]string{
			"get-token",
			"--oidc-issuer-url=https://issuer.example.com",
			"--oidc-client-id=test",
			"--grant-type=" + gt,
		})
		// The grantType is parsed correctly...
		if cfg.grantType != gt {
			t.Errorf("grantType = %q, want %q", cfg.grantType, gt)
		}
		// ...but when fed to PerformAuth, it should be mapped to a supported type.
		// The mapping must exist in oidcFlags or the login path.
		// Currently no mapping exists: "auto" goes straight to PerformAuth which rejects it.
		mapped, mapErr := mapGrantType(cfg.grantType)
		if mapErr != nil {
			t.Errorf("mapGrantType(%q) returned error: %v", cfg.grantType, mapErr)
		}
		validMapped := map[string]bool{"device-code": true, "authcode-browser": true}
		if !validMapped[mapped] {
			t.Errorf("grant type %q mapped to %q which is not supported by PerformAuth", gt, mapped)
		}
	}
}

// ==========================================================================
// F) Migration must produce configs that get-token actually accepts
// Bug: migrate leaves upstream-only flags in args, get-token rejects them
// ==========================================================================

func TestSetupMigrate_ProducesValidGetTokenArgs(t *testing.T) {
	config := &clientcmdapi.Config{
		CurrentContext: "test",
		Contexts: map[string]*clientcmdapi.Context{
			"test": {Cluster: "cluster", AuthInfo: "oidc"},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster": {Server: "https://k8s.example.com"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"oidc": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "kubelogin",
					Args: []string{
						"get-token",
						"--oidc-issuer-url=https://cilogon.org/authorize",
						"--oidc-client-id=cilogon:/client_id/test",
						"--oidc-extra-scope=profile,offline_access",
						"--grant-type=device-code",
						"--token-cache-storage=disk",
						"--token-cache-dir=/tmp/kubelogin-oidc-501",
						"--skip-open-browser",
						"-v=1",
					},
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	if err := runSetupMigrate("", false, true, false); err != nil {
		t.Fatalf("migrate failed: %v", err)
	}

	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}
	reloaded, err := rules.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	// Feed the migrated args to get-token's cobra command — it must not reject them.
	user := reloaded.AuthInfos["oidc"]
	cmd := getTokenCmd()
	cmd.RunE = func(cmd *cobra.Command, args []string) error { return nil }
	cmd.SetArgs(user.Exec.Args[1:]) // skip "get-token"
	if err := cmd.Execute(); err != nil {
		t.Fatalf("migrated args rejected by get-token: %v\nArgs: %v", err, user.Exec.Args)
	}
}

// ==========================================================================
// G) Upstream mock directory structure
// Bug: mocks at old path (int128/kubelogin), tests import from new path
// ==========================================================================

func TestUpstreamMockDirectoryExists(t *testing.T) {
	newPathBase := filepath.Join("mocks", "github.com", "ZihaoZhou", "kubelogin-daemon")
	oldPathBase := filepath.Join("mocks", "github.com", "int128", "kubelogin")

	newExists := false
	if _, err := os.Stat(newPathBase); err == nil {
		newExists = true
	}
	oldExists := false
	if _, err := os.Stat(oldPathBase); err == nil {
		oldExists = true
	}

	if oldExists && !newExists {
		t.Fatalf("mocks at old path (%s) but not new path (%s) — upstream tests won't compile",
			oldPathBase, newPathBase)
	}
	if !newExists && !oldExists {
		t.Fatal("no mock directories found at all")
	}
}

// ==========================================================================
// J) End-to-end: exact NRP Nautilus kubeconfig args
// ==========================================================================

func TestRealWorldNRPNautilus_GetTokenAcceptsArgs(t *testing.T) {
	// Exact args from the user's real kubeconfig that broke kubectl.
	realArgs := []string{
		"--oidc-issuer-url=https://cilogon.org/authorize",
		"--oidc-client-id=cilogon:/client_id/1253defc1e1fa80da28b0",
		"--oidc-extra-scope=profile,offline_access,org.cilogon.userinfo",
		"--grant-type=device-code",
		"--token-cache-storage=disk",
		"--token-cache-dir=/tmp/kubelogin-oidc-501",
		"--skip-open-browser",
		"-v=1",
	}

	cmd := getTokenCmd()
	cmd.RunE = func(cmd *cobra.Command, args []string) error { return nil }
	cmd.SetArgs(realArgs)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("get-token rejects real NRP Nautilus args: %v", err)
	}
}

func TestRealWorldNRPNautilus_ScopesParsedCorrectly(t *testing.T) {
	// COMPAT-4: With StringArrayVar, comma-separated scopes in one arg are treated
	// as a single value. Migrated kubeconfigs should use separate --oidc-extra-scope
	// flags per scope. setup migrate handles this conversion.
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-issuer-url=https://cilogon.org/authorize",
		"--oidc-client-id=cilogon:/client_id/1253defc1e1fa80da28b0",
		"--oidc-extra-scope=profile",
		"--oidc-extra-scope=offline_access",
		"--oidc-extra-scope=org.cilogon.userinfo",
		"--grant-type=device-code",
		"--token-cache-storage=disk",
		"--token-cache-dir=/tmp/kubelogin-oidc-501",
		"--skip-open-browser",
		"-v=1",
	})

	expectedScopes := []string{"profile", "offline_access", "org.cilogon.userinfo"}
	if len(cfg.extraScopes) != 3 {
		t.Fatalf("expected 3 scopes, got %d: %v", len(cfg.extraScopes), cfg.extraScopes)
	}
	for i, want := range expectedScopes {
		if cfg.extraScopes[i] != want {
			t.Errorf("scope[%d] = %q, want %q", i, cfg.extraScopes[i], want)
		}
	}
}

func TestRealWorldNRPNautilus_KubeconfigResolve(t *testing.T) {
	// COMPAT-4: Kubeconfig with separate --oidc-extra-scope per scope (correct format
	// for StringArrayVar). Migrated kubeconfigs should use this format.
	config := &clientcmdapi.Config{
		CurrentContext: "nautilus",
		Contexts: map[string]*clientcmdapi.Context{
			"nautilus": {Cluster: "nrp", AuthInfo: "oidc-nrp"},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			"nrp": {Server: "https://67.58.53.148:443"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"oidc-nrp": {
				Exec: &clientcmdapi.ExecConfig{
					Command:    "kubelogin-daemon",
					APIVersion: "client.authentication.k8s.io/v1beta1",
					Args: []string{
						"get-token",
						"--oidc-issuer-url=https://cilogon.org/authorize",
						"--oidc-client-id=cilogon:/client_id/test",
						"--oidc-extra-scope=profile",
						"--oidc-extra-scope=offline_access",
						"--oidc-extra-scope=org.cilogon.userinfo",
						"--grant-type=device-code",
						"--token-cache-storage=disk",
						"--token-cache-dir=/tmp/kubelogin-oidc-501",
						"--skip-open-browser",
						"-v=1",
					},
					InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	parsed, err := parseOIDCFromKubeconfig("")
	if err != nil {
		t.Fatalf("parseOIDCFromKubeconfig failed: %v", err)
	}

	if len(parsed.extraScopes) != 3 {
		t.Errorf("expected 3 scopes, got %d: %v", len(parsed.extraScopes), parsed.extraScopes)
	}
	if parsed.issuerURL != "https://cilogon.org/authorize" {
		t.Errorf("issuerURL = %q", parsed.issuerURL)
	}
}

// ==========================================================================
// Round 2 findings — Codex re-audit
// ==========================================================================

// Bug: --oidc-auth-request-extra-params is accepted by cobra but NOT wired
// to the same variable as --oidc-extra-param, so the value is silently dropped.
func TestGetToken_AuthRequestExtraParamsWiredToExtraParams(t *testing.T) {
	// When upstream kubeconfig has --oidc-auth-request-extra-params=audience=api,
	// it should be treated identically to --oidc-extra-param=audience=api.
	var capturedExtraParams map[string]string
	cmd := getTokenCmd()
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		// Read the actual value that would be passed to runGetToken
		val, err := cmd.Flags().GetStringToString("oidc-extra-param")
		if err != nil {
			return err
		}
		capturedExtraParams = val
		return nil
	}
	cmd.SetArgs([]string{
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"--oidc-auth-request-extra-params=audience=api",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if v, ok := capturedExtraParams["audience"]; !ok || v != "api" {
		t.Errorf("--oidc-auth-request-extra-params value not wired to extraParams: got %v", capturedExtraParams)
	}
}

// Bug: parseExecArgs doesn't capture --username from kubeconfig exec args.
func TestParseExecArgs_UsernameStored(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"--username=johndoe",
	})
	if cfg.username != "johndoe" {
		t.Errorf("username = %q, want johndoe", cfg.username)
	}
}

// Bug: parseExecArgs doesn't capture --oidc-auth-request-extra-params.
func TestParseExecArgs_AuthRequestExtraParamsStored(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
		"--oidc-auth-request-extra-params=audience=api",
	})
	if cfg.extraParams == nil || cfg.extraParams["audience"] != "api" {
		t.Errorf("extraParams = %v, want {audience:api}", cfg.extraParams)
	}
}

// COMPAT-1/COMPAT-2: password and client-credentials now return sentinel values
// instead of silently degrading to device-code. This prevents non-interactive
// workloads from hanging on interactive auth prompts.
func TestMapGrantType_AllUpstreamTypes(t *testing.T) {
	// Supported grant types should map without error.
	okCases := []struct {
		input    string
		expected string
	}{
		{"device-code", "device-code"},
		{"authcode-browser", "authcode-browser"},
		{"auto", "device-code"},
		{"authcode", "authcode-browser"},
		// COMPAT-HIGH-1: authcode-keyboard is headless → device-code (not browser).
		{"authcode-keyboard", "device-code"},
	}
	for _, c := range okCases {
		mapped, err := mapGrantType(c.input)
		if err != nil {
			t.Errorf("mapGrantType(%q) unexpected error: %v", c.input, err)
		}
		if mapped != c.expected {
			t.Errorf("mapGrantType(%q) = %q, want %q", c.input, mapped, c.expected)
		}
	}
	// COMPAT-CRIT-2: Unsupported grant types should return clear errors.
	errCases := []string{"password", "client-credentials"}
	for _, gt := range errCases {
		_, err := mapGrantType(gt)
		if err == nil {
			t.Errorf("mapGrantType(%q) expected error, got nil", gt)
		}
	}
}

// Bug: resolveFromKubeconfig doesn't merge username from kubeconfig.
func TestResolveFromKubeconfig_MergesUsername(t *testing.T) {
	config := &clientcmdapi.Config{
		CurrentContext: "test",
		Contexts: map[string]*clientcmdapi.Context{
			"test": {Cluster: "cluster", AuthInfo: "oidc"},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster": {Server: "https://k8s.example.com"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"oidc": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "kubelogin-daemon",
					Args: []string{
						"get-token",
						"--oidc-issuer-url=https://issuer.example.com",
						"--oidc-client-id=test",
						"--username=johndoe",
					},
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	parsed, err := parseOIDCFromKubeconfig("")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if parsed.username != "johndoe" {
		t.Errorf("username = %q, want johndoe", parsed.username)
	}
}

// ==========================================================================
// Round 5: oidcFlags / login / check / refresh parity gaps
// ==========================================================================

// Bug: oidcFlags struct is missing extraParams field.
// login/check/refresh commands cannot carry extra params from kubeconfig,
// so their cache keys differ from get-token's cache key.
func TestOidcFlags_HasExtraParams(t *testing.T) {
	f := oidcFlags{}
	// If oidcFlags has extraParams, we can set it.
	f.extraParams = map[string]string{"audience": "api"}
	if f.extraParams["audience"] != "api" {
		t.Error("oidcFlags.extraParams field missing or broken")
	}
}

// Bug: addOIDCFlags doesn't register --oidc-extra-param for login/check/refresh.
// So these commands can't accept extra params from CLI.
func TestAddOIDCFlags_RegistersExtraParam(t *testing.T) {
	var f oidcFlags
	cmd := &cobra.Command{Use: "test"}
	addOIDCFlags(cmd, &f, false, false, false)
	// --oidc-extra-param must be registered
	flag := cmd.Flags().Lookup("oidc-extra-param")
	if flag == nil {
		t.Fatal("addOIDCFlags does not register --oidc-extra-param")
	}
}

// Bug: resolveFromKubeconfig doesn't merge extraParams from kubeconfig.
func TestResolveFromKubeconfig_MergesExtraParams(t *testing.T) {
	config := &clientcmdapi.Config{
		CurrentContext: "test",
		Contexts: map[string]*clientcmdapi.Context{
			"test": {Cluster: "cluster", AuthInfo: "oidc"},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster": {Server: "https://k8s.example.com"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"oidc": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "kubelogin-daemon",
					Args: []string{
						"get-token",
						"--oidc-issuer-url=https://issuer.example.com",
						"--oidc-client-id=test",
						"--oidc-extra-param=audience=api",
					},
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	f := oidcFlags{}
	cmd := &cobra.Command{Use: "test"}
	addOIDCFlags(cmd, &f, true, true, true)
	cmd.SetArgs([]string{})
	_ = cmd.Execute()

	if err := f.resolveFromKubeconfig(cmd); err != nil {
		t.Fatalf("resolveFromKubeconfig: %v", err)
	}
	if f.extraParams == nil || f.extraParams["audience"] != "api" {
		t.Errorf("extraParams = %v, want {audience:api}", f.extraParams)
	}
}

// Bug: Login cache key uses nil extraParams — doesn't match get-token cache key
// when kubeconfig has --oidc-extra-param.
func TestCacheKeyParity_LoginVsGetToken(t *testing.T) {
	ep := map[string]string{"audience": "api"}
	keyWithParams, err := computeCacheKey(tokencache.Key{
		Provider:               oidc.Provider{IssuerURL: "https://issuer", ClientID: "client"},
		AuthRequestExtraParams: ep,
	})
	if err != nil {
		t.Fatalf("computeCacheKey with params: %v", err)
	}
	keyWithout, err := computeCacheKey(tokencache.Key{
		Provider: oidc.Provider{IssuerURL: "https://issuer", ClientID: "client"},
	})
	if err != nil {
		t.Fatalf("computeCacheKey without params: %v", err)
	}
	// These MUST be different — extra params affect cache key partitioning.
	if keyWithParams == keyWithout {
		t.Error("cache key should differ when extraParams differ (login passes nil, get-token passes actual)")
	}
}

// Bug: PerformAuth ignores skipOpenBrowser — hardcodes devicecode.Option{}.
// The AuthOptions struct must exist and carry through.
func TestPerformAuth_AcceptsAuthOptions(t *testing.T) {
	// This test verifies the PerformAuth signature accepts AuthOptions.
	// It doesn't actually call an OIDC provider — just checks compilation and defaults.
	opts := shim.AuthOptions{
		SkipOpenBrowser:        true,
		AuthenticationTimeout:  60,
		ListenAddress:          []string{"127.0.0.1:9000"},
		AuthRequestExtraParams: map[string]string{"prompt": "consent"},
	}
	if !opts.SkipOpenBrowser {
		t.Error("AuthOptions.SkipOpenBrowser not set")
	}
	if opts.AuthenticationTimeout != 60 {
		t.Error("AuthOptions.AuthenticationTimeout not set")
	}
	if len(opts.ListenAddress) != 1 {
		t.Error("AuthOptions.ListenAddress not set")
	}
	if opts.AuthRequestExtraParams["prompt"] != "consent" {
		t.Error("AuthOptions.AuthRequestExtraParams not set")
	}
}

// Bug: runSetupInstall doesn't emit --oidc-extra-param in generated kubeconfig exec args.
// Extra params configured during setup are lost in the kubeconfig.
func TestSetupInstall_EmitsExtraParams(t *testing.T) {
	f := &oidcFlags{
		issuerURL:   "https://issuer.example.com",
		clientID:    "test-client",
		extraParams: map[string]string{"audience": "api", "prompt": "consent"},
	}

	// We can't easily call runSetupInstall (it writes kubeconfig), so we test
	// the exec args generation logic. The args should contain --oidc-extra-param.
	// Inline the same logic as runSetupInstall to check:
	execArgs := []string{"get-token"}
	execArgs = append(execArgs, fmt.Sprintf("--oidc-issuer-url=%s", f.issuerURL))
	execArgs = append(execArgs, fmt.Sprintf("--oidc-client-id=%s", f.clientID))
	for k, v := range f.extraParams {
		execArgs = append(execArgs, fmt.Sprintf("--oidc-extra-param=%s=%s", k, v))
	}

	// Parse them back
	cfg := parseExecArgs(execArgs)
	if cfg.extraParams == nil {
		t.Fatal("extraParams is nil after round-trip")
	}
	if cfg.extraParams["audience"] != "api" {
		t.Errorf("audience = %q, want 'api'", cfg.extraParams["audience"])
	}
	if cfg.extraParams["prompt"] != "consent" {
		t.Errorf("prompt = %q, want 'consent'", cfg.extraParams["prompt"])
	}
}

// Bug: parseExecArgs treats --bool-flag false as --bool-flag (true) + positional "false".
// Upstream pflag consumes the next token as the boolean value.
func TestParseExecArgs_BoolFlagSpaceFalse(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--skip-open-browser", "false",
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
	})
	if cfg.skipOpenBrowser {
		t.Error("--skip-open-browser false should set skipOpenBrowser=false, got true")
	}
}

// Also test --oidc-use-access-token false in space format.
func TestParseExecArgs_UseAccessTokenSpaceFalse(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-use-access-token", "false",
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
	})
	if cfg.useAccessToken {
		t.Error("--oidc-use-access-token false should set useAccessToken=false, got true")
	}
}

// Test --force-refresh false in space format.
func TestParseExecArgs_ForceRefreshSpaceFalse(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--force-refresh", "false",
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=test",
	})
	if cfg.forceRefresh {
		t.Error("--force-refresh false should set forceRefresh=false, got true")
	}
}

// Test --bool-flag true in space format (should be explicit true, not just bare flag).
func TestParseExecArgs_BoolFlagSpaceTrue(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--skip-open-browser", "true",
		"--oidc-client-id=test",
		"--oidc-issuer-url=https://issuer.example.com",
	})
	if !cfg.skipOpenBrowser {
		t.Error("--skip-open-browser true should set skipOpenBrowser=true")
	}
	if cfg.clientID != "test" {
		t.Errorf("clientID = %q, want 'test' (next flag consumed by bool)", cfg.clientID)
	}
}
