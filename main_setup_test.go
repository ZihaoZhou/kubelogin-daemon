package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/daemon"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// writeTestKubeconfig writes a kubeconfig file with the given users and returns the path.
func writeTestKubeconfig(t *testing.T, config *clientcmdapi.Config) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := clientcmd.WriteToFile(*config, path); err != nil {
		t.Fatalf("write test kubeconfig: %v", err)
	}
	return path
}

// --- parseOIDCFromKubeconfig tests ---

func TestParseOIDC_AcceptKubelogin(t *testing.T) {
	config := &clientcmdapi.Config{
		CurrentContext: "test",
		Contexts: map[string]*clientcmdapi.Context{
			"test": {Cluster: "cluster", AuthInfo: "user"},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster": {Server: "https://k8s.example.com"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"user": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "kubelogin",
					Args:    []string{"get-token", "--oidc-issuer-url=https://issuer.example.com", "--oidc-client-id=my-client"},
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	// Set global kubeconfigPath
	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	parsed, err := parseOIDCFromKubeconfig("")
	if err != nil {
		t.Fatalf("should accept kubelogin command: %v", err)
	}
	if parsed.issuerURL != "https://issuer.example.com" {
		t.Errorf("issuerURL = %q, want https://issuer.example.com", parsed.issuerURL)
	}
	if parsed.clientID != "my-client" {
		t.Errorf("clientID = %q, want my-client", parsed.clientID)
	}
}

func TestParseOIDC_AcceptKubectlOidcLogin(t *testing.T) {
	config := &clientcmdapi.Config{
		CurrentContext: "test",
		Contexts: map[string]*clientcmdapi.Context{
			"test": {Cluster: "cluster", AuthInfo: "user"},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster": {Server: "https://k8s.example.com"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"user": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "/usr/local/bin/kubectl-oidc_login",
					Args:    []string{"get-token", "--oidc-issuer-url=https://issuer.example.com", "--oidc-client-id=kctl-client"},
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
		t.Fatalf("should accept kubectl-oidc_login: %v", err)
	}
	if parsed.clientID != "kctl-client" {
		t.Errorf("clientID = %q, want kctl-client", parsed.clientID)
	}
}

func TestParseOIDC_RejectUnknownCommand(t *testing.T) {
	config := &clientcmdapi.Config{
		CurrentContext: "test",
		Contexts: map[string]*clientcmdapi.Context{
			"test": {Cluster: "cluster", AuthInfo: "user"},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster": {Server: "https://k8s.example.com"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"user": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "some-other-tool",
					Args:    []string{"get-token"},
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	_, err := parseOIDCFromKubeconfig("")
	if err == nil {
		t.Fatal("should reject unknown exec command")
	}
	if !strings.Contains(err.Error(), "some-other-tool") {
		t.Errorf("error should mention the unknown command, got: %v", err)
	}
}

// --- --kubeconfig flag tests ---

func TestKubeconfigFlag_ExplicitPath(t *testing.T) {
	config := &clientcmdapi.Config{
		CurrentContext: "explicit",
		Contexts: map[string]*clientcmdapi.Context{
			"explicit": {Cluster: "cluster", AuthInfo: "user"},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster": {Server: "https://k8s.example.com"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"user": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "kubelogin-daemon",
					Args:    []string{"get-token", "--oidc-issuer-url=https://explicit.example.com", "--oidc-client-id=explicit-client"},
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
		t.Fatalf("explicit kubeconfig path failed: %v", err)
	}
	if parsed.issuerURL != "https://explicit.example.com" {
		t.Errorf("issuerURL = %q, want https://explicit.example.com", parsed.issuerURL)
	}
}

func TestKubeconfigFlag_InvalidPath(t *testing.T) {
	old := kubeconfigPath
	kubeconfigPath = filepath.Join(t.TempDir(), "nonexistent", "config")
	defer func() { kubeconfigPath = old }()

	_, err := parseOIDCFromKubeconfig("")
	if err == nil {
		t.Fatal("should fail with invalid kubeconfig path")
	}
}

// --- setup migrate detection tests ---

func TestSetupMigrate_DetectsKubelogin(t *testing.T) {
	config := &clientcmdapi.Config{
		CurrentContext: "nautilus",
		Contexts: map[string]*clientcmdapi.Context{
			"nautilus": {Cluster: "nautilus-cluster", AuthInfo: "oidc"},
			"staging":  {Cluster: "staging-cluster", AuthInfo: "oidc-staging"},
			"other":    {Cluster: "other-cluster", AuthInfo: "basic-user"},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			"nautilus-cluster": {Server: "https://nautilus.example.com"},
			"staging-cluster":  {Server: "https://staging.example.com"},
			"other-cluster":    {Server: "https://other.example.com"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"oidc": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "kubelogin",
					Args: []string{"get-token",
						"--oidc-issuer-url=https://cilogon.org/authorize",
						"--oidc-client-id=cilogon:/client_id/xxx",
						"--grant-type=device-code"},
				},
			},
			"oidc-staging": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "/usr/local/bin/kubelogin",
					Args: []string{"get-token",
						"--oidc-issuer-url=https://staging.cilogon.org/authorize",
						"--oidc-client-id=staging-client"},
				},
			},
			"basic-user": {
				Token: "test-static-token",
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	// Test dry-run migration
	err := runSetupMigrate("", true, true, false)
	if err != nil {
		t.Fatalf("dry-run migrate failed: %v", err)
	}

	// Verify kubeconfig was NOT modified (dry-run)
	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}
	reloaded, err := rules.Load()
	if err != nil {
		t.Fatalf("reload kubeconfig: %v", err)
	}
	if filepath.Base(reloaded.AuthInfos["oidc"].Exec.Command) != "kubelogin" {
		t.Error("dry-run should not modify kubeconfig")
	}
}

func TestSetupMigrate_ActualMigration(t *testing.T) {
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
					Args: []string{"get-token",
						"--oidc-issuer-url=https://issuer.example.com",
						"--oidc-client-id=my-client",
						"--grant-type=device-code"},
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	// Actual migration (--yes, no backup for cleaner test)
	err := runSetupMigrate("", false, true, false)
	if err != nil {
		t.Fatalf("migrate failed: %v", err)
	}

	// Reload and verify
	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}
	reloaded, err := rules.Load()
	if err != nil {
		t.Fatalf("reload kubeconfig: %v", err)
	}

	user := reloaded.AuthInfos["oidc"]
	if user.Exec == nil {
		t.Fatal("exec config should still exist")
	}
	// Command should now be absolute path to our binary
	if filepath.Base(user.Exec.Command) == "kubelogin" {
		t.Error("command should have been changed from kubelogin")
	}
	// Args should be preserved
	foundIssuer := false
	for _, arg := range user.Exec.Args {
		if strings.Contains(arg, "issuer.example.com") {
			foundIssuer = true
		}
	}
	if !foundIssuer {
		t.Error("OIDC args should be preserved after migration")
	}
	// InteractiveMode should be Never
	if user.Exec.InteractiveMode != clientcmdapi.NeverExecInteractiveMode {
		t.Errorf("interactiveMode should be Never, got %q", user.Exec.InteractiveMode)
	}
}

func TestSetupMigrate_WithBackup(t *testing.T) {
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
					Args:    []string{"get-token", "--oidc-issuer-url=https://issuer.example.com", "--oidc-client-id=c"},
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	err := runSetupMigrate("", false, true, true)
	if err != nil {
		t.Fatalf("migrate with backup failed: %v", err)
	}

	// Check that a backup file was created
	matches, _ := filepath.Glob(path + ".bak.*")
	if len(matches) == 0 {
		t.Error("backup file should have been created")
	}
}

func TestSetupMigrate_NoEntries(t *testing.T) {
	config := &clientcmdapi.Config{
		CurrentContext: "test",
		Contexts: map[string]*clientcmdapi.Context{
			"test": {Cluster: "cluster", AuthInfo: "user"},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster": {Server: "https://k8s.example.com"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"user": {Token: "test-static-token"},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	// Should return nil (nothing to migrate)
	err := runSetupMigrate("", false, true, false)
	if err != nil {
		t.Fatalf("should gracefully handle no entries: %v", err)
	}
}

func TestSetupMigrate_ContextFilter(t *testing.T) {
	config := &clientcmdapi.Config{
		CurrentContext: "nautilus",
		Contexts: map[string]*clientcmdapi.Context{
			"nautilus": {Cluster: "c1", AuthInfo: "oidc1"},
			"staging":  {Cluster: "c2", AuthInfo: "oidc2"},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			"c1": {Server: "https://nautilus.example.com"},
			"c2": {Server: "https://staging.example.com"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"oidc1": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "kubelogin",
					Args:    []string{"get-token", "--oidc-issuer-url=https://issuer1.example.com", "--oidc-client-id=c1"},
				},
			},
			"oidc2": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "kubelogin",
					Args:    []string{"get-token", "--oidc-issuer-url=https://issuer2.example.com", "--oidc-client-id=c2"},
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	// Migrate only staging
	err := runSetupMigrate("staging", false, true, false)
	if err != nil {
		t.Fatalf("context-filtered migrate failed: %v", err)
	}

	// Reload and verify: oidc1 should be untouched, oidc2 should be migrated
	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}
	reloaded, err := rules.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	if filepath.Base(reloaded.AuthInfos["oidc1"].Exec.Command) != "kubelogin" {
		t.Error("oidc1 should NOT have been migrated (context filter)")
	}
	if filepath.Base(reloaded.AuthInfos["oidc2"].Exec.Command) == "kubelogin" {
		t.Error("oidc2 should have been migrated")
	}
}

// --- setup install tests ---

func TestSetupInstall_DryRun(t *testing.T) {
	f := &oidcFlags{
		issuerURL: "https://issuer.example.com",
		clientID:  "my-client",
		grantType: "device-code",
	}

	// dry-run should not fail even without a real kubeconfig
	old := kubeconfigPath
	kubeconfigPath = filepath.Join(t.TempDir(), "config")
	defer func() { kubeconfigPath = old }()

	// Write minimal kubeconfig
	config := &clientcmdapi.Config{
		Clusters:  map[string]*clientcmdapi.Cluster{},
		Contexts:  map[string]*clientcmdapi.Context{},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{},
	}
	if err := clientcmd.WriteToFile(*config, kubeconfigPath); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}

	err := runSetupInstall(nil, f, "oidc", "", true, true, false)
	if err != nil {
		t.Fatalf("dry-run install should not fail: %v", err)
	}
}

func TestSetupInstall_WritesKubeconfig(t *testing.T) {
	f := &oidcFlags{
		issuerURL:    "https://issuer.example.com",
		clientID:     "my-client",
		clientSecret: "test-client-secret",
		extraScopes:  []string{"email", "profile"},
		grantType:    "authcode-browser",
	}

	kcPath := filepath.Join(t.TempDir(), "config")
	old := kubeconfigPath
	kubeconfigPath = kcPath
	defer func() { kubeconfigPath = old }()

	// Write minimal kubeconfig
	config := &clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			"mycluster": {Server: "https://k8s.example.com"},
		},
		Contexts:  map[string]*clientcmdapi.Context{},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{},
	}
	if err := clientcmd.WriteToFile(*config, kcPath); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}

	// Install with skip-auth-test (no real OIDC endpoint) and cluster binding
	err := runSetupInstall(nil, f, "oidc", "mycluster", true, false, false)
	if err != nil {
		t.Fatalf("install failed: %v", err)
	}

	// Reload and verify
	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kcPath}
	reloaded, err := rules.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	user, ok := reloaded.AuthInfos["oidc"]
	if !ok {
		t.Fatal("user 'oidc' not found in kubeconfig")
	}
	if user.Exec == nil {
		t.Fatal("exec config should exist")
	}
	if user.Exec.APIVersion != "client.authentication.k8s.io/v1" {
		t.Errorf("apiVersion = %q, want v1", user.Exec.APIVersion)
	}
	if user.Exec.InteractiveMode != clientcmdapi.NeverExecInteractiveMode {
		t.Errorf("interactiveMode = %q, want Never", user.Exec.InteractiveMode)
	}

	// Check args contain all OIDC flags
	args := strings.Join(user.Exec.Args, " ")
	for _, want := range []string{"--oidc-issuer-url=https://issuer.example.com", "--oidc-client-id=my-client", "--oidc-client-secret=test-client-secret", "--oidc-extra-scope=email", "--oidc-extra-scope=profile", "--grant-type=authcode-browser"} {
		if !strings.Contains(args, want) {
			t.Errorf("args should contain %q, got: %s", want, args)
		}
	}

	// Check context was created
	ctx, ok := reloaded.Contexts["mycluster"]
	if !ok {
		t.Fatal("context 'mycluster' not found")
	}
	if ctx.AuthInfo != "oidc" || ctx.Cluster != "mycluster" {
		t.Errorf("context should bind cluster=mycluster, user=oidc, got cluster=%s user=%s", ctx.Cluster, ctx.AuthInfo)
	}
}

func TestSetupInstall_NonexistentCluster(t *testing.T) {
	f := &oidcFlags{
		issuerURL: "https://issuer.example.com",
		clientID:  "my-client",
	}

	kcPath := filepath.Join(t.TempDir(), "config")
	old := kubeconfigPath
	kubeconfigPath = kcPath
	defer func() { kubeconfigPath = old }()

	config := &clientcmdapi.Config{
		Clusters:  map[string]*clientcmdapi.Cluster{},
		Contexts:  map[string]*clientcmdapi.Context{},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{},
	}
	if err := clientcmd.WriteToFile(*config, kcPath); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}

	err := runSetupInstall(nil, f, "oidc", "nonexistent", true, false, false)
	if err == nil {
		t.Fatal("should fail with nonexistent cluster")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error should mention cluster name, got: %v", err)
	}
}

func TestSetupInstall_UseAccessToken(t *testing.T) {
	f := &oidcFlags{
		issuerURL:      "https://issuer.example.com",
		clientID:       "my-client",
		useAccessToken: true,
	}

	kcPath := filepath.Join(t.TempDir(), "config")
	old := kubeconfigPath
	kubeconfigPath = kcPath
	defer func() { kubeconfigPath = old }()

	config := &clientcmdapi.Config{
		Clusters:  map[string]*clientcmdapi.Cluster{},
		Contexts:  map[string]*clientcmdapi.Context{},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{},
	}
	if err := clientcmd.WriteToFile(*config, kcPath); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}

	err := runSetupInstall(nil, f, "oidc", "", true, false, false)
	if err != nil {
		t.Fatalf("install failed: %v", err)
	}

	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kcPath}
	reloaded, err := rules.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	args := strings.Join(reloaded.AuthInfos["oidc"].Exec.Args, " ")
	if !strings.Contains(args, "--oidc-use-access-token") {
		t.Error("args should contain --oidc-use-access-token when useAccessToken=true")
	}
}

// --- robustness edge case tests ---

func TestSafeWriteFile_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	err := safeWriteFile(link, []byte("overwritten"), 0600)
	if err == nil {
		t.Fatal("safeWriteFile should reject symlinks")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error should mention symlink, got: %v", err)
	}

	// Original should be untouched
	data, _ := os.ReadFile(target)
	if string(data) != "original" {
		t.Error("original file should not be modified")
	}
}

func TestSafeWriteFile_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	// Write initial content
	if err := safeWriteFile(path, []byte("version1"), 0600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	// Overwrite
	if err := safeWriteFile(path, []byte("version2"), 0600); err != nil {
		t.Fatalf("second write: %v", err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "version2" {
		t.Errorf("content = %q, want version2", data)
	}
	// Check permissions
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Errorf("perms = %v, want 0600", info.Mode().Perm())
	}
}

func TestSafeWriteFile_NewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new-config")

	err := safeWriteFile(path, []byte("new content"), 0600)
	if err != nil {
		t.Fatalf("writing new file: %v", err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "new content" {
		t.Errorf("content = %q, want 'new content'", data)
	}
}

func TestSetupMigrate_MixedAuthInfos(t *testing.T) {
	// Test with a mix of exec and non-exec users — migration should only touch kubelogin entries
	config := &clientcmdapi.Config{
		CurrentContext: "test",
		Contexts: map[string]*clientcmdapi.Context{
			"test":    {Cluster: "cluster", AuthInfo: "oidc"},
			"basic-ctx": {Cluster: "cluster", AuthInfo: "basic-user"},
			"noexec-ctx": {Cluster: "cluster", AuthInfo: "noexec-user"},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster": {Server: "https://k8s.example.com"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"oidc": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "kubelogin",
					Args:    []string{"get-token", "--oidc-issuer-url=https://i.example.com", "--oidc-client-id=c"},
				},
			},
			"basic-user": {Token: "test-static-token"},        // no exec
			"noexec-user": {},                           // empty but non-nil, no exec
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	// Should not panic, should find and migrate only the oidc entry
	err := runSetupMigrate("", false, true, false)
	if err != nil {
		t.Fatalf("migrate with mixed entries should not fail: %v", err)
	}

	// Verify only oidc was migrated
	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}
	reloaded, err := rules.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if filepath.Base(reloaded.AuthInfos["oidc"].Exec.Command) == "kubelogin" {
		t.Error("oidc should have been migrated")
	}
	if reloaded.AuthInfos["basic-user"].Token != "test-static-token" {
		t.Error("basic-user should be untouched")
	}
}

func TestSetupInstall_SymlinkKubeconfig(t *testing.T) {
	dir := t.TempDir()
	realConfig := filepath.Join(dir, "real-config")
	linkConfig := filepath.Join(dir, "config-link")

	// Create real kubeconfig
	config := &clientcmdapi.Config{
		Clusters:  map[string]*clientcmdapi.Cluster{},
		Contexts:  map[string]*clientcmdapi.Context{},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{},
	}
	if err := clientcmd.WriteToFile(*config, realConfig); err != nil {
		t.Fatal(err)
	}

	// Create symlink pointing to real config
	if err := os.Symlink(realConfig, linkConfig); err != nil {
		t.Fatal(err)
	}

	old := kubeconfigPath
	kubeconfigPath = linkConfig
	defer func() { kubeconfigPath = old }()

	f := &oidcFlags{
		issuerURL: "https://issuer.example.com",
		clientID:  "my-client",
	}
	err := runSetupInstall(nil, f, "oidc", "", true, false, false)
	if err == nil {
		t.Fatal("should reject symlink kubeconfig")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error should mention symlink, got: %v", err)
	}
}

// --- daemon status enhancement tests ---

func TestDaemonStatus_LoggerFilePath(t *testing.T) {
	dir := t.TempDir()
	logger, err := daemon.NewLogger(dir, false)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()

	path := logger.FilePath()
	if path == "" {
		t.Error("FilePath should return non-empty for file logger")
	}
	if !strings.HasSuffix(path, "daemon.log") {
		t.Errorf("FilePath should end with daemon.log, got %q", path)
	}
}

func TestDaemonStatus_StderrLoggerFilePath(t *testing.T) {
	logger := daemon.NewStderrLogger(false)
	if logger.FilePath() != "" {
		t.Error("stderr logger FilePath should be empty")
	}
}

// --- isKubeloginDaemonCommand tests ---

func TestIsKubeloginDaemonCommand(t *testing.T) {
	tests := []struct {
		command string
		want    bool
	}{
		{"kubelogin-daemon", true},
		{"kubelogin-daemon.exe", true},
		{"/usr/local/bin/kubelogin-daemon", true},
		{"/usr/local/bin/kubelogin-daemon.exe", true},
		// Prefix-matched variants (Bug 1.6: match renamed binaries)
		{"kubelogin-daemon-old", true},
		{"kubelogin-daemon-new", true},
		{"kubelogin-daemon-v2", true},
		{"kubelogin-daemon-linux-amd64", true},
		{"/tmp/kubelogin-daemon-new", true},
		// Non-matches
		{"kubelogin", false},
		{"kubectl-oidc_login", false},
		{"some-other-tool", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := isKubeloginDaemonCommand(tt.command)
			if got != tt.want {
				t.Errorf("isKubeloginDaemonCommand(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// --- hasMultipleKubeconfigs tests ---

func TestHasMultipleKubeconfigs_None(t *testing.T) {
	t.Setenv("KUBECONFIG", "")
	if hasMultipleKubeconfigs() {
		t.Error("empty KUBECONFIG should not be multiple")
	}
}

func TestHasMultipleKubeconfigs_Single(t *testing.T) {
	path := writeTestKubeconfig(t, &clientcmdapi.Config{})
	t.Setenv("KUBECONFIG", path)
	if hasMultipleKubeconfigs() {
		t.Error("single KUBECONFIG should not be multiple")
	}
}

func TestHasMultipleKubeconfigs_Multiple(t *testing.T) {
	path1 := writeTestKubeconfig(t, &clientcmdapi.Config{})
	path2 := writeTestKubeconfig(t, &clientcmdapi.Config{})
	t.Setenv("KUBECONFIG", path1+string(filepath.ListSeparator)+path2)
	if !hasMultipleKubeconfigs() {
		t.Error("two existing KUBECONFIG files should be multiple")
	}
}

func TestHasMultipleKubeconfigs_NonexistentIgnored(t *testing.T) {
	path1 := writeTestKubeconfig(t, &clientcmdapi.Config{})
	t.Setenv("KUBECONFIG", path1+string(filepath.ListSeparator)+"/nonexistent/config")
	if hasMultipleKubeconfigs() {
		t.Error("one existing + one nonexistent should not count as multiple")
	}
}

// --- setup upgrade tests ---

func TestSetupUpgrade_HappyPath(t *testing.T) {
	// Create a kubeconfig with a stale kubelogin-daemon entry
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
					Command: "/old/path/kubelogin-daemon",
					Args:    []string{"get-token", "--oidc-issuer-url=https://issuer.example.com", "--oidc-client-id=c"},
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	// Run upgrade with --yes and --keep-old (skip deletion, no confirmation)
	err := runSetupUpgrade(false, true, false, true)
	if err != nil {
		t.Fatalf("upgrade failed: %v", err)
	}

	// Reload and verify the command was updated
	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}
	reloaded, err := rules.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	user := reloaded.AuthInfos["oidc"]
	if user.Exec == nil {
		t.Fatal("exec config should exist")
	}
	if user.Exec.Command == "/old/path/kubelogin-daemon" {
		t.Error("command should have been updated from old path")
	}
	// Verify args were preserved
	args := strings.Join(user.Exec.Args, " ")
	if !strings.Contains(args, "issuer.example.com") {
		t.Error("OIDC args should be preserved after upgrade")
	}
}

func TestSetupUpgrade_AlreadyUpToDate(t *testing.T) {
	// Get current binary path
	binPath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binPath, err = filepath.EvalSymlinks(binPath)
	if err != nil {
		t.Fatal(err)
	}

	config := &clientcmdapi.Config{
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"oidc": {
				Exec: &clientcmdapi.ExecConfig{
					Command: binPath,
					Args:    []string{"get-token"},
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	// Should succeed (exit 0) — "Already up to date"
	err = runSetupUpgrade(false, true, false, true)
	if err != nil {
		t.Fatalf("already up-to-date should not fail: %v", err)
	}
}

func TestSetupUpgrade_NoEntries(t *testing.T) {
	config := &clientcmdapi.Config{
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"user": {Token: "static-token"},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	// Should succeed (exit 0) — suggests setup install
	err := runSetupUpgrade(false, true, false, true)
	if err != nil {
		t.Fatalf("no entries should not fail: %v", err)
	}
}

func TestSetupUpgrade_DryRun(t *testing.T) {
	config := &clientcmdapi.Config{
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"oidc": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "/old/path/kubelogin-daemon",
					Args:    []string{"get-token"},
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	err := runSetupUpgrade(true, true, false, false)
	if err != nil {
		t.Fatalf("dry-run should not fail: %v", err)
	}

	// Verify kubeconfig was NOT modified
	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}
	reloaded, err := rules.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.AuthInfos["oidc"].Exec.Command != "/old/path/kubelogin-daemon" {
		t.Error("dry-run should not modify kubeconfig")
	}
}

func TestSetupUpgrade_MultipleStaleEntries(t *testing.T) {
	config := &clientcmdapi.Config{
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"oidc1": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "/old/path1/kubelogin-daemon",
					Args:    []string{"get-token"},
				},
			},
			"oidc2": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "/old/path2/kubelogin-daemon",
					Args:    []string{"get-token"},
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	err := runSetupUpgrade(false, true, false, true)
	if err != nil {
		t.Fatalf("upgrade with multiple entries failed: %v", err)
	}

	// Both should be updated
	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}
	reloaded, err := rules.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	for _, name := range []string{"oidc1", "oidc2"} {
		if strings.Contains(reloaded.AuthInfos[name].Exec.Command, "/old/") {
			t.Errorf("%s should have been updated", name)
		}
	}
}

func TestSetupUpgrade_WithBackup(t *testing.T) {
	config := &clientcmdapi.Config{
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"oidc": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "/old/path/kubelogin-daemon",
					Args:    []string{"get-token"},
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	err := runSetupUpgrade(false, true, true, true)
	if err != nil {
		t.Fatalf("upgrade with backup failed: %v", err)
	}

	// Verify backup was created
	matches, _ := filepath.Glob(path + ".bak.*")
	if len(matches) == 0 {
		t.Error("backup file should have been created")
	}
}

func TestSetupUpgrade_MultipleKubeconfigs(t *testing.T) {
	path1 := writeTestKubeconfig(t, &clientcmdapi.Config{})
	path2 := writeTestKubeconfig(t, &clientcmdapi.Config{})

	old := kubeconfigPath
	kubeconfigPath = ""
	defer func() { kubeconfigPath = old }()

	t.Setenv("KUBECONFIG", path1+string(filepath.ListSeparator)+path2)

	err := runSetupUpgrade(false, true, false, true)
	if err == nil {
		t.Fatal("should fail with multiple kubeconfig files")
	}
	if !strings.Contains(err.Error(), "multiple kubeconfig") {
		t.Errorf("error should mention multiple kubeconfig, got: %v", err)
	}
}

// --- deleteOldBinary safety tests ---

func TestDeleteOldBinary_NonKubeloginDaemon(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "not-kubelogin")
	os.WriteFile(badPath, []byte("x"), 0755)

	err := deleteOldBinary(badPath, "/new/kubelogin-daemon")
	if err == nil {
		t.Fatal("should refuse to delete non-kubelogin-daemon binary")
	}
	if !strings.Contains(err.Error(), "refusing") {
		t.Errorf("error should mention refusing, got: %v", err)
	}
	// File should still exist
	if _, err := os.Stat(badPath); os.IsNotExist(err) {
		t.Error("file should NOT have been deleted")
	}
}

func TestDeleteOldBinary_AlreadyGone(t *testing.T) {
	err := deleteOldBinary("/nonexistent/kubelogin-daemon", "/new/kubelogin-daemon")
	if err != nil {
		t.Fatalf("already-gone path should not fail: %v", err)
	}
}

func TestDeleteOldBinary_SameResolvedPath(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "real")
	os.MkdirAll(subdir, 0755)
	realBin := filepath.Join(subdir, "kubelogin-daemon")
	os.WriteFile(realBin, []byte("binary"), 0755)

	// Create a symlink with the correct basename in a different directory
	linkDir := filepath.Join(dir, "link")
	os.MkdirAll(linkDir, 0755)
	linkBin := filepath.Join(linkDir, "kubelogin-daemon")
	os.Symlink(realBin, linkBin)

	// Should not delete because they resolve to the same file
	err := deleteOldBinary(linkBin, realBin)
	if err != nil {
		t.Fatalf("same-file should not fail: %v", err)
	}
	// Real binary should still exist
	if _, err := os.Stat(realBin); os.IsNotExist(err) {
		t.Error("real binary should still exist")
	}
}

func TestDeleteOldBinary_SymlinkRemovesOnlySymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "kubelogin-daemon-target")
	os.WriteFile(target, []byte("binary"), 0755)

	link := filepath.Join(dir, "kubelogin-daemon")
	os.Symlink(target, link)

	// Different new path so it won't be treated as same file
	newPath := filepath.Join(dir, "new", "kubelogin-daemon")
	os.MkdirAll(filepath.Join(dir, "new"), 0755)
	os.WriteFile(newPath, []byte("new binary"), 0755)

	err := deleteOldBinary(link, newPath)
	if err != nil {
		t.Fatalf("symlink delete should not fail: %v", err)
	}
	// Symlink should be gone
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Error("symlink should have been removed")
	}
	// Target should still exist
	if _, err := os.Stat(target); os.IsNotExist(err) {
		t.Error("target should not be deleted")
	}
}

// --- setup install backup tests ---

func TestSetupInstall_BackupCreated(t *testing.T) {
	f := &oidcFlags{
		issuerURL: "https://issuer.example.com",
		clientID:  "my-client",
	}

	kcPath := filepath.Join(t.TempDir(), "config")
	old := kubeconfigPath
	kubeconfigPath = kcPath
	defer func() { kubeconfigPath = old }()

	config := &clientcmdapi.Config{
		Clusters:  map[string]*clientcmdapi.Cluster{},
		Contexts:  map[string]*clientcmdapi.Context{},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{},
	}
	if err := clientcmd.WriteToFile(*config, kcPath); err != nil {
		t.Fatal(err)
	}

	// Install with backup=true
	err := runSetupInstall(nil, f, "oidc", "", true, false, true)
	if err != nil {
		t.Fatalf("install failed: %v", err)
	}

	matches, _ := filepath.Glob(kcPath + ".bak.*")
	if len(matches) == 0 {
		t.Error("backup should have been created with backup=true")
	}
}

func TestSetupInstall_BackupSkipped(t *testing.T) {
	f := &oidcFlags{
		issuerURL: "https://issuer.example.com",
		clientID:  "my-client",
	}

	kcPath := filepath.Join(t.TempDir(), "config")
	old := kubeconfigPath
	kubeconfigPath = kcPath
	defer func() { kubeconfigPath = old }()

	config := &clientcmdapi.Config{
		Clusters:  map[string]*clientcmdapi.Cluster{},
		Contexts:  map[string]*clientcmdapi.Context{},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{},
	}
	if err := clientcmd.WriteToFile(*config, kcPath); err != nil {
		t.Fatal(err)
	}

	// Install with backup=false
	err := runSetupInstall(nil, f, "oidc", "", true, false, false)
	if err != nil {
		t.Fatalf("install failed: %v", err)
	}

	matches, _ := filepath.Glob(kcPath + ".bak.*")
	if len(matches) != 0 {
		t.Error("backup should not be created with backup=false")
	}
}

// --- setup migrate stale hint tests ---

func TestSetupMigrate_StaleHint(t *testing.T) {
	// Create a kubeconfig with both a kubelogin entry (migratable) and a
	// stale kubelogin-daemon entry
	config := &clientcmdapi.Config{
		CurrentContext: "test",
		Contexts: map[string]*clientcmdapi.Context{
			"test":   {Cluster: "cluster", AuthInfo: "oidc"},
			"stale":  {Cluster: "cluster", AuthInfo: "old-daemon"},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster": {Server: "https://k8s.example.com"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"oidc": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "kubelogin",
					Args:    []string{"get-token", "--oidc-issuer-url=https://issuer.example.com", "--oidc-client-id=c"},
				},
			},
			"old-daemon": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "/old/path/kubelogin-daemon",
					Args:    []string{"get-token", "--oidc-issuer-url=https://issuer.example.com", "--oidc-client-id=c"},
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	// The migrate should succeed and the stale daemon entry should not be modified
	err := runSetupMigrate("", false, true, false)
	if err != nil {
		t.Fatalf("migrate failed: %v", err)
	}

	// Verify the stale kubelogin-daemon entry was NOT modified by migrate
	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}
	reloaded, err := rules.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.AuthInfos["old-daemon"].Exec.Command != "/old/path/kubelogin-daemon" {
		t.Error("stale kubelogin-daemon entry should NOT be modified by migrate")
	}
	// The kubelogin entry should have been migrated
	if filepath.Base(reloaded.AuthInfos["oidc"].Exec.Command) == "kubelogin" {
		t.Error("kubelogin entry should have been migrated")
	}
}

func TestSetupMigrate_NoStaleHint(t *testing.T) {
	// Get current binary path
	binPath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binPath, err = filepath.EvalSymlinks(binPath)
	if err != nil {
		t.Fatal(err)
	}

	// Create kubeconfig with kubelogin entry and an up-to-date kubelogin-daemon entry
	config := &clientcmdapi.Config{
		CurrentContext: "test",
		Contexts: map[string]*clientcmdapi.Context{
			"test":    {Cluster: "cluster", AuthInfo: "oidc"},
			"current": {Cluster: "cluster", AuthInfo: "current-daemon"},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster": {Server: "https://k8s.example.com"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"oidc": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "kubelogin",
					Args:    []string{"get-token", "--oidc-issuer-url=https://issuer.example.com", "--oidc-client-id=c"},
				},
			},
			"current-daemon": {
				Exec: &clientcmdapi.ExecConfig{
					Command: binPath,
					Args:    []string{"get-token", "--oidc-issuer-url=https://issuer.example.com", "--oidc-client-id=c"},
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	// Should succeed — no stale hint needed since daemon entry is current
	err = runSetupMigrate("", false, true, false)
	if err != nil {
		t.Fatalf("migrate failed: %v", err)
	}
}

// --- backupKubeconfig tests ---

func TestBackupKubeconfig_CreatesBackup(t *testing.T) {
	path := writeTestKubeconfig(t, &clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{"c": {Server: "https://example.com"}},
	})

	backupPath, err := backupKubeconfig(path)
	if err != nil {
		t.Fatalf("backupKubeconfig failed: %v", err)
	}
	if backupPath == "" {
		t.Fatal("backup path should not be empty")
	}
	if !strings.HasPrefix(backupPath, path+".bak.") {
		t.Errorf("backup path should start with %s.bak., got %s", path, backupPath)
	}
	// Verify backup file has content
	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("backup should have content")
	}
}

func TestBackupKubeconfig_NonexistentSkipped(t *testing.T) {
	backupPath, err := backupKubeconfig(filepath.Join(t.TempDir(), "nonexistent"))
	if err != nil {
		t.Fatalf("nonexistent should not fail: %v", err)
	}
	if backupPath != "" {
		t.Errorf("nonexistent should return empty path, got %s", backupPath)
	}
}

// --- collectUniqueOldPaths tests ---

func TestCollectUniqueOldPaths_Dedup(t *testing.T) {
	result := collectUniqueOldPaths(
		[]string{"/old/kubelogin-daemon", "/old/kubelogin-daemon", "/other/kubelogin-daemon"},
		"/new/kubelogin-daemon",
	)
	if len(result) != 2 {
		t.Errorf("expected 2 unique paths, got %d: %v", len(result), result)
	}
}

func TestCollectUniqueOldPaths_ExcludesNewPath(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "kubelogin-daemon")
	os.WriteFile(bin, []byte("x"), 0755)

	// Resolve the path the same way the production code does (handles /var → /private/var on macOS)
	resolved, err := filepath.EvalSymlinks(bin)
	if err != nil {
		t.Fatal(err)
	}

	result := collectUniqueOldPaths([]string{bin}, resolved)
	if len(result) != 0 {
		t.Errorf("should exclude paths that resolve to newPath, got %v", result)
	}
}

// --- read-only kubeconfig test ---

func TestSetupUpgrade_ReadOnlyKubeconfig(t *testing.T) {
	config := &clientcmdapi.Config{
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"oidc": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "/old/path/kubelogin-daemon",
					Args:    []string{"get-token"},
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	// Make it read-only
	if err := os.Chmod(path, 0444); err != nil {
		t.Fatal(err)
	}
	// Restore permissions on cleanup so TempDir can be removed
	t.Cleanup(func() { os.Chmod(path, 0644) })

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	err := runSetupUpgrade(false, true, false, true)
	if err == nil {
		t.Fatal("should fail with read-only kubeconfig")
	}
	if !strings.Contains(err.Error(), "read-only") {
		t.Errorf("error should mention read-only, got: %v", err)
	}
}

// --- setup migrate stale hint in dry-run mode ---

func TestSetupMigrate_StaleHintDryRun(t *testing.T) {
	config := &clientcmdapi.Config{
		CurrentContext: "test",
		Contexts: map[string]*clientcmdapi.Context{
			"test":  {Cluster: "cluster", AuthInfo: "oidc"},
			"stale": {Cluster: "cluster", AuthInfo: "old-daemon"},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			"cluster": {Server: "https://k8s.example.com"},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"oidc": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "kubelogin",
					Args:    []string{"get-token", "--oidc-issuer-url=https://issuer.example.com", "--oidc-client-id=c"},
				},
			},
			"old-daemon": {
				Exec: &clientcmdapi.ExecConfig{
					Command: "/old/path/kubelogin-daemon",
					Args:    []string{"get-token", "--oidc-issuer-url=https://issuer.example.com", "--oidc-client-id=c"},
				},
			},
		},
	}
	path := writeTestKubeconfig(t, config)

	old := kubeconfigPath
	kubeconfigPath = path
	defer func() { kubeconfigPath = old }()

	// Dry-run migrate should show the stale hint without modifying anything
	err := runSetupMigrate("", true, true, false)
	if err != nil {
		t.Fatalf("dry-run migrate failed: %v", err)
	}

	// Verify kubeconfig was NOT modified
	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}
	reloaded, err := rules.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.AuthInfos["oidc"].Exec.Command != "kubelogin" {
		t.Error("dry-run should not modify kubeconfig")
	}
	if reloaded.AuthInfos["old-daemon"].Exec.Command != "/old/path/kubelogin-daemon" {
		t.Error("dry-run should not modify stale daemon entry")
	}
}
