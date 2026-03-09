package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/credentialplugin"
	credentialpluginwriter "github.com/ZihaoZhou/kubelogin-daemon/pkg/credentialplugin/writer"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/daemon"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/infrastructure/stdio"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/oidc"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/shim"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/tlsclientconfig"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/tokencache"
	tokencacherepository "github.com/ZihaoZhou/kubelogin-daemon/pkg/tokencache/repository"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

var version = "HEAD"

// errAlreadyReported is returned when the error has already been printed to stderr
// by writeUserError. The root handler should exit(1) without printing again.
var errAlreadyReported = errors.New("already reported")

// kubeconfigPath is the global --kubeconfig flag value, propagated to all commands that need it.
var kubeconfigPath string

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rootCmd := &cobra.Command{
		Use:           "kubelogin-daemon",
		Short:         "OIDC token daemon for kubectl — eliminates concurrent refresh token corruption",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.PersistentFlags().StringVar(&kubeconfigPath, "kubeconfig", "",
		"Path to kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")

	rootCmd.AddCommand(daemonCmd(), getTokenCmd(), loginCmd(), checkCmd(), refreshCmd(), setupCmd(), cleanCmd())

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		if !errors.Is(err, errAlreadyReported) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}

// --- daemon command group ---

func daemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Manage the daemon process",
	}

	// daemon start
	var verbose bool
	var idleTimeout time.Duration
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start the daemon process",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDaemonStart(cmd.Context(), verbose, idleTimeout)
		},
	}
	// ROB-HIGH-2: --foreground is accepted for backward compat with auto-start
	// callers but has no effect (daemon always runs in foreground; process
	// detachment is handled by the auto-start code's cmd.Process.Release).
	startCmd.Flags().Bool("foreground", false, "Run in foreground (no-op, kept for backward compat)")
	_ = startCmd.Flags().MarkHidden("foreground")
	startCmd.Flags().BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	startCmd.Flags().DurationVar(&idleTimeout, "idle-timeout", 0, "Idle timeout before auto-exit (0 = never)")

	// daemon stop
	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the daemon process",
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimeDir := daemon.RuntimeDir()
			if err := shim.SendShutdown(runtimeDir); err != nil {
				return fmt.Errorf("send shutdown: %w (is the daemon running?)", err)
			}
			fmt.Println("Shutdown signal sent.")
			return nil
		},
	}

	// daemon status
	var statusJSON bool
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Check daemon status",
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimeDir := daemon.RuntimeDir()
			ipcAddr := daemon.TransportAddress(runtimeDir)
			resp, err := shim.SendHealth(runtimeDir)
			if err != nil {
				if statusJSON {
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					return enc.Encode(map[string]any{
						"status":      "stopped",
						"address":     ipcAddr,
						"runtime_dir": runtimeDir,
					})
				}
				fmt.Printf("Status:       stopped\n")
				fmt.Printf("Address:      %s\n", ipcAddr)
				fmt.Printf("Runtime dir:  %s\n", runtimeDir)
				return nil
			}
			if statusJSON {
				out := map[string]any{
					"status":           "running",
					"pid":              resp.PID,
					"uptime":           resp.Uptime,
					"uptime_seconds":   resp.UptimeSeconds,
					"tokens_managed":   resp.TokenCount,
					"address":          ipcAddr,
					"runtime_dir":      resp.RuntimeDir,
					"log_file":         resp.LogPath,
					"binary":           resp.BinaryPath,
					"version":          version,
					"protocol_version": daemon.ProtocolVersion,
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}
			fmt.Printf("Status:       running\n")
			fmt.Printf("PID:          %d\n", resp.PID)
			fmt.Printf("Uptime:       %s\n", resp.Uptime)
			fmt.Printf("Tokens:       %d managed\n", resp.TokenCount)
			fmt.Printf("Address:      %s\n", ipcAddr)
			fmt.Printf("Runtime dir:  %s\n", resp.RuntimeDir)
			fmt.Printf("Log file:     %s\n", resp.LogPath)
			fmt.Printf("Version:      %s (protocol v%d)\n", version, daemon.ProtocolVersion)
			if resp.TokenExpiry != nil {
				fmt.Printf("Next expiry:  %s\n", resp.TokenExpiry.Format(time.RFC3339))
			}
			return nil
		},
	}
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "Output as JSON")

	cmd.AddCommand(startCmd, stopCmd, statusCmd)
	return cmd
}

// --- get-token command (shim mode) ---
// NEVER does interactive auth. Returns structured errors on failure.

func getTokenCmd() *cobra.Command {
	var (
		issuerURL      string
		clientID       string
		clientSecret   string
		extraScopes    []string
		extraParams    map[string]string
		requestHeaders map[string]string
		username       string
		grantType      string
		useAccessToken bool
		forceRefresh   bool
	)

	cmd := &cobra.Command{
		Use:   "get-token",
		Short: "Get a token from the daemon (exec credential plugin)",
		RunE: func(cmd *cobra.Command, args []string) error {
			// COMPAT-1/5: Read TLS/redirect/PKCE compat flags for cache key.
			caCert, _ := cmd.Flags().GetStringArray("certificate-authority")
			caCertData, _ := cmd.Flags().GetStringArray("certificate-authority-data")
			skipTLS, _ := cmd.Flags().GetBool("insecure-skip-tls-verify")
			var reneg tls.RenegotiationSupport
			if v, _ := cmd.Flags().GetBool("tls-renegotiation-once"); v {
				reneg = tls.RenegotiateOnceAsClient
			}
			if v, _ := cmd.Flags().GetBool("tls-renegotiation-freely"); v {
				reneg = tls.RenegotiateFreelyAsClient
			}
			tlsCfg := tlsclientconfig.Config{
				CACertFilename: caCert,
				CACertData:     caCertData,
				SkipTLSVerify:  skipTLS,
				Renegotiation:  reneg,
			}
			redirURL, _ := cmd.Flags().GetString("oidc-redirect-url")
			pkceStr, _ := cmd.Flags().GetString("oidc-pkce-method")
			pkceVal := parsePKCEMethod(pkceStr)
			if v, _ := cmd.Flags().GetBool("oidc-use-pkce"); v {
				pkceVal = oidc.PKCEMethodS256
			}

			key := tokencache.Key{
				Provider: oidc.Provider{
					IssuerURL:      issuerURL,
					ClientID:       clientID,
					ClientSecret:   clientSecret,
					ExtraScopes:    extraScopes,
					UseAccessToken: useAccessToken,
					RequestHeaders: requestHeaders,
					RedirectURL:    redirURL,
					PKCEMethod:     pkceVal,
				},
				TLSClientConfig:        tlsCfg,
				Username:               username,
				AuthRequestExtraParams: extraParams,
			}
			cacheKey, err := computeCacheKey(key)
			if err != nil {
				writeUserError("Invalid OIDC configuration. Check kubeconfig exec args.")
				return errAlreadyReported
			}
			// COMPAT-9: Don't call mapGrantType here. The daemon ignores GrantType
			// for get-token (it only does cache lookup + refresh, never interactive auth).
			// Calling mapGrantType prints warnings to stderr on every kubectl call
			// for users with unsupported grant types (password, client-credentials).
			req := daemon.Request{
				IssuerURL:      issuerURL,
				ClientID:       clientID,
				ClientSecret:   clientSecret,
				ExtraScopes:    extraScopes,
				ExtraParams:    extraParams,
				Username:       username,
				UseAccessToken: useAccessToken,
				GrantType:      grantType,
				RequestHeaders: requestHeaders,
				RedirectURL:    redirURL, // COMPAT-CRIT-1: forward for Keycloak refresh
				ForceRefresh:   forceRefresh,
				TLSConfig:      tlsCfg,
			}
			return runGetToken(cmd.Context(), cacheKey, req)
		},
	}

	// --- Flags used by the daemon ---
	cmd.Flags().StringVar(&issuerURL, "oidc-issuer-url", "", "OIDC issuer URL")
	cmd.Flags().StringVar(&clientID, "oidc-client-id", "", "OIDC client ID")
	cmd.Flags().StringVar(&clientSecret, "oidc-client-secret", "", "OIDC client secret")
	// COMPAT-8: Use StringArrayVar (not StringSliceVar) to match upstream pflag behavior.
	// COMPAT-HIGH-2: Use StringSliceVar to match upstream kubelogin (pkg/cmd/get_token.go).
	// StringSliceVar splits on commas, so --oidc-extra-scope=groups,email produces
	// ["groups","email"], same as upstream. StringArrayVar would produce ["groups,email"],
	// causing scope mismatches with the OIDC provider.
	cmd.Flags().StringSliceVar(&extraScopes, "oidc-extra-scope", nil, "Extra OIDC scopes")
	cmd.Flags().StringToStringVar(&extraParams, "oidc-extra-param", nil, "Extra auth request params (key=value)")
	cmd.Flags().StringToStringVar(&extraParams, "oidc-auth-request-extra-params", nil, "Extra auth request params (upstream alias for --oidc-extra-param)")
	cmd.Flags().StringToStringVar(&requestHeaders, "oidc-request-header", nil, "Request headers for OIDC provider (key=value)")
	cmd.Flags().StringVar(&username, "username", "", "Username for ROPC or cache key differentiation")
	cmd.Flags().StringVar(&grantType, "grant-type", "auto", "Grant type (auto, device-code, authcode-browser)")
	cmd.Flags().BoolVar(&useAccessToken, "oidc-use-access-token", false, "Use access token instead of ID token")
	// COMPAT-CRIT-3: Wire --force-refresh to the daemon instead of ignoring it.
	// Users with --force-refresh in kubeconfig expect unconditional refresh.
	cmd.Flags().BoolVar(&forceRefresh, "force-refresh", false, "Force token refresh (skip cache)")
	_ = cmd.MarkFlagRequired("oidc-issuer-url")
	_ = cmd.MarkFlagRequired("oidc-client-id")
	_ = cmd.Flags().MarkHidden("oidc-auth-request-extra-params") // hide upstream alias from help

	// --- Upstream kubelogin flags accepted for compatibility ---
	// These flags exist in kubeconfig exec args written by upstream kubelogin's setup command.
	// The daemon manages auth/cache/TLS internally, so these values are accepted but not used
	// by get-token. They MUST be registered so cobra doesn't reject them.
	registerUpstreamCompatFlags(cmd)

	return cmd
}

// registerUpstreamCompatFlags registers all upstream kubelogin flags that may appear
// in kubeconfig exec args. The daemon doesn't use these values in get-token
// (it manages auth/cache/TLS internally), but they must be accepted so kubectl
// exec credential invocation doesn't fail.
func registerUpstreamCompatFlags(cmd *cobra.Command) {
	// Token cache flags (upstream: pkg/cmd/tokencache.go)
	cmd.Flags().String("token-cache-dir", "", "[upstream compat] Token cache directory (unused by daemon)")
	cmd.Flags().String("token-cache-storage", "", "[upstream compat] Token cache storage (unused by daemon)")

	// TLS flags (upstream: pkg/cmd/tls.go)
	// COMPAT-2: These flags ARE used — they're read in getTokenCmd's RunE closure
	// to build req.TLSConfig for the daemon's OIDCRefresher. The "upstream compat"
	// prefix is kept because they originate from upstream kubelogin's flag set.
	cmd.Flags().StringArray("certificate-authority", nil, "[upstream compat] CA cert path")
	cmd.Flags().StringArray("certificate-authority-data", nil, "[upstream compat] CA cert data")
	cmd.Flags().Bool("insecure-skip-tls-verify", false, "[upstream compat] Skip TLS verify")
	cmd.Flags().Bool("tls-renegotiation-once", false, "[upstream compat] TLS renegotiation once")
	cmd.Flags().Bool("tls-renegotiation-freely", false, "[upstream compat] TLS renegotiation freely")

	// PKCE flags (upstream: pkg/cmd/pkce.go)
	cmd.Flags().String("oidc-pkce-method", "", "[upstream compat] PKCE method (unused by daemon)")
	cmd.Flags().Bool("oidc-use-pkce", false, "[upstream compat] Force PKCE (deprecated, unused by daemon)")

	// Authentication flags (upstream: pkg/cmd/authentication.go)
	cmd.Flags().StringSlice("listen-address", nil, "[upstream compat] Local server bind addresses (unused by daemon)")
	cmd.Flags().Bool("skip-open-browser", false, "[upstream compat] Skip browser open (unused by daemon)")
	cmd.Flags().String("browser-command", "", "[upstream compat] Browser command (unused by daemon)")
	cmd.Flags().Int("authentication-timeout-sec", 0, "[upstream compat] Auth timeout (unused by daemon)")
	cmd.Flags().String("local-server-cert", "", "[upstream compat] Local server cert (unused by daemon)")
	cmd.Flags().String("local-server-key", "", "[upstream compat] Local server key (unused by daemon)")
	cmd.Flags().String("open-url-after-authentication", "", "[upstream compat] Post-auth URL (unused by daemon)")
	// NOTE: --oidc-auth-request-extra-params is registered in getTokenCmd() as an alias
	// for --oidc-extra-param (same variable). It is NOT a no-op compat flag.
	cmd.Flags().String("password", "", "[upstream compat] Password for ROPC (unused by daemon)")

	// OIDC flags (upstream: pkg/cmd/get_token.go)
	// COMPAT-5: This flag IS actively used — it's read in getTokenCmd's RunE closure
	// and forwarded to the daemon for cache key computation and Keycloak refresh compat.
	cmd.Flags().String("oidc-redirect-url", "", "[upstream compat] Redirect URL for OIDC provider")
	cmd.Flags().String("oidc-redirect-url-hostname", "", "[upstream compat] Redirect URL hostname (unused by daemon)")
	// COMPAT-CRIT-1: Upstream kubelogin had --oidc-redirect-url-authcode-keyboard
	// (removed in v1.35.0). Old kubeconfigs may still contain it; without this
	// flag, kubectl exec invocation fails with "unknown flag".
	cmd.Flags().String("oidc-redirect-url-authcode-keyboard", "", "[upstream compat] Keyboard authcode redirect URL (unused by daemon)")
	// COMPAT-CRIT-1: Google OIDC/GKE kubeconfigs may include --oidc-access-type=offline.
	cmd.Flags().String("oidc-access-type", "", "[upstream compat] OIDC access type (unused by daemon)")
	// NOTE: --oidc-request-header is registered in getTokenCmd() as a real flag (forwarded to daemon).
	// NOTE: --force-refresh is registered in getTokenCmd() as a real flag (forwarded to daemon).

	// Verbosity (upstream: klog via logger.AddFlags)
	// COMPAT-MED-1: Use IntP (not CountP). klog accepts -v=5 / --v=5 (integer),
	// but CountP only supports repeated -v -v -v (no = syntax). Kubeconfigs
	// commonly include --v=5, which fails with CountP.
	cmd.Flags().IntP("v", "v", 0, "[upstream compat] Verbosity level (unused by daemon)")

	// Hide all compat flags from help output — they clutter the UX.
	compatFlags := []string{
		"token-cache-dir", "token-cache-storage",
		"certificate-authority", "certificate-authority-data",
		"insecure-skip-tls-verify", "tls-renegotiation-once", "tls-renegotiation-freely",
		"oidc-pkce-method", "oidc-use-pkce",
		"listen-address", "skip-open-browser", "browser-command",
		"authentication-timeout-sec", "local-server-cert", "local-server-key",
		"open-url-after-authentication", "password",
		"oidc-redirect-url", "oidc-redirect-url-hostname", "oidc-redirect-url-authcode-keyboard",
		"oidc-access-type",
		"v",
	}
	for _, name := range compatFlags {
		_ = cmd.Flags().MarkHidden(name)
	}
}

// --- login command ---

func loginCmd() *cobra.Command {
	var f oidcFlags

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate interactively (run in a terminal)",
		Long: `Performs interactive OIDC authentication (device-code or browser flow).
Reads OIDC configuration from kubeconfig by default. Use --context to select
a specific context, or provide explicit flags to override.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := f.resolveFromKubeconfig(cmd); err != nil {
				writeUserError("Cannot read kubeconfig. Check that your kubeconfig is valid.")
				return errAlreadyReported
			}
			if err := f.validate(); err != nil {
				writeUserError("Invalid OIDC configuration. Provide --oidc-issuer-url and --oidc-client-id, or configure kubeconfig.")
				return errAlreadyReported
			}
			return runLogin(cmd.Context(), &f)
		},
	}

	addOIDCFlags(cmd, &f, true, true, false)
	return cmd
}

// --- check command ---

func checkCmd() *cobra.Command {
	var (
		f          oidcFlags
		jsonOutput bool
	)

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check token status (agent preflight)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := f.resolveFromKubeconfig(cmd); err != nil {
				if jsonOutput {
					return outputCheckJSON(false, "NEEDS_LOGIN", daemon.ErrCodeConfigError, err.Error(), "Fix kubeconfig or provide explicit flags", nil, nil)
				}
				writeUserError("Cannot read kubeconfig. Check that your kubeconfig is valid.")
				return errAlreadyReported
			}
			if err := f.validate(); err != nil {
				if jsonOutput {
					return outputCheckJSON(false, "NEEDS_LOGIN", daemon.ErrCodeConfigError, err.Error(), "Provide --oidc-issuer-url and --oidc-client-id", nil, nil)
				}
				writeUserError("Invalid OIDC configuration. Provide --oidc-issuer-url and --oidc-client-id, or configure kubeconfig.")
				return errAlreadyReported
			}
			return runCheck(cmd.Context(), jsonOutput, &f)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output as JSON")
	addOIDCFlags(cmd, &f, true, false, true)
	return cmd
}

// --- refresh command ---

func refreshCmd() *cobra.Command {
	var (
		f     oidcFlags
		quiet bool
	)

	cmd := &cobra.Command{
		Use:   "refresh",
		Short: "Force a token refresh (non-interactive, for cron/scripts)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := f.resolveFromKubeconfig(cmd); err != nil {
				writeUserError("Cannot read kubeconfig. Check that your kubeconfig is valid.")
				return errAlreadyReported
			}
			if err := f.validate(); err != nil {
				writeUserError("Invalid OIDC configuration. Provide --oidc-issuer-url and --oidc-client-id, or configure kubeconfig.")
				return errAlreadyReported
			}
			return runRefresh(cmd.Context(), quiet, &f)
		},
	}

	cmd.Flags().BoolVar(&quiet, "quiet", false, "Suppress output on success")
	addOIDCFlags(cmd, &f, true, true, true)
	return cmd
}

// --- setup command ---

func setupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Configure kubeconfig for kubelogin-daemon",
		Long: `Sets up kubeconfig to use kubelogin-daemon as the exec credential plugin.
Can perform fresh setup or migrate from upstream kubelogin.`,
	}

	// setup (fresh)
	var (
		setupFlags    oidcFlags
		setupUser     string
		setupCluster  string
		skipAuthTest  bool
		dryRun        bool
		installBackup bool
	)
	freshCmd := &cobra.Command{
		Use:   "install",
		Short: "Install kubelogin-daemon into kubeconfig",
		Long: `Configures a kubeconfig user entry to use kubelogin-daemon as the exec
credential plugin. Optionally performs a test authentication.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := setupFlags.validate(); err != nil {
				return err
			}
			return runSetupInstall(cmd.Context(), &setupFlags, setupUser, setupCluster, skipAuthTest, dryRun, installBackup)
		},
	}
	addOIDCFlags(freshCmd, &setupFlags, false, true, false)
	freshCmd.Flags().StringVar(&setupUser, "user", "oidc", "Kubeconfig user name")
	freshCmd.Flags().StringVar(&setupCluster, "cluster", "", "Bind to existing cluster (creates context)")
	freshCmd.Flags().BoolVar(&skipAuthTest, "skip-auth-test", false, "Skip test authentication")
	freshCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print changes without modifying kubeconfig")
	freshCmd.Flags().BoolVar(&installBackup, "backup", true, "Create backup before modifying kubeconfig")
	_ = freshCmd.MarkFlagRequired("oidc-issuer-url")
	_ = freshCmd.MarkFlagRequired("oidc-client-id")

	// setup migrate
	var (
		migrateContext string
		migrateDryRun  bool
		migrateYes     bool
		migrateBackup  bool
	)
	migrateCmd := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate from upstream kubelogin to kubelogin-daemon",
		Long: `Scans kubeconfig for entries using upstream kubelogin and replaces them
with kubelogin-daemon. Creates a backup by default.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSetupMigrate(migrateContext, migrateDryRun, migrateYes, migrateBackup)
		},
	}
	migrateCmd.Flags().StringVar(&migrateContext, "context", "", "Migrate only this context")
	migrateCmd.Flags().BoolVar(&migrateDryRun, "dry-run", false, "Show changes without modifying")
	migrateCmd.Flags().BoolVar(&migrateYes, "yes", false, "Skip confirmation prompt")
	migrateCmd.Flags().BoolVar(&migrateBackup, "backup", true, "Create backup before modifying")

	// setup upgrade
	var (
		upgradeDryRun  bool
		upgradeYes     bool
		upgradeBackup  bool
		upgradeKeepOld bool
	)
	upgradeCmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Update kubeconfig to use this binary, stop old daemon, clean old binary",
		Long: `Scans kubeconfig for entries using kubelogin-daemon at a different path and
updates them to point to this binary. Stops the old daemon and optionally deletes the old binary.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSetupUpgrade(upgradeDryRun, upgradeYes, upgradeBackup, upgradeKeepOld)
		},
	}
	upgradeCmd.Flags().BoolVar(&upgradeDryRun, "dry-run", false, "Show changes without modifying")
	upgradeCmd.Flags().BoolVar(&upgradeYes, "yes", false, "Skip confirmation prompt")
	upgradeCmd.Flags().BoolVar(&upgradeBackup, "backup", true, "Create backup before modifying")
	upgradeCmd.Flags().BoolVar(&upgradeKeepOld, "keep-old", false, "Don't delete the old binary")

	cmd.AddCommand(freshCmd, migrateCmd, upgradeCmd)
	return cmd
}

// --- clean command (COMPAT-CRIT-1: upstream kubelogin has "clean") ---

func cleanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "clean",
		Aliases: []string{"logout"},
		Short:   "Remove cached tokens and stop the daemon",
		Long: `Removes all cached tokens from the daemon and disk, then stops the daemon.
Equivalent to upstream kubelogin's "clean" command.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClean()
		},
	}
	return cmd
}

func runClean() error {
	runtimeDir := daemon.RuntimeDir()

	// Try to shut down the running daemon first.
	if err := shim.SendShutdown(runtimeDir); err == nil {
		fmt.Println("Background service stopped.")
		// Brief wait for daemon to finish shutdown. The new shutdown is instant
		// (no graceful drain), but give it a moment to clean up.
		addr := daemon.TransportAddress(runtimeDir)
		deadline := time.After(3 * time.Second)
		for {
			select {
			case <-deadline:
				goto done
			case <-time.After(100 * time.Millisecond):
				if !daemon.TransportProbeAlive(addr, 500*time.Millisecond) {
					goto done
				}
			}
		}
	done:
	}

	// Remove all persisted token files (.json) from the runtime directory
	entries, err := os.ReadDir(runtimeDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No cached tokens found.")
			return nil
		}
		return fmt.Errorf("read runtime dir: %w", err)
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// ROB-HIGH-2: Only remove files matching the validCacheKey pattern
		// (hex strings + .json). Avoids accidentally deleting non-token .json
		// files that other tools or future versions might write.
		if filepath.Ext(name) == ".json" {
			base := strings.TrimSuffix(name, ".json")
			if !daemon.IsValidCacheKey(base) {
				continue
			}
			path := filepath.Join(runtimeDir, name)
			if err := os.Remove(path); err == nil {
				removed++
			}
		}
	}

	if removed > 0 {
		fmt.Printf("Removed %d cached token(s) from %s\n", removed, runtimeDir)
	} else {
		fmt.Println("No cached tokens found.")
	}
	return nil
}

// --- implementations ---

func runSetupInstall(ctx context.Context, f *oidcFlags, userName, clusterName string, skipAuthTest, dryRun, backup bool) error {
	// Resolve absolute path to our binary
	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve binary path: %w", err)
	}
	binaryPath, err = filepath.EvalSymlinks(binaryPath)
	if err != nil {
		return fmt.Errorf("resolve binary symlinks: %w", err)
	}

	// Build exec args in --flag=value format
	execArgs := []string{"get-token"}
	execArgs = append(execArgs, fmt.Sprintf("--oidc-issuer-url=%s", f.issuerURL))
	execArgs = append(execArgs, fmt.Sprintf("--oidc-client-id=%s", f.clientID))
	if f.clientSecret != "" {
		execArgs = append(execArgs, fmt.Sprintf("--oidc-client-secret=%s", f.clientSecret))
	}
	for _, scope := range f.extraScopes {
		execArgs = append(execArgs, fmt.Sprintf("--oidc-extra-scope=%s", scope))
	}
	for k, v := range f.extraParams {
		execArgs = append(execArgs, fmt.Sprintf("--oidc-extra-param=%s=%s", k, v))
	}
	for k, v := range f.requestHeaders {
		execArgs = append(execArgs, fmt.Sprintf("--oidc-request-header=%s=%s", k, v))
	}
	if f.username != "" {
		execArgs = append(execArgs, fmt.Sprintf("--username=%s", f.username))
	}
	if f.grantType != "" && f.grantType != "auto" {
		execArgs = append(execArgs, fmt.Sprintf("--grant-type=%s", f.grantType))
	}
	if f.useAccessToken {
		execArgs = append(execArgs, "--oidc-use-access-token")
	}

	// Load kubeconfig
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}
	config, err := rules.Load()
	if err != nil {
		return fmt.Errorf("load kubeconfig: %w", err)
	}

	// Build the user entry
	userEntry := &clientcmdapi.AuthInfo{
		Exec: &clientcmdapi.ExecConfig{
			// COMPAT-CRIT-1: Use v1 (not deprecated v1beta1). v1 is stable since
			// Kubernetes 1.22+ and is the default for all modern clusters.
			APIVersion:      "client.authentication.k8s.io/v1",
			Command:         binaryPath,
			Args:            execArgs,
			InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
		},
	}

	if dryRun {
		fmt.Printf("Would configure user %q in kubeconfig:\n", userName)
		fmt.Printf("  command: %s\n", binaryPath)
		fmt.Printf("  args:    %v\n", execArgs)
		fmt.Printf("  interactiveMode: Never\n")
		if clusterName != "" {
			contextName := clusterName
			fmt.Printf("Would create context %q → cluster=%s, user=%s\n", contextName, clusterName, userName)
		}
		return nil
	}

	// Optionally perform test auth
	if !skipAuthTest {
		fmt.Fprintf(os.Stderr, "Testing OIDC authentication...\n")
		provider := oidc.Provider{
			IssuerURL:      f.issuerURL,
			ClientID:       f.clientID,
			ClientSecret:   f.clientSecret,
			ExtraScopes:    f.extraScopes,
			UseAccessToken: f.useAccessToken,
			RequestHeaders: f.requestHeaders,
		}
		grantType, gtErr := mapGrantType(f.grantType)
		if gtErr != nil {
			return fmt.Errorf("test authentication: %w (use --skip-auth-test to skip)", gtErr)
		}
		if grantType == "" {
			grantType = "device-code"
		}
		// ROB-MED-2: Use cmd context so Ctrl+C cancels the test auth flow.
		_, err := shim.PerformAuth(ctx, provider, grantType, shim.AuthOptions{})
		if err != nil {
			return fmt.Errorf("test authentication failed: %w (use --skip-auth-test to skip)", err)
		}
		fmt.Fprintf(os.Stderr, "Authentication successful.\n\n")
	}

	// Write kubeconfig
	config.AuthInfos[userName] = userEntry
	if clusterName != "" {
		if _, ok := config.Clusters[clusterName]; !ok {
			return fmt.Errorf("cluster %q not found in kubeconfig", clusterName)
		}
		contextName := clusterName
		config.Contexts[contextName] = &clientcmdapi.Context{
			Cluster:  clusterName,
			AuthInfo: userName,
		}
	}

	kubeconfigFile := resolveKubeconfigFile()

	// Backup before modifying (skip if file doesn't exist yet)
	if backup && !dryRun {
		if backupPath, err := backupKubeconfig(kubeconfigFile); err != nil {
			return err
		} else if backupPath != "" {
			fmt.Printf("Backup: %s\n", backupPath)
		}
	}

	if err := safeWriteKubeconfig(*config, kubeconfigFile); err != nil {
		return fmt.Errorf("write kubeconfig: %w", err)
	}

	fmt.Printf("Configured user %q in %s\n", userName, kubeconfigFile)
	if clusterName != "" {
		fmt.Printf("Created context %q (cluster=%s, user=%s)\n", clusterName, clusterName, userName)
	}
	fmt.Printf("\nTest: kubectl --user=%s get pods\n", userName)
	return nil
}

func runSetupMigrate(contextFilter string, dryRun, skipConfirm, backup bool) error {
	// Load kubeconfig
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}
	config, err := rules.Load()
	if err != nil {
		return fmt.Errorf("load kubeconfig: %w", err)
	}

	// Resolve our binary path
	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve binary path: %w", err)
	}
	binaryPath, err = filepath.EvalSymlinks(binaryPath)
	if err != nil {
		return fmt.Errorf("resolve binary symlinks: %w", err)
	}

	// Find all users with kubelogin exec config
	type migrateEntry struct {
		userName string
		authInfo *clientcmdapi.AuthInfo
		contexts []string // contexts referencing this user
	}
	var entries []migrateEntry

	for userName, authInfo := range config.AuthInfos {
		if authInfo == nil || authInfo.Exec == nil {
			continue
		}
		base := filepath.Base(authInfo.Exec.Command)
		base = strings.TrimSuffix(base, ".exe") // Windows compatibility
		if base != "kubelogin" && base != "kubectl-oidc_login" {
			continue
		}
		// If context filter, check if any context references this user
		var ctxs []string
		for ctxName, ctxObj := range config.Contexts {
			if ctxObj == nil {
				continue
			}
			if ctxObj.AuthInfo == userName {
				ctxs = append(ctxs, ctxName)
			}
		}
		if contextFilter != "" {
			found := false
			for _, c := range ctxs {
				if c == contextFilter {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		entries = append(entries, migrateEntry{userName: userName, authInfo: authInfo, contexts: ctxs})
	}

	if len(entries) == 0 {
		fmt.Println("No kubelogin entries found in kubeconfig. Nothing to migrate.")
		return nil
	}

	// Show what we found
	fmt.Printf("Found %d user(s) using kubelogin:\n", len(entries))
	for i, e := range entries {
		ctxStr := strings.Join(e.contexts, ", ")
		if ctxStr == "" {
			ctxStr = "(no contexts)"
		}
		fmt.Printf("  %d. user=%s, command=%s, contexts=[%s]\n", i+1, e.userName, e.authInfo.Exec.Command, ctxStr)
	}
	fmt.Println()

	// COMPAT-CRIT-2 / COMPAT-HIGH-1: Warn about incompatible features before migration.
	for _, e := range entries {
		parsed := parseExecArgs(e.authInfo.Exec.Args)
		switch parsed.grantType {
		case "password":
			fmt.Fprintf(os.Stderr, "WARNING: user %q uses grant-type 'password' (ROPC), which is not supported by kubelogin-daemon.\n", e.userName)
			fmt.Fprintf(os.Stderr, "  Passwords cannot be stored. After migration, 'kubelogin-daemon login' will fail for this user.\n")
			fmt.Fprintf(os.Stderr, "  Consider keeping upstream kubelogin for this user, or switch to 'device-code'.\n\n")
		case "client-credentials":
			fmt.Fprintf(os.Stderr, "WARNING: user %q uses grant-type 'client-credentials', which is not supported by kubelogin-daemon.\n", e.userName)
			fmt.Fprintf(os.Stderr, "  Machine-to-machine flows are not supported. Keep upstream kubelogin for this user.\n\n")
		}
		// Check for keyring storage in raw args (parseExecArgs doesn't capture --token-cache-storage)
		for _, arg := range e.authInfo.Exec.Args {
			if strings.Contains(arg, "token-cache-storage") && strings.Contains(arg, "keyring") {
				fmt.Fprintf(os.Stderr, "WARNING: user %q uses keyring token storage, which is not supported by kubelogin-daemon.\n", e.userName)
				fmt.Fprintf(os.Stderr, "  Tokens will be stored in plaintext files in %s instead.\n\n", daemon.RuntimeDir())
				break
			}
		}
	}

	if dryRun {
		fmt.Println("Dry run — would make these changes:")
		for _, e := range entries {
			fmt.Printf("  %s: %s → %s\n", e.userName, e.authInfo.Exec.Command, binaryPath)
			fmt.Printf("  %s: add interactiveMode: Never\n", e.userName)
		}
		printStaleKubeloginDaemonHint(config, binaryPath)
		return nil
	}

	// Confirm
	// ROB-LOW-1: Use bufio.Scanner instead of fmt.Scanln. fmt.Scanln treats
	// spaces as delimiters and silently drops input after the first space.
	// bufio.Scanner reads the full line including spaces.
	if !skipConfirm {
		fmt.Printf("Migrate all to kubelogin-daemon? [Y/n] ")
		scanner := bufio.NewScanner(os.Stdin)
		var answer string
		if scanner.Scan() {
			answer = scanner.Text()
		}
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "" && answer != "y" && answer != "yes" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Backup
	kubeconfigFile := resolveKubeconfigFile()
	if backup {
		backupPath, err := backupKubeconfig(kubeconfigFile)
		if err != nil {
			return err
		}
		if backupPath != "" {
			fmt.Printf("Backup: %s\n\n", backupPath)
		}
	}

	// Migrate
	for _, e := range entries {
		oldCmd := e.authInfo.Exec.Command
		e.authInfo.Exec.Command = binaryPath
		e.authInfo.Exec.InteractiveMode = clientcmdapi.NeverExecInteractiveMode
		fmt.Printf("Migrating %s...\n", e.userName)
		fmt.Printf("  command: %s → %s\n", oldCmd, binaryPath)
		fmt.Printf("  added: interactiveMode: Never\n")
	}

	if err := safeWriteKubeconfig(*config, kubeconfigFile); err != nil {
		return fmt.Errorf("write kubeconfig: %w", err)
	}

	fmt.Printf("\nMigration complete. Run 'kubelogin-daemon login' to authenticate.\n")
	printStaleKubeloginDaemonHint(config, binaryPath)
	return nil
}

// printStaleKubeloginDaemonHint scans the kubeconfig for existing kubelogin-daemon
// entries that point to a different path than the current binary and prints a hint
// suggesting `setup upgrade`. This catches the case where a user has previously
// installed kubelogin-daemon at a different path.
func printStaleKubeloginDaemonHint(config *clientcmdapi.Config, binaryPath string) {
	var stalePaths []string
	seen := make(map[string]bool)
	for _, authInfo := range config.AuthInfos {
		if authInfo == nil || authInfo.Exec == nil {
			continue
		}
		if !isKubeloginDaemonCommand(authInfo.Exec.Command) {
			continue
		}
		oldPath := authInfo.Exec.Command
		resolved := oldPath
		if r, err := filepath.EvalSymlinks(oldPath); err == nil {
			resolved = r
		}
		if resolved != binaryPath && !seen[oldPath] {
			seen[oldPath] = true
			stalePaths = append(stalePaths, oldPath)
		}
	}
	if len(stalePaths) > 0 {
		fmt.Printf("\nNote: Found %d existing kubelogin-daemon entry(s) at stale path(s):\n", len(stalePaths))
		for _, p := range stalePaths {
			fmt.Printf("  %s\n", p)
		}
		fmt.Println("Run 'kubelogin-daemon setup upgrade' to update them to the current binary.")
	}
}

// backupKubeconfig creates a timestamped backup of the kubeconfig file.
// Returns the backup path, or "" if the source file doesn't exist.
func backupKubeconfig(kubeconfigFile string) (string, error) {
	data, err := os.ReadFile(kubeconfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // nothing to backup
		}
		return "", fmt.Errorf("read kubeconfig for backup: %w", err)
	}
	backupPath := kubeconfigFile + ".bak." + time.Now().Format("20060102T150405.000000000")
	if err := safeWriteFile(backupPath, data, 0600); err != nil {
		return "", fmt.Errorf("write backup: %w", err)
	}
	return backupPath, nil
}

// isKubeloginDaemonCommand checks if an exec command basename starts with "kubelogin-daemon".
// This matches variants like kubelogin-daemon-new, kubelogin-daemon-v2,
// kubelogin-daemon-linux-amd64, etc.
func isKubeloginDaemonCommand(command string) bool {
	base := filepath.Base(command)
	base = strings.TrimSuffix(base, ".exe")
	return strings.HasPrefix(base, "kubelogin-daemon")
}

// hasMultipleKubeconfigs checks if KUBECONFIG env contains multiple existing files.
func hasMultipleKubeconfigs() bool {
	env := os.Getenv("KUBECONFIG")
	if env == "" {
		return false
	}
	paths := filepath.SplitList(env)
	var existing int
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			existing++
		}
	}
	return existing > 1
}

func runSetupUpgrade(dryRun, skipConfirm, backup, keepOld bool) error {
	// Resolve current binary path
	newPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve binary path: %w", err)
	}
	newPath, err = filepath.EvalSymlinks(newPath)
	if err != nil {
		return fmt.Errorf("resolve binary symlinks: %w", err)
	}

	// Reject multiple kubeconfig files (unless --kubeconfig is explicit)
	if kubeconfigPath == "" && hasMultipleKubeconfigs() {
		return fmt.Errorf("multiple kubeconfig files detected (KUBECONFIG=%s); specify --kubeconfig to pick one", os.Getenv("KUBECONFIG"))
	}

	// Load kubeconfig
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}
	config, err := rules.Load()
	if err != nil {
		return fmt.Errorf("load kubeconfig: %w", err)
	}

	// Find stale kubelogin-daemon entries (command path differs from current binary)
	type upgradeEntry struct {
		userName string
		oldPath  string
	}
	newInfo, newInfoErr := os.Stat(newPath)
	var stale []upgradeEntry
	for userName, authInfo := range config.AuthInfos {
		if authInfo == nil || authInfo.Exec == nil {
			continue
		}
		if !isKubeloginDaemonCommand(authInfo.Exec.Command) {
			continue
		}
		// Compare via EvalSymlinks first, then os.SameFile for hardlink detection
		oldResolved := authInfo.Exec.Command
		if resolved, err := filepath.EvalSymlinks(authInfo.Exec.Command); err == nil {
			oldResolved = resolved
		}
		if oldResolved == newPath {
			continue // same resolved path
		}
		// Check for hardlinks (same inode, different path)
		if newInfoErr == nil {
			if oldInfo, err := os.Stat(authInfo.Exec.Command); err == nil && os.SameFile(oldInfo, newInfo) {
				continue // same file via hardlink
			}
		}
		stale = append(stale, upgradeEntry{userName: userName, oldPath: authInfo.Exec.Command})
	}

	if len(stale) == 0 {
		// Check if there are ANY kubelogin-daemon entries at all
		found := false
		for _, authInfo := range config.AuthInfos {
			if authInfo != nil && authInfo.Exec != nil && isKubeloginDaemonCommand(authInfo.Exec.Command) {
				found = true
				break
			}
		}
		if !found {
			fmt.Println("No kubelogin-daemon entries found in kubeconfig. Use 'kubelogin-daemon setup install' first.")
			return nil
		}
		// Same-path upgrade: kubeconfig already points to this binary, but the
		// binary content may have changed (user replaced the file in place).
		// Stop the running daemon so the next kubectl call auto-starts the new binary.
		fmt.Println("Kubeconfig already points to this binary.")
		if dryRun {
			fmt.Println("Would stop running daemon (so the new binary takes effect on next kubectl call).")
			return nil
		}
		fmt.Println("Stopping running daemon so the new binary takes effect...")
		runtimeDir := daemon.RuntimeDir()
		addr := daemon.TransportAddress(runtimeDir)
		if !daemon.TransportProbeAlive(addr, 1*time.Second) {
			fmt.Println("No daemon running.")
		} else if err := shim.SendShutdown(runtimeDir); err != nil {
			if killErr := killDaemonProcess(runtimeDir); killErr != nil {
				fmt.Fprintf(os.Stderr, "Note: could not stop daemon (IPC: %v, kill: %v)\n", err, killErr)
			} else {
				fmt.Println("Daemon stopped (via process kill).")
			}
		} else {
			for i := 0; i < 10; i++ {
				time.Sleep(100 * time.Millisecond)
				if !daemon.TransportProbeAlive(addr, 500*time.Millisecond) {
					break
				}
			}
			fmt.Println("Daemon stopped.")
		}
		fmt.Println("\nUpgrade complete. Next kubectl call will auto-start the new binary.")
		return nil
	}

	// Show planned changes
	fmt.Printf("Found %d stale kubelogin-daemon entry(s):\n", len(stale))
	for i, e := range stale {
		fmt.Printf("  %d. user=%s\n", i+1, e.userName)
		fmt.Printf("     %s → %s\n", e.oldPath, newPath)
	}
	fmt.Println()

	if dryRun {
		fmt.Println("Dry run — no changes made.")
		for _, e := range stale {
			fmt.Printf("Would update user %s: %s → %s\n", e.userName, e.oldPath, newPath)
		}
		fmt.Println("Would stop old daemon")
		if !keepOld {
			var rawOldPaths []string
			for _, e := range stale {
				rawOldPaths = append(rawOldPaths, e.oldPath)
			}
			oldPaths := collectUniqueOldPaths(rawOldPaths, newPath)
			for _, p := range oldPaths {
				fmt.Printf("Would delete old binary: %s\n", p)
			}
		}
		return nil
	}

	// Confirm
	if !skipConfirm {
		fmt.Printf("Update kubeconfig and clean up? [Y/n] ")
		scanner := bufio.NewScanner(os.Stdin)
		var answer string
		if scanner.Scan() {
			answer = scanner.Text()
		}
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "" && answer != "y" && answer != "yes" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Check kubeconfig is writable before making changes
	kubeconfigFile := resolveKubeconfigFile()
	if info, err := os.Stat(kubeconfigFile); err == nil {
		if info.Mode()&0200 == 0 {
			return fmt.Errorf("kubeconfig %s is read-only; fix permissions first", kubeconfigFile)
		}
	}

	// Backup kubeconfig
	if backup {
		backupPath, err := backupKubeconfig(kubeconfigFile)
		if err != nil {
			return err
		}
		if backupPath != "" {
			fmt.Printf("Backup: %s\n\n", backupPath)
		}
	}

	// Update kubeconfig entries
	for _, e := range stale {
		authInfo := config.AuthInfos[e.userName]
		authInfo.Exec.Command = newPath
		fmt.Printf("Updated %s: %s → %s\n", e.userName, e.oldPath, newPath)
	}

	if err := safeWriteKubeconfig(*config, kubeconfigFile); err != nil {
		return fmt.Errorf("write kubeconfig: %w", err)
	}
	fmt.Println("Kubeconfig updated.")

	// Stop old daemon (best-effort, don't fail the upgrade).
	// Try IPC shutdown first (clean shutdown). If that fails (socket gone,
	// protocol mismatch), fall back to PID-based kill.
	runtimeDir := daemon.RuntimeDir()
	addr := daemon.TransportAddress(runtimeDir)
	if !daemon.TransportProbeAlive(addr, 1*time.Second) {
		// No daemon running — nothing to stop.
	} else if err := shim.SendShutdown(runtimeDir); err != nil {
		// IPC shutdown failed — try PID-based kill as fallback.
		if killErr := killDaemonProcess(runtimeDir); killErr != nil {
			fmt.Fprintf(os.Stderr, "Note: could not stop old daemon (IPC: %v, kill: %v)\n", err, killErr)
		} else {
			fmt.Println("Old daemon stopped (via process kill).")
		}
	} else {
		// Shutdown was accepted — verify daemon actually exited.
		for i := 0; i < 10; i++ {
			time.Sleep(100 * time.Millisecond)
			if !daemon.TransportProbeAlive(addr, 500*time.Millisecond) {
				break
			}
		}
		fmt.Println("Old daemon stopped.")
	}

	// Delete old binaries (best-effort)
	if !keepOld {
		var rawOldPaths []string
		for _, e := range stale {
			rawOldPaths = append(rawOldPaths, e.oldPath)
		}
		oldPaths := collectUniqueOldPaths(rawOldPaths, newPath)
		for _, oldPath := range oldPaths {
			if err := deleteOldBinary(oldPath, newPath); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not delete old binary %s: %v\n", oldPath, err)
			} else {
				fmt.Printf("Deleted old binary: %s\n", oldPath)
			}
		}
	}

	fmt.Println("\nUpgrade complete. Next kubectl call will use the new binary.")
	return nil
}

// getDaemonPID attempts to get the running daemon's PID via IPC health check.
// Returns 0 if the daemon is unreachable or doesn't report a PID.
func getDaemonPID(runtimeDir string) int {
	resp, err := shim.SendHealth(runtimeDir)
	if err != nil {
		return 0
	}
	return resp.PID
}

// killDaemonProcess attempts to find and kill a running kubelogin-daemon process.
// This is a best-effort fallback when IPC shutdown fails (e.g., socket gone).
// Uses PID-based kill to avoid killing unrelated processes (including the
// upgrade process itself, which would also match a name-based kill).
//
// Strategy: try IPC health first (fast, reliable when nonce matches). If that
// fails (stale daemon with wrong nonce), fall back to findPIDBySocket which
// scans /proc (Linux) or uses lsof (macOS/fallback).
func killDaemonProcess(runtimeDir string) error {
	pid := getDaemonPID(runtimeDir)
	if pid <= 0 {
		// IPC failed (nonce mismatch, no daemon, etc). Try socket-based PID lookup.
		socketPath := daemon.TransportAddress(runtimeDir)
		pid = findPIDBySocket(socketPath)
	}
	if pid <= 0 {
		return fmt.Errorf("could not determine daemon PID")
	}
	// Safety: never kill ourselves
	if pid == os.Getpid() {
		return fmt.Errorf("refusing to kill own process (PID %d)", pid)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}
	if err := proc.Kill(); err != nil {
		return fmt.Errorf("kill process %d: %w", pid, err)
	}
	return nil
}

// ensureHealthyDaemon verifies the daemon is running and responsive, or starts one.
// If a stale daemon is detected (e.g., nonce mismatch from failed upgrade), kills
// it and starts a fresh one. This prevents the scenario where login succeeds at the
// OIDC provider but StoreToken fails because the daemon rejects all IPC.
func ensureHealthyDaemon(runtimeDir string) error {
	resp, err := shim.SendHealth(runtimeDir)
	if err != nil {
		// Connection failed — no daemon or transport gone. Auto-start.
		return shim.AutoStartDaemon(runtimeDir)
	}
	if resp.Status == "ok" {
		return nil // Daemon is healthy
	}
	// Daemon responded but with error (e.g., "invalid nonce"). Kill and restart.
	_ = killDaemonProcess(runtimeDir)
	addr := daemon.TransportAddress(runtimeDir)
	for i := 0; i < 10; i++ {
		if !daemon.TransportProbeAlive(addr, 500*time.Millisecond) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return shim.AutoStartDaemon(runtimeDir)
}

// collectUniqueOldPaths returns deduplicated old binary paths that differ from newPath.
func collectUniqueOldPaths(oldPaths []string, newPath string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, p := range oldPaths {
		resolved := p
		if r, err := filepath.EvalSymlinks(p); err == nil {
			resolved = r
		}
		if resolved == newPath {
			continue
		}
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}

// deleteOldBinary safely deletes the old binary at oldPath.
func deleteOldBinary(oldPath, newPath string) error {
	// Verify basename starts with kubelogin-daemon (matches isKubeloginDaemonCommand)
	base := filepath.Base(oldPath)
	base = strings.TrimSuffix(base, ".exe")
	if !strings.HasPrefix(base, "kubelogin-daemon") {
		return fmt.Errorf("refusing to delete %s (not a kubelogin-daemon binary)", oldPath)
	}

	// Resolve both paths to catch symlinks to same file
	oldResolved, err := filepath.EvalSymlinks(oldPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // already gone
		}
		return err
	}
	newResolved, err := filepath.EvalSymlinks(newPath)
	if err != nil {
		return err
	}
	if oldResolved == newResolved {
		return nil // same file via symlink, don't delete
	}
	// Also check for hardlinks (same inode, different path)
	oldInfo, err := os.Stat(oldPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	newInfo, err := os.Stat(newPath)
	if err != nil {
		return err
	}
	if os.SameFile(oldInfo, newInfo) {
		return nil // same file via hardlink, don't delete
	}

	// If oldPath is a symlink, remove the symlink only
	if info, err := os.Lstat(oldPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return os.Remove(oldPath)
	}

	return os.Remove(oldPath)
}

func runDaemonStart(ctx context.Context, verbose bool, idleTimeout time.Duration) error {
	runtimeDir := daemon.RuntimeDir()

	// Pre-check: reject symlink at runtime dir before creating any files there.
	// ListenAndServe also checks, but the logger is created first and would
	// follow a symlink to write logs outside the intended directory.
	if info, err := os.Lstat(runtimeDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("runtime dir %s is a symlink (possible attack, refusing to start)", runtimeDir)
		}
	}

	// ROB-CRIT-1: Use os.Mkdir (not MkdirAll) to avoid following symlinks in
	// intermediate path components. ListenAndServe also calls os.Mkdir +
	// validateRuntimeDirSecurity, but the logger is created first and needs
	// the directory to exist.
	if err := os.Mkdir(runtimeDir, 0700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create runtime dir: %w", err)
	}
	// Migrate tokens from legacy TMPDIR-dependent path (one-time, on upgrade).
	daemon.MigrateTokensFromLegacyDir(runtimeDir)

	logger, err := daemon.NewLogger(runtimeDir, verbose)
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}
	defer logger.Close()

	srv := daemon.NewServer(daemon.ServerConfig{
		RuntimeDir:  runtimeDir,
		Logger:      logger,
		IdleTimeout: idleTimeout,
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe(ctx)
	}()

	select {
	case err := <-errCh:
		// If another daemon already holds the socket (EADDRINUSE),
		// exit cleanly — the existing daemon is serving requests.
		if err != nil && isAddrInUse(err) {
			fmt.Fprintf(os.Stderr, "another daemon is already running\n")
			// B1: Exit with code 1 (failure) so parent processes and autostart
			// code can distinguish "bind failed" from "shutdown cleanly".
			os.Exit(1)
		}
		// ROB-CRIT-1: Persist tokens before returning on fatal accept error.
		// Without this, all in-memory token state (including newer refresh
		// tokens from recent refreshes) is lost.
		srv.Shutdown()
		return err
	case <-ctx.Done():
		srv.Shutdown()
		return nil
	}
}

func runGetToken(_ context.Context, cacheKey string, req daemon.Request) error {
	runtimeDir := daemon.RuntimeDir()

	resp, err := shim.GetTokenFromDaemon(runtimeDir, cacheKey, req)
	if err != nil {
		writeUserError("Not authenticated. Run 'kubelogin-daemon login' to log in.")
		return errAlreadyReported
	}

	switch resp.Status {
	case "ok":
		return writeExecCredential(resp.Token, resp.Expiry)
	case "needs-auth":
		writeUserError("Not authenticated. Run 'kubelogin-daemon login' to log in.")
		return errAlreadyReported
	case "login-in-progress":
		writeUserError("Login in progress. Wait a moment and retry.")
		return errAlreadyReported
	case "error":
		if resp.ErrorCode == daemon.ErrCodeTokenRevoked || resp.ErrorCode == daemon.ErrCodeRefreshFailed {
			writeUserError("Session expired. Run 'kubelogin-daemon login' to re-authenticate.")
		} else {
			writeUserError("Not authenticated. Run 'kubelogin-daemon login' to log in.")
		}
		return errAlreadyReported
	default:
		writeUserError("Not authenticated. Run 'kubelogin-daemon login' to log in.")
		return errAlreadyReported
	}
}

func runLogin(ctx context.Context, f *oidcFlags) error {
	cacheKey, err := f.buildCacheKey()
	if err != nil {
		writeUserError("Invalid OIDC configuration. Check kubeconfig or provide --oidc-issuer-url and --oidc-client-id.")
		return errAlreadyReported
	}
	runtimeDir := daemon.RuntimeDir()

	// Ensure a healthy daemon is running. If the existing daemon has a stale
	// nonce (e.g., after a failed upgrade), kill it and start fresh.
	if err := ensureHealthyDaemon(runtimeDir); err != nil {
		writeUserError("Cannot start background service. Check that kubelogin-daemon is installed correctly.")
		return errAlreadyReported
	}

	// Begin login — coordinate with daemon state machine.
	// If a previous login is stuck (e.g., SSH session died mid-flow), cancel it
	// and start fresh. The user expects `login` to always show a URL immediately.
	beginResp, err := shim.SendBeginLogin(runtimeDir, cacheKey)
	if err != nil {
		writeUserError("Cannot connect to background service. Try again.")
		return errAlreadyReported
	}
	if beginResp.Status == "login-in-progress" {
		// Cancel the stuck login and retry
		_, _ = shim.SendCancelLogin(runtimeDir, cacheKey)
		beginResp, err = shim.SendBeginLogin(runtimeDir, cacheKey)
		if err != nil {
			writeUserError("Cannot connect to background service. Try again.")
			return errAlreadyReported
		}
		if beginResp.Status == "login-in-progress" {
			// Still stuck after cancel — force restart
			_ = shim.SendShutdown(runtimeDir)
			time.Sleep(300 * time.Millisecond)
			if err := shim.AutoStartDaemon(runtimeDir); err != nil {
				writeUserError("Cannot start background service. Check that kubelogin-daemon is installed correctly.")
				return errAlreadyReported
			}
			beginResp, err = shim.SendBeginLogin(runtimeDir, cacheKey)
			if err != nil {
				writeUserError("Cannot connect to background service. Try again.")
				return errAlreadyReported
			}
		}
	}

	// Set up Ctrl+C handler to send cancel-login
	loginCtx, loginCancel := context.WithCancel(ctx)
	defer loginCancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			fmt.Fprintf(os.Stderr, "\nLogin interrupted, cancelling...\n")
			_, _ = shim.SendCancelLogin(runtimeDir, cacheKey)
			loginCancel()
		case <-loginCtx.Done():
		}
	}()
	defer signal.Stop(sigCh)

	// Perform the interactive auth flow
	// COMPAT-MED-1: Include RedirectURL so the OIDC client factory uses
	// the user-configured redirect URL for the authcode callback server.
	provider := oidc.Provider{
		IssuerURL:      f.issuerURL,
		ClientID:       f.clientID,
		ClientSecret:   f.clientSecret,
		ExtraScopes:    f.extraScopes,
		UseAccessToken: f.useAccessToken,
		RequestHeaders: f.requestHeaders,
		RedirectURL:    f.redirectURL,
	}

	// COMPAT-1: Warn if --oidc-redirect-url-hostname is set but not used.
	// This flag is deprecated in upstream kubelogin and not supported by the daemon.
	// Users should use --listen-address instead.
	if f.redirectURLHostname != "" {
		fmt.Fprintf(os.Stderr, "[KUBELOGIN] WARNING: --oidc-redirect-url-hostname=%q is not supported by kubelogin-daemon.\n", f.redirectURLHostname)
		fmt.Fprintf(os.Stderr, "[KUBELOGIN] Use --listen-address to control the callback server bind address instead.\n")
	}

	// COMPAT-HIGH-1: Warn if keyring storage was configured in kubeconfig.
	// The daemon stores tokens in plaintext files, not in the OS keyring.
	if strings.EqualFold(f.tokenCacheStorage, "keyring") {
		fmt.Fprintf(os.Stderr, "[KUBELOGIN] WARNING: --token-cache-storage=keyring is not supported by kubelogin-daemon.\n")
		fmt.Fprintf(os.Stderr, "[KUBELOGIN] Tokens will be stored in plaintext files in %s.\n", daemon.RuntimeDir())
	}

	// SEC-MED-7: Warn when TLS verification is disabled.
	// This allows MITM of all OIDC traffic (discovery, token exchange, refresh).
	if f.tlsConfig.SkipTLSVerify {
		fmt.Fprintf(os.Stderr, "[KUBELOGIN] WARNING: --insecure-skip-tls-verify is enabled. All OIDC connections are vulnerable to MITM.\n")
	}

	// Forward all upstream auth options to the auth flow.
	authOpts := shim.AuthOptions{
		SkipOpenBrowser:            f.skipOpenBrowser,
		AuthenticationTimeout:      f.authenticationTimeoutSec,
		ListenAddress:              f.listenAddress,
		BrowserCommand:             f.browserCommand,
		LocalServerCertFile:        f.localServerCertFile,
		LocalServerKeyFile:         f.localServerKeyFile,
		OpenURLAfterAuthentication: f.openURLAfterAuthentication,
		AuthRequestExtraParams:     f.extraParams,
		TLSConfig:                  f.tlsConfig,
	}
	mappedGrant, gtErr := mapGrantType(f.grantType)
	if gtErr != nil {
		_, _ = shim.SendCancelLogin(runtimeDir, cacheKey)
		writeUserError(fmt.Sprintf("Unsupported grant type %q. Use 'device-code' or 'authcode-browser'.", f.grantType))
		return errAlreadyReported
	}
	// Device-code flow is terminal-only by design: print URL + code, user opens
	// any browser on any device. Never auto-open a browser — it defeats the
	// purpose and fails in headless/SSH/container environments.
	if mappedGrant == "device-code" {
		authOpts.SkipOpenBrowser = true
	}
	tokenSet, err := shim.PerformAuth(loginCtx, provider, mappedGrant, authOpts)
	if err != nil {
		_, _ = shim.SendCancelLogin(runtimeDir, cacheKey)
		if loginCtx.Err() != nil {
			return errAlreadyReported // Ctrl+C, already printed "Login interrupted"
		}
		writeUserError(fmt.Sprintf("Authentication failed: %v", err))
		return errAlreadyReported
	}

	// Store the token in the daemon
	// COMPAT-CRIT-2: Include TLS config so the daemon's OIDCRefresher can
	// perform subsequent refreshes with the correct TLS settings.
	req := daemon.Request{
		IssuerURL:      f.issuerURL,
		ClientID:       f.clientID,
		ClientSecret:   f.clientSecret,
		ExtraScopes:    f.extraScopes,
		ExtraParams:    f.extraParams,
		Username:       f.username,
		UseAccessToken: f.useAccessToken,
		GrantType:      f.grantType,
		RequestHeaders: f.requestHeaders,
		RedirectURL:    f.redirectURL, // CRIT-2: Required for Keycloak strict redirect_uri on refresh
		TLSConfig:      f.tlsConfig,
	}
	storeResp, err := shim.StoreToken(runtimeDir, cacheKey, req, tokenSet.IDToken, tokenSet.RefreshToken)
	if err != nil || storeResp.Status != "ok" {
		// StoreToken failed — likely a stale daemon with wrong nonce, or daemon
		// died during the auth flow. Kill stale daemon, start fresh, retry once.
		fmt.Fprintf(os.Stderr, "[KUBELOGIN] Token store failed, restarting daemon and retrying...\n")
		_ = killDaemonProcess(runtimeDir)
		// Wait for transport to go away
		addr := daemon.TransportAddress(runtimeDir)
		for i := 0; i < 10; i++ {
			if !daemon.TransportProbeAlive(addr, 500*time.Millisecond) {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if err := shim.AutoStartDaemon(runtimeDir); err != nil {
			writeUserError("Login succeeded but failed to save token: cannot restart daemon.")
			return errAlreadyReported
		}
		storeResp, err = shim.StoreToken(runtimeDir, cacheKey, req, tokenSet.IDToken, tokenSet.RefreshToken)
		if err != nil || storeResp.Status != "ok" {
			writeUserError("Login succeeded but failed to save token after daemon restart.")
			return errAlreadyReported
		}
	}

	fmt.Fprintf(os.Stderr, "Login successful. Token expires %s\n", storeResp.Expiry.Format(time.RFC3339))
	return nil
}

func runCheck(_ context.Context, jsonOutput bool, f *oidcFlags) error {
	cacheKey, err := f.buildCacheKey()
	if err != nil {
		if jsonOutput {
			return outputCheckJSON(false, "NEEDS_LOGIN", daemon.ErrCodeConfigError, "Failed to compute cache key", "Check OIDC configuration", nil, nil)
		}
		writeUserError("Invalid OIDC configuration. Check kubeconfig or provide --oidc-issuer-url and --oidc-client-id.")
		return errAlreadyReported
	}

	runtimeDir := daemon.RuntimeDir()

	// Auto-start daemon if not running
	if _, err := shim.SendHealth(runtimeDir); err != nil {
		if err := shim.AutoStartDaemon(runtimeDir); err != nil {
			if jsonOutput {
				daemonRunning := false
				return outputCheckJSON(false, "NEEDS_LOGIN", daemon.ErrCodeDaemonStartFailed, "Cannot start background service", "Run 'kubelogin-daemon login'", &daemonRunning, nil)
			}
			writeUserError("Cannot start background service. Run 'kubelogin-daemon login' to authenticate.")
			return errAlreadyReported
		}
	}

	resp, err := shim.SendCheck(runtimeDir, cacheKey)
	if err != nil {
		if jsonOutput {
			daemonRunning := false
			return outputCheckJSON(false, "NEEDS_LOGIN", daemon.ErrCodeDaemonStartFailed, "Cannot reach background service", "Run 'kubelogin-daemon login'", &daemonRunning, nil)
		}
		writeUserError("Cannot connect to background service. Run 'kubelogin-daemon login' to authenticate.")
		return errAlreadyReported
	}

	if jsonOutput {
		// Output the daemon's response directly as JSON
		out := map[string]any{
			"ready":          resp.Ready != nil && *resp.Ready,
			"state":          resp.State,
			"daemon_running": resp.DaemonRunning != nil && *resp.DaemonRunning,
		}
		if resp.AccessTokenExpiry != nil {
			out["access_token_expires"] = resp.AccessTokenExpiry.Format(time.RFC3339)
		}
		if resp.RefreshTokenValid != nil {
			out["refresh_token_valid"] = *resp.RefreshTokenValid
		}
		if resp.ErrorCode != "" {
			out["error"] = resp.ErrorCode
		}
		if resp.Message != "" {
			out["message"] = resp.Message
		}
		if resp.Action != "" {
			out["action"] = resp.Action
		}
		if resp.LoginStartedAt != nil {
			out["login_started_at"] = resp.LoginStartedAt.Format(time.RFC3339)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return err
		}
		if resp.Ready == nil || !*resp.Ready {
			os.Exit(1)
		}
		return nil
	}

	// Human-readable output
	if resp.Ready != nil && *resp.Ready {
		fmt.Printf("Token is valid")
		if resp.AccessTokenExpiry != nil {
			fmt.Printf(" (expires %s)", resp.AccessTokenExpiry.Format(time.RFC3339))
		}
		fmt.Println()
		return nil
	}

	fmt.Printf("Not ready: %s\n", resp.State)
	if resp.Message != "" {
		fmt.Printf("  %s\n", resp.Message)
	}
	if resp.Action != "" {
		fmt.Printf("  Action: %s\n", resp.Action)
	}
	os.Exit(1)
	return nil
}

func runRefresh(_ context.Context, quiet bool, f *oidcFlags) error {
	cacheKey, err := f.buildCacheKey()
	if err != nil {
		writeUserError("Invalid OIDC configuration. Check kubeconfig or provide --oidc-issuer-url and --oidc-client-id.")
		return errAlreadyReported
	}

	runtimeDir := daemon.RuntimeDir()

	// Auto-start daemon if not running
	if _, err := shim.SendHealth(runtimeDir); err != nil {
		if err := shim.AutoStartDaemon(runtimeDir); err != nil {
			writeUserError("Cannot start background service. Run 'kubelogin-daemon login' to authenticate.")
			return errAlreadyReported
		}
	}

	providerReq := daemon.Request{
		IssuerURL:      f.issuerURL,
		ClientID:       f.clientID,
		ClientSecret:   f.clientSecret,
		ExtraScopes:    f.extraScopes,
		ExtraParams:    f.extraParams,
		Username:       f.username,
		UseAccessToken: f.useAccessToken,
		GrantType:      f.grantType,
		RequestHeaders: f.requestHeaders,
		RedirectURL:    f.redirectURL, // ROB-1: Required for Keycloak strict redirect_uri on refresh
		TLSConfig:      f.tlsConfig,
	}

	resp, err := shim.SendRefresh(runtimeDir, cacheKey, providerReq)
	if err != nil {
		writeUserError("Cannot connect to background service. Try again or run 'kubelogin-daemon login'.")
		return errAlreadyReported
	}

	switch resp.Status {
	case "ok":
		if !quiet {
			if resp.Refreshed != nil && *resp.Refreshed {
				fmt.Printf("Token refreshed. Expires %s\n", resp.Expiry.Format(time.RFC3339))
			} else {
				fmt.Println(resp.Message)
			}
		}
		return nil
	case "error":
		if resp.ErrorCode == daemon.ErrCodeNeedsLogin || resp.ErrorCode == daemon.ErrCodeTokenExpired || resp.ErrorCode == daemon.ErrCodeTokenRevoked {
			writeUserError("Session expired. Run 'kubelogin-daemon login' to re-authenticate.")
			return errAlreadyReported
		}
		writeUserError(fmt.Sprintf("Refresh failed: %s", resp.Error))
		return errAlreadyReported
	default:
		writeUserError("Unexpected error. Try again or run 'kubelogin-daemon login'.")
		return errAlreadyReported
	}
}

// --- helpers ---

// resolveKubeconfigFile returns the path to write kubeconfig to.
// Priority: --kubeconfig flag > $KUBECONFIG (first entry) > ~/.kube/config.
func resolveKubeconfigFile() string {
	if kubeconfigPath != "" {
		return kubeconfigPath
	}
	if env := os.Getenv("KUBECONFIG"); env != "" {
		// KUBECONFIG can be colon-separated; use the first entry for writes
		parts := filepath.SplitList(env)
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
	}
	return clientcmd.RecommendedHomeFile
}

// safeWriteFile writes data to path, rejecting symlinks at the destination
// and in parent path components. Uses atomic write (temp file + rename).
func safeWriteFile(path string, data []byte, perm os.FileMode) error {
	// Canonicalize to resolve any parent symlinks, then compare
	canonical, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("resolve parent path: %w", err)
	}
	if canonical != "" && canonical != filepath.Dir(path) {
		// Parent contains symlinks — use the canonical path for the write
		path = filepath.Join(canonical, filepath.Base(path))
	}
	// Reject if destination itself is a symlink
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write to symlink at %s", path)
		}
	}
	// Write to temp file in same directory, then atomic rename
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".kubeconfig-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := f.Name()
	// Track whether we successfully renamed — only clean up temp file on error
	renamed := false
	defer func() {
		if !renamed {
			f.Close()
			os.Remove(tmpPath)
		}
	}()
	if err := f.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	// ADD-5: Fsync before rename to ensure data is on disk. Without this,
	// a power failure between write and rename could result in a corrupted
	// kubeconfig (empty or partial file at the target path).
	if err := f.Sync(); err != nil {
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp to target: %w", err)
	}
	renamed = true
	return nil
}

// safeWriteKubeconfig writes a kubeconfig to path with symlink protection and atomic write.
func safeWriteKubeconfig(config clientcmdapi.Config, path string) error {
	data, err := clientcmd.Write(config)
	if err != nil {
		return fmt.Errorf("serialize kubeconfig: %w", err)
	}
	return safeWriteFile(path, data, 0600)
}

func writeExecCredential(token string, expiry time.Time) error {
	apiVersion := "client.authentication.k8s.io/v1"
	if envInfo := os.Getenv("KUBERNETES_EXEC_INFO"); envInfo != "" {
		var execInfo struct {
			APIVersion string `json:"apiVersion"`
		}
		if err := json.Unmarshal([]byte(envInfo), &execInfo); err == nil && execInfo.APIVersion != "" {
			apiVersion = execInfo.APIVersion
		}
	}

	out := credentialplugin.Output{
		Token:                          token,
		Expiry:                         expiry,
		ClientAuthenticationAPIVersion: apiVersion,
	}
	w := &credentialpluginwriter.Writer{Stdout: stdio.Stdout(os.Stdout)}
	return w.Write(out)
}

// writeUserError writes a single-line, user-friendly error to stderr.
// The message should be a complete sentence telling the user what happened
// and what to do next. No error codes, no internal details, no socket paths.
func writeUserError(message string) {
	fmt.Fprintf(os.Stderr, "[KUBELOGIN] %s\n", message)
}

// computeCacheKey creates a deterministic cache key using the same tokencache.Key
// and gob-based hashing as upstream kubelogin, ensuring cache compatibility.
// COMPAT-1/COMPAT-5: All fields of tokencache.Key (including TLSClientConfig,
// Provider.RedirectURL, and Provider.PKCEMethod) must be populated for the
// hash to match upstream kubelogin and for consistent keys across daemon commands.
func computeCacheKey(key tokencache.Key) (string, error) {
	return tokencacherepository.ComputeChecksum(key)
}

// isAddrInUse checks if an error is caused by EADDRINUSE (another process holds the socket).
func isAddrInUse(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			return errors.Is(sysErr.Err, syscall.EADDRINUSE)
		}
	}
	return false
}

// isTimeoutError checks if an error is a timeout (for DAEMON_TIMEOUT classification).
func isTimeoutError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

// outputCheckJSON writes a check response as JSON and exits with appropriate code.
func outputCheckJSON(ready bool, state, errorCode, message, action string, daemonRunning *bool, loginStartedAt *time.Time) error {
	out := map[string]any{
		"ready": ready,
		"state": state,
	}
	if daemonRunning != nil {
		out["daemon_running"] = *daemonRunning
	} else {
		out["daemon_running"] = true
	}
	if errorCode != "" {
		out["error"] = errorCode
	}
	if message != "" {
		out["message"] = message
	}
	if action != "" {
		out["action"] = action
	}
	if loginStartedAt != nil {
		out["login_started_at"] = loginStartedAt.Format(time.RFC3339)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	if !ready {
		os.Exit(1)
	}
	return nil
}

// --- shared OIDC flag helpers (single source of truth) ---

// oidcFlags holds the common OIDC flags shared across login/check/refresh commands.
// This is the single definition point for these flags — no duplication.
type oidcFlags struct {
	contextName    string
	issuerURL      string
	clientID       string
	clientSecret   string
	extraScopes    []string
	extraParams    map[string]string
	requestHeaders map[string]string
	username       string
	grantType      string
	useAccessToken bool
	// COMPAT-1/5: Fields that affect cache key but not daemon behavior.
	// Parsed from kubeconfig exec args to ensure consistent cache keys.
	redirectURL string
	pkceMethod  oidc.PKCEMethod
	tlsConfig   tlsclientconfig.Config

	// Upstream auth flags forwarded to interactive auth flows (login command).
	skipOpenBrowser            bool
	listenAddress              []string
	browserCommand             string
	authenticationTimeoutSec   int
	localServerCertFile        string
	localServerKeyFile         string
	openURLAfterAuthentication string
	redirectURLHostname        string // COMPAT-1: not used, only for warning
	tokenCacheStorage          string // COMPAT-HIGH-1: "keyring" silently unsupported
}

// addOIDCFlags registers the common OIDC flags on a cobra command.
// Pass includeContext=true for commands that support --context (login/check/refresh).
// Pass includeGrantType=true for commands that support --grant-type (login/refresh).
// Pass includeUsername=true for commands that support --username (check/refresh).
func addOIDCFlags(cmd *cobra.Command, f *oidcFlags, includeContext, includeGrantType, includeUsername bool) {
	if includeContext {
		cmd.Flags().StringVar(&f.contextName, "context", "", "Kubeconfig context (default: current context)")
	}
	cmd.Flags().StringVar(&f.issuerURL, "oidc-issuer-url", "", "OIDC issuer URL")
	cmd.Flags().StringVar(&f.clientID, "oidc-client-id", "", "OIDC client ID")
	cmd.Flags().StringVar(&f.clientSecret, "oidc-client-secret", "", "OIDC client secret")
	// COMPAT-HIGH-2: Use StringSliceVar to match upstream and getTokenCmd.
	cmd.Flags().StringSliceVar(&f.extraScopes, "oidc-extra-scope", nil, "Extra OIDC scopes")
	cmd.Flags().StringToStringVar(&f.extraParams, "oidc-extra-param", nil, "Extra auth request params (key=value)")
	cmd.Flags().StringToStringVar(&f.requestHeaders, "oidc-request-header", nil, "Request headers for OIDC provider (key=value)")
	if includeGrantType {
		cmd.Flags().StringVar(&f.grantType, "grant-type", "auto", "Grant type (auto, device-code, authcode-browser)")
	}
	if includeUsername {
		cmd.Flags().StringVar(&f.username, "username", "", "Username")
	}
	cmd.Flags().BoolVar(&f.useAccessToken, "oidc-use-access-token", false, "Use access token instead of ID token")
}

// resolveOIDCConfig merges CLI flags with kubeconfig, enforcing that explicit
// CLI flags always win. Returns an error if issuerURL or clientID are still empty.
func (f *oidcFlags) resolveFromKubeconfig(cmd *cobra.Command) error {
	if f.issuerURL != "" && f.clientID != "" {
		return nil // all explicit, no kubeconfig needed
	}
	parsed, err := parseOIDCFromKubeconfig(f.contextName)
	if err != nil {
		return fmt.Errorf("read kubeconfig: %w", err)
	}
	if f.issuerURL == "" {
		f.issuerURL = parsed.issuerURL
	}
	if f.clientID == "" {
		f.clientID = parsed.clientID
	}
	if f.clientSecret == "" {
		f.clientSecret = parsed.clientSecret
	}
	if len(f.extraScopes) == 0 && len(parsed.extraScopes) > 0 {
		f.extraScopes = parsed.extraScopes
	}
	if f.grantType == "auto" && parsed.grantType != "" {
		f.grantType = parsed.grantType
	}
	if !cmd.Flags().Changed("oidc-use-access-token") {
		f.useAccessToken = parsed.useAccessToken
	}
	if f.username == "" && parsed.username != "" {
		f.username = parsed.username
	}
	if len(f.extraParams) == 0 && len(parsed.extraParams) > 0 {
		f.extraParams = parsed.extraParams
	}
	if len(f.requestHeaders) == 0 && len(parsed.requestHeaders) > 0 {
		f.requestHeaders = parsed.requestHeaders
	}
	// COMPAT-1/5: Copy TLS/redirect/PKCE fields from kubeconfig for cache key parity.
	if f.redirectURL == "" {
		f.redirectURL = parsed.redirectURL
	}
	if f.pkceMethod == oidc.PKCEMethodAuto {
		f.pkceMethod = parsed.pkceMethod
	}
	if len(f.tlsConfig.CACertFilename) == 0 && len(f.tlsConfig.CACertData) == 0 {
		f.tlsConfig = tlsclientconfig.Config{
			CACertFilename: parsed.caCertFilename,
			CACertData:     parsed.caCertData,
			SkipTLSVerify:  parsed.skipTLSVerify,
			Renegotiation:  parsed.renegotiation,
		}
	}

	// Forward upstream auth flags (only if not already set by CLI).
	if !f.skipOpenBrowser {
		f.skipOpenBrowser = parsed.skipOpenBrowser
	}
	if len(f.listenAddress) == 0 && len(parsed.listenAddress) > 0 {
		f.listenAddress = parsed.listenAddress
	}
	if f.browserCommand == "" {
		f.browserCommand = parsed.browserCommand
	}
	if f.authenticationTimeoutSec == 0 && parsed.authenticationTimeoutSec > 0 {
		f.authenticationTimeoutSec = parsed.authenticationTimeoutSec
	}
	if f.localServerCertFile == "" {
		f.localServerCertFile = parsed.localServerCertFile
	}
	if f.localServerKeyFile == "" {
		f.localServerKeyFile = parsed.localServerKeyFile
	}
	if f.openURLAfterAuthentication == "" {
		f.openURLAfterAuthentication = parsed.openURLAfterAuthentication
	}
	if f.redirectURLHostname == "" {
		f.redirectURLHostname = parsed.redirectURLHostname
	}
	if f.tokenCacheStorage == "" {
		f.tokenCacheStorage = parsed.tokenCacheStorage
	}
	return nil
}

// buildCacheKey computes a deterministic cache key from the OIDC flags.
func (f *oidcFlags) buildCacheKey() (string, error) {
	return computeCacheKey(tokencache.Key{
		Provider: oidc.Provider{
			IssuerURL:      f.issuerURL,
			ClientID:       f.clientID,
			ClientSecret:   f.clientSecret,
			ExtraScopes:    f.extraScopes,
			UseAccessToken: f.useAccessToken,
			RequestHeaders: f.requestHeaders,
			RedirectURL:    f.redirectURL,
			PKCEMethod:     f.pkceMethod,
		},
		TLSClientConfig:        f.tlsConfig,
		Username:               f.username,
		AuthRequestExtraParams: f.extraParams,
	})
}

// validate checks that required fields are present after resolution.
func (f *oidcFlags) validate() error {
	if f.issuerURL == "" || f.clientID == "" {
		return fmt.Errorf("OIDC issuer URL and client ID are required (provide via kubeconfig or --oidc-issuer-url/--oidc-client-id)")
	}
	return nil
}

// mapGrantType maps upstream kubelogin grant type names to daemon-supported equivalents.
// Upstream supports: auto, authcode, authcode-keyboard, password, device-code, client-credentials.
// Daemon supports: device-code, authcode-browser.
//
// COMPAT-1/COMPAT-2: password and client-credentials grant types return errors
// instead of silently degrading to device-code. Silent degradation caused
// non-interactive CI/CD workloads to hang waiting for user interaction.
// COMPAT-CRIT-2: Returns an error directly instead of a mangled string, so
// callers get a clear message about the original grant type.
func mapGrantType(gt string) (string, error) {
	switch gt {
	case "device-code", "authcode-browser":
		return gt, nil // native support
	case "auto":
		return "device-code", nil // auto → daemon's default interactive flow
	case "authcode":
		return "authcode-browser", nil // browser-based authcode is daemon's equivalent
	case "authcode-keyboard":
		// COMPAT-HIGH-1: authcode-keyboard was designed for headless environments
		// (SSH, containers) where the user copy-pastes a URL. Mapping to
		// authcode-browser fails headless (no browser/display). Device-code
		// is the daemon's headless-compatible interactive flow.
		return "device-code", nil
	case "password":
		return "", fmt.Errorf("grant-type 'password' (ROPC) is not supported by kubelogin-daemon; use grant-type 'device-code' or upstream kubelogin for ROPC")
	case "client-credentials":
		return "", fmt.Errorf("grant-type 'client-credentials' is not supported by kubelogin-daemon; use upstream kubelogin for client-credentials flows")
	default:
		return gt, nil // pass through, let downstream error if unsupported
	}
}

// parseIntSafe converts a string to int, returning an error if invalid.
func parseIntSafe(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// parsePKCEMethod maps a string PKCE method name to the oidc.PKCEMethod enum.
func parsePKCEMethod(s string) oidc.PKCEMethod {
	switch s {
	case "S256":
		return oidc.PKCEMethodS256
	case "":
		return oidc.PKCEMethodAuto
	default:
		return oidc.PKCEMethodNo
	}
}

// --- kubeconfig parsing ---

// parsedOIDCConfig holds OIDC parameters extracted from kubeconfig exec section.
type parsedOIDCConfig struct {
	issuerURL      string
	clientID       string
	clientSecret   string
	extraScopes    []string
	grantType      string
	useAccessToken bool
	username       string
	extraParams    map[string]string
	requestHeaders map[string]string
	// Upstream auth flags (parsed from kubeconfig exec args, forwarded to auth flows).
	skipOpenBrowser            bool
	listenAddress              []string
	browserCommand             string
	authenticationTimeoutSec   int
	localServerCertFile        string
	localServerKeyFile         string
	openURLAfterAuthentication string
	redirectURLHostname        string // COMPAT-1: parsed but not used, triggers warning
	forceRefresh               bool
	tokenCacheDir              string
	tokenCacheStorage          string // COMPAT-HIGH-1: "keyring" silently unsupported
	// COMPAT-1/5: TLS/redirect/PKCE fields affect cache key computation.
	redirectURL    string
	pkceMethod     oidc.PKCEMethod
	caCertFilename []string
	caCertData     []string
	skipTLSVerify  bool
	renegotiation  tls.RenegotiationSupport
}

// parseOIDCFromKubeconfig reads the kubeconfig and extracts OIDC parameters
// from the exec section of the current (or specified) context's user.
func parseOIDCFromKubeconfig(contextName string) (*parsedOIDCConfig, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}
	config, err := rules.Load()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}

	if contextName == "" {
		contextName = config.CurrentContext
	}
	if contextName == "" {
		return nil, fmt.Errorf("no current context in kubeconfig")
	}

	ctxObj, ok := config.Contexts[contextName]
	if !ok || ctxObj == nil {
		return nil, fmt.Errorf("context %q not found in kubeconfig", contextName)
	}

	userObj, ok := config.AuthInfos[ctxObj.AuthInfo]
	if !ok || userObj == nil {
		return nil, fmt.Errorf("user %q not found in kubeconfig", ctxObj.AuthInfo)
	}

	if userObj.Exec == nil {
		return nil, fmt.Errorf("user %q does not use exec credential plugin", ctxObj.AuthInfo)
	}

	// Accept kubelogin-daemon, kubelogin, and kubectl-oidc_login as valid exec commands.
	// This allows login/check/refresh to work during partial migration from upstream.
	base := filepath.Base(userObj.Exec.Command)
	base = strings.TrimSuffix(base, ".exe") // Windows compatibility
	if base != "kubelogin-daemon" && base != "kubelogin" && base != "kubectl-oidc_login" {
		return nil, fmt.Errorf("context uses exec command %q, expected kubelogin-daemon or kubelogin (use --oidc-issuer-url/--oidc-client-id flags or --context to select the right context)", base)
	}

	// Parse OIDC flags from the exec args
	return parseExecArgs(userObj.Exec.Args), nil
}

// parseExecArgs extracts OIDC flags from the exec args array.
// Example args: ["get-token", "--oidc-issuer-url", "https://...", "--oidc-client-id", "k8s"]
// Unknown upstream flags (e.g. --token-cache-storage, --certificate-authority) are
// silently skipped so that kubeconfigs migrated from upstream kubelogin still work.
func parseExecArgs(args []string) *parsedOIDCConfig {
	cfg := &parsedOIDCConfig{}

	// Known boolean flags that take no value — prevents them from consuming the next arg.
	// COMPAT-5: Include both single-dash and double-dash forms to handle kubeconfigs
	// that may use either style (pflag accepts both).
	boolFlags := map[string]bool{
		"--skip-open-browser":        true,
		"-skip-open-browser":         true,
		"--force-refresh":            true,
		"-force-refresh":             true,
		"--oidc-use-access-token":    true,
		"-oidc-use-access-token":     true,
		"--oidc-use-pkce":            true,
		"-oidc-use-pkce":             true,
		"--insecure-skip-tls-verify": true,
		"-insecure-skip-tls-verify":  true,
		"--tls-renegotiation-once":   true,
		"-tls-renegotiation-once":    true,
		"--tls-renegotiation-freely": true,
		"-tls-renegotiation-freely":  true,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]

		// Skip non-flag args (e.g. "get-token" subcommand name)
		if !strings.HasPrefix(arg, "-") {
			continue
		}

		// COMPAT-5: Normalize single-dash long flags to double-dash.
		// pflag accepts both -oidc-issuer-url and --oidc-issuer-url.
		// Normalize here so the switch statement below works with both.
		if !strings.HasPrefix(arg, "--") && len(arg) > 2 {
			arg = "-" + arg // -foo → --foo
		}

		// Handle --flag=value and --flag value
		var key, val string
		if eqIdx := strings.IndexByte(arg, '='); eqIdx >= 0 {
			key = arg[:eqIdx]
			val = arg[eqIdx+1:]
		} else {
			key = arg
			if boolFlags[key] {
				// For boolean flags, only consume the next arg if it's "true" or "false".
				// This matches upstream pflag behavior: --skip-open-browser false → false.
				if i+1 < len(args) {
					next := strings.ToLower(args[i+1])
					if next == "true" || next == "false" {
						val = next
						i++
					}
					// Otherwise leave val empty (bare flag = true)
				}
			} else {
				// ROB-1: Always consume the next arg as the value for non-boolean
				// flags, even if it starts with "-". This matches pflag behavior.
				// Without this, --oidc-client-secret -my-secret silently loses the
				// value, causing cache key divergence between get-token (pflag) and
				// login/check/refresh (parseExecArgs).
				if i+1 < len(args) {
					val = args[i+1]
					i++
				}
			}
		}

		switch key {
		case "--oidc-issuer-url":
			cfg.issuerURL = val
		case "--oidc-client-id":
			cfg.clientID = val
		case "--oidc-client-secret":
			cfg.clientSecret = val
		case "--oidc-extra-scope":
			// COMPAT-CRIT-1: Comma-split to match getTokenCmd's StringSliceVar behavior.
			// StringSliceVar (used since COMPAT-HIGH-2) splits "groups,email" into
			// ["groups","email"]. parseExecArgs must produce the same result to ensure
			// consistent cache keys between login/check and get-token paths.
			if val != "" {
				for _, s := range strings.Split(val, ",") {
					s = strings.TrimSpace(s)
					if s != "" {
						cfg.extraScopes = append(cfg.extraScopes, s)
					}
				}
			}
		case "--grant-type":
			cfg.grantType = val
		case "--oidc-use-access-token":
			cfg.useAccessToken = val != "false"
		case "--skip-open-browser":
			cfg.skipOpenBrowser = val != "false"
		case "--listen-address":
			if val != "" {
				cfg.listenAddress = append(cfg.listenAddress, val)
			}
		case "--browser-command":
			cfg.browserCommand = val
		case "--authentication-timeout-sec":
			if val != "" {
				if n, err := parseIntSafe(val); err == nil {
					cfg.authenticationTimeoutSec = n
				}
			}
		case "--local-server-cert":
			cfg.localServerCertFile = val
		case "--local-server-key":
			cfg.localServerKeyFile = val
		case "--open-url-after-authentication":
			cfg.openURLAfterAuthentication = val
		case "--force-refresh":
			cfg.forceRefresh = val != "false"
		case "--token-cache-dir":
			cfg.tokenCacheDir = val
		case "--token-cache-storage":
			cfg.tokenCacheStorage = val
		case "--username":
			cfg.username = val
		case "--oidc-auth-request-extra-params", "--oidc-extra-param":
			// Parse key=value format for extra auth request parameters.
			// Upstream uses --oidc-auth-request-extra-params, daemon also accepts --oidc-extra-param.
			if val != "" {
				if cfg.extraParams == nil {
					cfg.extraParams = make(map[string]string)
				}
				if eqIdx := strings.IndexByte(val, '='); eqIdx >= 0 {
					cfg.extraParams[val[:eqIdx]] = val[eqIdx+1:]
				} else {
					cfg.extraParams[val] = ""
				}
			}
		case "--oidc-request-header":
			// Parse key=value format for OIDC provider request headers.
			if val != "" {
				if cfg.requestHeaders == nil {
					cfg.requestHeaders = make(map[string]string)
				}
				if eqIdx := strings.IndexByte(val, '='); eqIdx >= 0 {
					cfg.requestHeaders[val[:eqIdx]] = val[eqIdx+1:]
				} else {
					cfg.requestHeaders[val] = ""
				}
			}
		// COMPAT-1: TLS config fields affect cache key computation.
		case "--certificate-authority":
			if val != "" {
				cfg.caCertFilename = append(cfg.caCertFilename, val)
			}
		case "--certificate-authority-data":
			if val != "" {
				cfg.caCertData = append(cfg.caCertData, val)
			}
		case "--insecure-skip-tls-verify":
			cfg.skipTLSVerify = val != "false"
		case "--tls-renegotiation-once":
			if val != "false" {
				cfg.renegotiation = tls.RenegotiateOnceAsClient
			}
		case "--tls-renegotiation-freely":
			if val != "false" {
				cfg.renegotiation = tls.RenegotiateFreelyAsClient
			}
		// COMPAT-5: RedirectURL and PKCEMethod affect cache key computation.
		case "--oidc-redirect-url":
			cfg.redirectURL = val
		case "--oidc-pkce-method":
			cfg.pkceMethod = parsePKCEMethod(val)
		case "--oidc-use-pkce":
			if val != "false" {
				cfg.pkceMethod = oidc.PKCEMethodS256
			}
		// COMPAT-1: Parse redirect-url-hostname to detect usage and warn.
		case "--oidc-redirect-url-hostname":
			cfg.redirectURLHostname = val
			// All other upstream flags are silently ignored (token-cache-storage,
			// etc.). They remain in kubeconfig args for backward compatibility.
		}
	}
	return cfg
}
