package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/config"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/orchestrator"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/report"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "kld-stresstest",
		Short: "24-hour stress test for kubelogin-daemon",
	}

	rootCmd.AddCommand(newRunCmd())
	rootCmd.AddCommand(newReportCmd())
	rootCmd.AddCommand(newCleanupCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newRunCmd() *cobra.Command {
	var (
		configFile string
		duration   string
		namespace  string
		outputDir  string
		rngSeed    int64
		runLabel   string
		verbose    bool
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the 24-hour stress test",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configFile)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			// Apply CLI overrides
			if cmd.Flags().Changed("duration") {
				if err := cfg.SetDuration(duration); err != nil {
					return err
				}
			}
			if cmd.Flags().Changed("namespace") {
				cfg.Namespace = namespace
			}
			if cmd.Flags().Changed("output-dir") {
				cfg.OutputDir = outputDir
			}
			if cmd.Flags().Changed("rng-seed") {
				cfg.RNGSeed = rngSeed
			}
			if cmd.Flags().Changed("run-label") {
				cfg.RunLabel = runLabel
			}
			if verbose {
				cfg.Verbose = true
			}

			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("config validation: %w", err)
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			orch := orchestrator.New(cfg)
			return orch.Run(ctx)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "stress.yaml", "config file path")
	cmd.Flags().StringVar(&duration, "duration", "", "test duration (e.g. 24h, 1h)")
	cmd.Flags().StringVar(&namespace, "namespace", "", "Kubernetes namespace")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "output directory for results")
	cmd.Flags().Int64Var(&rngSeed, "rng-seed", 0, "RNG seed (0 = random)")
	cmd.Flags().StringVar(&runLabel, "run-label", "", "unique run label for multi-instance isolation")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "enable verbose logging")

	return cmd
}

func newReportCmd() *cobra.Command {
	var (
		dbPath string
		runID  string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Parse SQLite DB and produce summary report",
		RunE: func(cmd *cobra.Command, args []string) error {
			return report.GenerateFromDB(dbPath, runID)
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "", "path to stress.db")
	cmd.Flags().StringVar(&runID, "run-id", "", "test run ID (default: most recent)")
	_ = cmd.MarkFlagRequired("db")

	return cmd
}

func newCleanupCmd() *cobra.Command {
	var (
		configFile string
		namespace  string
	)

	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Delete all stress test resources (safety net)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configFile)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			if cmd.Flags().Changed("namespace") {
				cfg.Namespace = namespace
			}
			if cfg.Namespace == "" {
				return fmt.Errorf("namespace is required")
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			return orchestrator.Cleanup(ctx, cfg)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "stress.yaml", "config file path")
	cmd.Flags().StringVar(&namespace, "namespace", "", "Kubernetes namespace")

	return cmd
}
