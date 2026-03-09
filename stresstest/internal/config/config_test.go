package config

import (
	"strings"
	"testing"
	"time"
)

// validConfig returns a Config that passes all validation checks.
// Tests mutate individual fields from this baseline to trigger specific errors.
func validConfig() *Config {
	cfg := Defaults()
	cfg.Namespace = "test-ns"
	// Defaults already set Duration, but make sure it is positive.
	cfg.Duration = 1 * time.Hour
	return cfg
}

func TestValidate_HappyPath(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
}

func TestValidate_DefaultsWithNamespace(t *testing.T) {
	cfg := Defaults()
	cfg.Namespace = "default"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("defaults + namespace should be valid, got: %v", err)
	}
}

func TestValidate_EmptyNamespace(t *testing.T) {
	cfg := validConfig()
	cfg.Namespace = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty namespace")
	}
	if !strings.Contains(err.Error(), "namespace is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_NonPositiveDuration(t *testing.T) {
	for _, d := range []time.Duration{0, -1 * time.Second} {
		cfg := validConfig()
		cfg.Duration = d
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("expected error for duration=%v", d)
		}
		if !strings.Contains(err.Error(), "duration must be positive") {
			t.Fatalf("unexpected error for duration=%v: %v", d, err)
		}
	}
}

func TestValidate_PhaseWeights(t *testing.T) {
	tests := []struct {
		name    string
		steady  int
		burst   int
		quiet   int
		wantErr string
	}{
		{
			name:    "sum to 99",
			steady:  69,
			burst:   20,
			quiet:   10,
			wantErr: "phase weights must sum to 100 (got 99)",
		},
		{
			name:    "sum to 101",
			steady:  71,
			burst:   20,
			quiet:   10,
			wantErr: "phase weights must sum to 100 (got 101)",
		},
		{
			name:    "all zero",
			steady:  0,
			burst:   0,
			quiet:   0,
			wantErr: "phase weights must sum to 100 (got 0)",
		},
		{
			name:   "sum to 100",
			steady: 50,
			burst:  30,
			quiet:  20,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Workload.SteadyWeight = tt.steady
			cfg.Workload.BurstWeight = tt.burst
			cfg.Workload.QuietWeight = tt.quiet
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidate_CommandWeights(t *testing.T) {
	tests := []struct {
		name    string
		read    int
		mutate  int
		invalid int
		fuzz    int
		wantErr string
	}{
		{
			name:    "sum to 50",
			read:    20,
			mutate:  10,
			invalid: 10,
			fuzz:    10,
			wantErr: "command weights must sum to 100 (got 50)",
		},
		{
			name:    "sum to 200",
			read:    100,
			mutate:  50,
			invalid: 25,
			fuzz:    25,
			wantErr: "command weights must sum to 100 (got 200)",
		},
		{
			name:    "all zero",
			read:    0,
			mutate:  0,
			invalid: 0,
			fuzz:    0,
			wantErr: "command weights must sum to 100 (got 0)",
		},
		{
			name:    "sum to 100 alternative",
			read:    25,
			mutate:  25,
			invalid: 25,
			fuzz:    25,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Workload.CommandWeights = CommandWeights{
				Read:    tt.read,
				Mutate:  tt.mutate,
				Invalid: tt.invalid,
				Fuzz:    tt.fuzz,
			}
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidate_MinGreaterThanMax_Durations(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "steady_delay min > max",
			mutate: func(c *Config) {
				c.Workload.SteadyMinDelay = 5 * time.Second
				c.Workload.SteadyMaxDelay = 1 * time.Second
			},
			wantErr: "steady_delay: min",
		},
		{
			name: "burst_delay min > max",
			mutate: func(c *Config) {
				c.Workload.BurstMinDelay = 10 * time.Second
				c.Workload.BurstMaxDelay = 1 * time.Second
			},
			wantErr: "burst_delay: min",
		},
		{
			name: "quiet_delay min > max",
			mutate: func(c *Config) {
				c.Workload.QuietMinDelay = 10 * time.Second
				c.Workload.QuietMaxDelay = 1 * time.Second
			},
			wantErr: "quiet_delay: min",
		},
		{
			name: "phase_duration min > max",
			mutate: func(c *Config) {
				c.Workload.PhaseDurationMin = 20 * time.Minute
				c.Workload.PhaseDurationMax = 5 * time.Minute
			},
			wantErr: "phase_duration: min",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidate_MinGreaterThanMax_Concurrency(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "steady_conc min > max",
			mutate: func(c *Config) {
				c.Workload.SteadyMinConc = 20
				c.Workload.SteadyMaxConc = 5
			},
			wantErr: "steady_conc: min (20) > max (5)",
		},
		{
			name: "burst_conc min > max",
			mutate: func(c *Config) {
				c.Workload.BurstMinConc = 200
				c.Workload.BurstMaxConc = 10
			},
			wantErr: "burst_conc: min (200) > max (10)",
		},
		{
			name: "quiet_conc min > max",
			mutate: func(c *Config) {
				c.Workload.QuietMinConc = 5
				c.Workload.QuietMaxConc = 0
			},
			wantErr: "quiet_conc: min (5) > max (0)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidate_PositiveConstraints(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "max_resources zero",
			mutate: func(c *Config) {
				c.Workload.MaxResources = 0
			},
			wantErr: "max_resources must be > 0",
		},
		{
			name: "max_resources negative",
			mutate: func(c *Config) {
				c.Workload.MaxResources = -1
			},
			wantErr: "max_resources must be > 0",
		},
		{
			name: "kubectl_timeout zero",
			mutate: func(c *Config) {
				c.Workload.KubectlTimeout = 0
			},
			wantErr: "kubectl_timeout must be > 0",
		},
		{
			name: "sla_threshold zero",
			mutate: func(c *Config) {
				c.Workload.SLAThreshold = 0
			},
			wantErr: "sla_threshold must be > 0",
		},
		{
			name: "direct_ipc_workers zero",
			mutate: func(c *Config) {
				c.Workload.DirectIPCWorkers = 0
			},
			wantErr: "direct_ipc_workers must be >= 1",
		},
		{
			name: "direct_ipc_rate negative",
			mutate: func(c *Config) {
				c.Workload.DirectIPCRate = -1
			},
			wantErr: "direct_ipc_rate must be >= 0",
		},
		{
			name: "direct_ipc_rate zero is valid",
			mutate: func(c *Config) {
				c.Workload.DirectIPCRate = 0
			},
			// No error expected
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(cfg)
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidate_ChaosValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "fill_disk enabled with zero max_fill_bytes",
			mutate: func(c *Config) {
				c.Chaos.FillDisk.Enabled = true
				c.Chaos.FillDisk.MaxFillBytes = 0
			},
			wantErr: "fill_disk.max_fill_bytes must be > 0",
		},
		{
			name: "fill_disk disabled with zero max_fill_bytes is ok",
			mutate: func(c *Config) {
				c.Chaos.FillDisk.Enabled = false
				c.Chaos.FillDisk.MaxFillBytes = 0
			},
		},
		{
			name: "fill_connections enabled with zero target_count",
			mutate: func(c *Config) {
				c.Chaos.FillConnections.Enabled = true
				c.Chaos.FillConnections.TargetCount = 0
			},
			wantErr: "fill_connections.target_count must be > 0",
		},
		{
			name: "fill_connections disabled with zero target_count is ok",
			mutate: func(c *Config) {
				c.Chaos.FillConnections.Enabled = false
				c.Chaos.FillConnections.TargetCount = 0
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(cfg)
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidate_ChaosIntervalMinMax(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "kill_daemon interval_min > interval_max",
			mutate: func(c *Config) {
				c.Chaos.KillDaemon.Enabled = true
				c.Chaos.KillDaemon.IntervalMin = 2 * time.Hour
				c.Chaos.KillDaemon.IntervalMax = 1 * time.Hour
			},
			wantErr: "chaos kill_daemon: interval_min > interval_max",
		},
		{
			name: "delete_socket interval_min zero",
			mutate: func(c *Config) {
				c.Chaos.DeleteSocket.Enabled = true
				c.Chaos.DeleteSocket.IntervalMin = 0
				c.Chaos.DeleteSocket.IntervalMax = 1 * time.Hour
			},
			wantErr: "chaos delete_socket: interval_min must be > 0",
		},
		{
			name: "disabled chaos type skips interval check",
			mutate: func(c *Config) {
				c.Chaos.KillDaemon.Enabled = false
				c.Chaos.KillDaemon.IntervalMin = 2 * time.Hour
				c.Chaos.KillDaemon.IntervalMax = 1 * time.Hour
			},
			// No error because the chaos type is disabled.
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(cfg)
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidate_RunLabel(t *testing.T) {
	tests := []struct {
		name    string
		label   string
		wantErr string
	}{
		{name: "empty is valid", label: ""},
		{name: "simple lowercase", label: "abc"},
		{name: "with hyphens", label: "my-test-run"},
		{name: "with digits", label: "run1"},
		{name: "single char", label: "a"},
		{name: "max length 47", label: "a234567890123456789012345678901234567890123456b"},
		{
			name:    "too long (48 chars)",
			label:   "a2345678901234567890123456789012345678901234567c",
			wantErr: "run_label must be <= 47 chars",
		},
		{
			name:    "leading hyphen",
			label:   "-bad",
			wantErr: "run_label must match RFC 1123",
		},
		{
			name:    "trailing hyphen",
			label:   "bad-",
			wantErr: "run_label must match RFC 1123",
		},
		{
			name:    "uppercase letters",
			label:   "Bad",
			wantErr: "run_label must match RFC 1123",
		},
		{
			name:    "underscore",
			label:   "bad_label",
			wantErr: "run_label must match RFC 1123",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.RunLabel = tt.label
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error for label %q, got: %v", tt.label, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q for label %q", tt.wantErr, tt.label)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestSetDuration(t *testing.T) {
	cfg := &Config{}
	if err := cfg.SetDuration("5m"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Duration != 5*time.Minute {
		t.Fatalf("expected 5m, got %v", cfg.Duration)
	}
	if cfg.DurationStr != "5m" {
		t.Fatalf("expected DurationStr='5m', got %q", cfg.DurationStr)
	}

	if err := cfg.SetDuration("not-a-duration"); err == nil {
		t.Fatal("expected error for invalid duration string")
	}
}

func TestLabelSelector(t *testing.T) {
	cfg := &Config{}
	if got := cfg.LabelSelector(); got != "app.kubernetes.io/managed-by=kld-stress-test" {
		t.Fatalf("unexpected label selector: %q", got)
	}
	cfg.RunLabel = "run42"
	if got := cfg.LabelSelector(); got != "app.kubernetes.io/managed-by=kld-stress-test-run42" {
		t.Fatalf("unexpected label selector: %q", got)
	}
}

func TestManagedByValue(t *testing.T) {
	cfg := &Config{}
	if got := cfg.ManagedByValue(); got != "kld-stress-test" {
		t.Fatalf("unexpected managed-by value: %q", got)
	}
	cfg.RunLabel = "abc"
	if got := cfg.ManagedByValue(); got != "kld-stress-test-abc" {
		t.Fatalf("unexpected managed-by value: %q", got)
	}
}

func TestDefaults_PassesValidation(t *testing.T) {
	cfg := Defaults()
	cfg.Namespace = "test"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("defaults should pass validation with namespace set, got: %v", err)
	}
}

func TestValidate_MultipleErrors_ReturnsFirst(t *testing.T) {
	// Config with no namespace AND bad phase weights: namespace check comes first.
	cfg := Defaults()
	cfg.Namespace = ""
	cfg.Workload.SteadyWeight = 0
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "namespace") {
		t.Fatalf("expected first error to be about namespace, got: %v", err)
	}
}
