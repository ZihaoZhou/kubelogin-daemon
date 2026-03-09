package config

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all stress test configuration.
type Config struct {
	Namespace    string        `yaml:"namespace"`
	Duration     time.Duration `yaml:"-"`
	DurationStr  string        `yaml:"duration"`
	OutputDir    string        `yaml:"output_dir"`
	RNGSeed      int64         `yaml:"rng_seed"`
	RunLabel     string        `yaml:"run_label"`
	DaemonBinary string        `yaml:"daemon_binary"`
	RuntimeDir   string        `yaml:"runtime_dir"`
	SocketPath   string        `yaml:"socket_path"`
	Verbose      bool          `yaml:"-"`

	Workload WorkloadConfig `yaml:"workload"`
	Chaos    ChaosConfig    `yaml:"chaos"`
	Health   HealthConfig   `yaml:"health"`
	Reaper   ReaperConfig   `yaml:"reaper"`
	Report   ReportConfig   `yaml:"report"`
}

// WorkloadConfig configures the workload generator.
type WorkloadConfig struct {
	SteadyWeight int `yaml:"steady_weight"`
	BurstWeight  int `yaml:"burst_weight"`
	QuietWeight  int `yaml:"quiet_weight"`

	SteadyMinConc  int           `yaml:"steady_min_conc"`
	SteadyMaxConc  int           `yaml:"steady_max_conc"`
	SteadyMinDelay time.Duration `yaml:"-"`
	SteadyMaxDelay time.Duration `yaml:"-"`

	BurstMinConc  int           `yaml:"burst_min_conc"`
	BurstMaxConc  int           `yaml:"burst_max_conc"`
	BurstMinDelay time.Duration `yaml:"-"`
	BurstMaxDelay time.Duration `yaml:"-"`

	QuietMinConc  int           `yaml:"quiet_min_conc"`
	QuietMaxConc  int           `yaml:"quiet_max_conc"`
	QuietMinDelay time.Duration `yaml:"-"`
	QuietMaxDelay time.Duration `yaml:"-"`

	PhaseDurationMin time.Duration `yaml:"-"`
	PhaseDurationMax time.Duration `yaml:"-"`

	CommandWeights CommandWeights `yaml:"command_weights"`

	DirectIPCWorkers int `yaml:"direct_ipc_workers"`
	DirectIPCRate    int `yaml:"direct_ipc_rate"`

	KubectlTimeout time.Duration `yaml:"-"`
	SLAThreshold   time.Duration `yaml:"-"`

	RateLimit RateLimitConfig `yaml:"rate_limit"`

	MaxResources int `yaml:"max_resources"`

	KubeconfigContext string `yaml:"kubeconfig_context"`

	// Raw string fields for YAML unmarshalling
	SteadyMinDelayStr  string `yaml:"steady_min_delay"`
	SteadyMaxDelayStr  string `yaml:"steady_max_delay"`
	BurstMinDelayStr   string `yaml:"burst_min_delay"`
	BurstMaxDelayStr   string `yaml:"burst_max_delay"`
	QuietMinDelayStr   string `yaml:"quiet_min_delay"`
	QuietMaxDelayStr   string `yaml:"quiet_max_delay"`
	PhaseDurationMinStr string `yaml:"phase_duration_min"`
	PhaseDurationMaxStr string `yaml:"phase_duration_max"`
	KubectlTimeoutStr  string `yaml:"kubectl_timeout"`
	SLAThresholdStr    string `yaml:"sla_threshold"`
}

// CommandWeights defines the distribution of command categories.
type CommandWeights struct {
	Read    int `yaml:"read"`
	Mutate  int `yaml:"mutate"`
	Invalid int `yaml:"invalid"`
	Fuzz    int `yaml:"fuzz"`
}

// RateLimitConfig configures per-phase rate limiting.
type RateLimitConfig struct {
	SteadyQPS   int `yaml:"steady_qps"`
	SteadyBurst int `yaml:"steady_burst"`
	BurstQPS    int `yaml:"burst_qps"`
	BurstBurst  int `yaml:"burst_burst"`
	QuietQPS    int `yaml:"quiet_qps"`
	QuietBurst  int `yaml:"quiet_burst"`
}

// ChaosConfig configures the chaos engine.
type ChaosConfig struct {
	Enabled                bool          `yaml:"enabled"`
	InitialStabilityPeriod time.Duration `yaml:"-"`
	GlobalCooldown         time.Duration `yaml:"-"`

	KillDaemon        ChaosTypeConfig `yaml:"kill_daemon"`
	DeleteSocket      ChaosTypeConfig `yaml:"delete_socket"`
	CorruptTokenFiles ChaosTypeConfig `yaml:"corrupt_token_files"`
	FillConnections   ChaosTypeConfig `yaml:"fill_connections"`
	FillDisk          ChaosTypeConfig `yaml:"fill_disk"`

	InitialStabilityPeriodStr string `yaml:"initial_stability_period"`
	GlobalCooldownStr         string `yaml:"global_cooldown"`
}

// ChaosTypeConfig configures a single chaos type.
type ChaosTypeConfig struct {
	Enabled      bool          `yaml:"enabled"`
	IntervalMin  time.Duration `yaml:"-"`
	IntervalMax  time.Duration `yaml:"-"`
	HoldDuration time.Duration `yaml:"-"`
	TargetCount  int           `yaml:"target_count"`
	MaxFillBytes int64         `yaml:"max_fill_bytes"`

	IntervalMinStr  string `yaml:"interval_min"`
	IntervalMaxStr  string `yaml:"interval_max"`
	HoldDurationStr string `yaml:"hold_duration"`
}

// HealthConfig configures the health monitor.
type HealthConfig struct {
	PollInterval     time.Duration `yaml:"-"`
	HangThreshold    time.Duration `yaml:"-"`
	ExitThreshold    time.Duration `yaml:"-"` // exit stress test after this long unresponsive
	MemoryWarnMB     int           `yaml:"memory_warn_mb"`
	MemoryKillMB     int           `yaml:"memory_kill_mb"`
	IdleAwareProbing bool          `yaml:"idle_aware_probing"`

	PollIntervalStr  string `yaml:"poll_interval"`
	HangThresholdStr string `yaml:"hang_threshold"`
	ExitThresholdStr string `yaml:"exit_threshold"`
}

// ReaperConfig configures the resource reaper.
type ReaperConfig struct {
	Interval time.Duration `yaml:"-"`
	MaxAge   time.Duration `yaml:"-"`

	IntervalStr string `yaml:"interval"`
	MaxAgeStr   string `yaml:"max_age"`
}

// ReportConfig configures the reporter.
type ReportConfig struct {
	Percentiles     []int `yaml:"percentiles"`
	IncludeTimeline bool  `yaml:"include_timeline"`
}

// LabelSelector returns the Kubernetes label selector for this run.
func (c *Config) LabelSelector() string {
	base := "kld-stress-test"
	if c.RunLabel != "" {
		base += "-" + c.RunLabel
	}
	return "app.kubernetes.io/managed-by=" + base
}

// ManagedByValue returns the label value for managed-by.
func (c *Config) ManagedByValue() string {
	base := "kld-stress-test"
	if c.RunLabel != "" {
		base += "-" + c.RunLabel
	}
	return base
}

// SetDuration parses and sets the duration from a string.
func (c *Config) SetDuration(s string) error {
	d, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	c.Duration = d
	c.DurationStr = s
	return nil
}

var runLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,45}[a-z0-9])?$`)

// Validate checks all configuration constraints.
func (c *Config) Validate() error {
	if c.Namespace == "" {
		return fmt.Errorf("namespace is required")
	}
	if c.Duration <= 0 {
		return fmt.Errorf("duration must be positive")
	}

	if c.RunLabel != "" {
		if len(c.RunLabel) > 47 {
			return fmt.Errorf("run_label must be <= 47 chars (total label value <= 63)")
		}
		if !runLabelRe.MatchString(c.RunLabel) {
			return fmt.Errorf("run_label must match RFC 1123 label value (lowercase alphanumeric + hyphens, no leading/trailing hyphen)")
		}
	}

	// Phase weights
	w := c.Workload
	if w.SteadyWeight+w.BurstWeight+w.QuietWeight != 100 {
		return fmt.Errorf("phase weights must sum to 100 (got %d)", w.SteadyWeight+w.BurstWeight+w.QuietWeight)
	}

	// Command weights
	cw := w.CommandWeights
	if cw.Read+cw.Mutate+cw.Invalid+cw.Fuzz != 100 {
		return fmt.Errorf("command weights must sum to 100 (got %d)", cw.Read+cw.Mutate+cw.Invalid+cw.Fuzz)
	}

	// Min <= max constraints
	checks := []struct {
		name     string
		min, max time.Duration
	}{
		{"steady_delay", w.SteadyMinDelay, w.SteadyMaxDelay},
		{"burst_delay", w.BurstMinDelay, w.BurstMaxDelay},
		{"quiet_delay", w.QuietMinDelay, w.QuietMaxDelay},
		{"phase_duration", w.PhaseDurationMin, w.PhaseDurationMax},
	}
	for _, ch := range checks {
		if ch.min > ch.max {
			return fmt.Errorf("%s: min (%s) > max (%s)", ch.name, ch.min, ch.max)
		}
	}

	intChecks := []struct {
		name     string
		min, max int
	}{
		{"steady_conc", w.SteadyMinConc, w.SteadyMaxConc},
		{"burst_conc", w.BurstMinConc, w.BurstMaxConc},
		{"quiet_conc", w.QuietMinConc, w.QuietMaxConc},
	}
	for _, ch := range intChecks {
		if ch.min > ch.max {
			return fmt.Errorf("%s: min (%d) > max (%d)", ch.name, ch.min, ch.max)
		}
	}

	if w.MaxResources <= 0 {
		return fmt.Errorf("max_resources must be > 0")
	}
	if w.KubectlTimeout <= 0 {
		return fmt.Errorf("kubectl_timeout must be > 0")
	}
	if w.SLAThreshold <= 0 {
		return fmt.Errorf("sla_threshold must be > 0")
	}
	if w.DirectIPCWorkers < 1 {
		return fmt.Errorf("direct_ipc_workers must be >= 1")
	}
	if w.DirectIPCRate < 0 {
		return fmt.Errorf("direct_ipc_rate must be >= 0")
	}

	// Chaos validation
	if c.Chaos.FillDisk.Enabled && c.Chaos.FillDisk.MaxFillBytes <= 0 {
		return fmt.Errorf("fill_disk.max_fill_bytes must be > 0 when enabled")
	}
	if c.Chaos.FillConnections.Enabled && c.Chaos.FillConnections.TargetCount <= 0 {
		return fmt.Errorf("fill_connections.target_count must be > 0 when enabled")
	}

	// Chaos interval validation
	chaosTypes := []struct {
		name string
		cfg  ChaosTypeConfig
	}{
		{"kill_daemon", c.Chaos.KillDaemon},
		{"delete_socket", c.Chaos.DeleteSocket},
		{"corrupt_token_files", c.Chaos.CorruptTokenFiles},
		{"fill_connections", c.Chaos.FillConnections},
		{"fill_disk", c.Chaos.FillDisk},
	}
	for _, ct := range chaosTypes {
		if !ct.cfg.Enabled {
			continue
		}
		if ct.cfg.IntervalMin > ct.cfg.IntervalMax {
			return fmt.Errorf("chaos %s: interval_min > interval_max", ct.name)
		}
		if ct.cfg.IntervalMin <= 0 {
			return fmt.Errorf("chaos %s: interval_min must be > 0", ct.name)
		}
	}

	return nil
}

// Load reads a config file and returns a Config with parsed durations.
func Load(path string) (*Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// No config file — use defaults (namespace still required)
			return cfg, nil
		}
		return nil, fmt.Errorf("read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	if err := cfg.parseDurations(); err != nil {
		return nil, fmt.Errorf("parse durations: %w", err)
	}

	return cfg, nil
}

func (c *Config) parseDurations() error {
	parse := func(name, s string, target *time.Duration) error {
		if s == "" {
			return nil
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		*target = d
		return nil
	}

	if err := parse("duration", c.DurationStr, &c.Duration); err != nil {
		return err
	}

	w := &c.Workload
	for _, p := range []struct {
		name string
		s    string
		t    *time.Duration
	}{
		{"steady_min_delay", w.SteadyMinDelayStr, &w.SteadyMinDelay},
		{"steady_max_delay", w.SteadyMaxDelayStr, &w.SteadyMaxDelay},
		{"burst_min_delay", w.BurstMinDelayStr, &w.BurstMinDelay},
		{"burst_max_delay", w.BurstMaxDelayStr, &w.BurstMaxDelay},
		{"quiet_min_delay", w.QuietMinDelayStr, &w.QuietMinDelay},
		{"quiet_max_delay", w.QuietMaxDelayStr, &w.QuietMaxDelay},
		{"phase_duration_min", w.PhaseDurationMinStr, &w.PhaseDurationMin},
		{"phase_duration_max", w.PhaseDurationMaxStr, &w.PhaseDurationMax},
		{"kubectl_timeout", w.KubectlTimeoutStr, &w.KubectlTimeout},
		{"sla_threshold", w.SLAThresholdStr, &w.SLAThreshold},
	} {
		if err := parse(p.name, p.s, p.t); err != nil {
			return err
		}
	}

	ch := &c.Chaos
	if err := parse("initial_stability_period", ch.InitialStabilityPeriodStr, &ch.InitialStabilityPeriod); err != nil {
		return err
	}
	if err := parse("global_cooldown", ch.GlobalCooldownStr, &ch.GlobalCooldown); err != nil {
		return err
	}

	chaosTypes := []*ChaosTypeConfig{
		&ch.KillDaemon, &ch.DeleteSocket, &ch.CorruptTokenFiles,
		&ch.FillConnections, &ch.FillDisk,
	}
	for _, ct := range chaosTypes {
		if err := parse("interval_min", ct.IntervalMinStr, &ct.IntervalMin); err != nil {
			return err
		}
		if err := parse("interval_max", ct.IntervalMaxStr, &ct.IntervalMax); err != nil {
			return err
		}
		if err := parse("hold_duration", ct.HoldDurationStr, &ct.HoldDuration); err != nil {
			return err
		}
	}

	h := &c.Health
	if err := parse("poll_interval", h.PollIntervalStr, &h.PollInterval); err != nil {
		return err
	}
	if err := parse("hang_threshold", h.HangThresholdStr, &h.HangThreshold); err != nil {
		return err
	}
	if h.ExitThresholdStr != "" {
		if err := parse("exit_threshold", h.ExitThresholdStr, &h.ExitThreshold); err != nil {
			return err
		}
	}

	r := &c.Reaper
	if err := parse("interval", r.IntervalStr, &r.Interval); err != nil {
		return err
	}
	if err := parse("max_age", r.MaxAgeStr, &r.MaxAge); err != nil {
		return err
	}

	return nil
}

// Defaults returns a Config with all default values set.
func Defaults() *Config {
	return &Config{
		DurationStr:  "24h",
		Duration:     24 * time.Hour,
		OutputDir:    "./stress-results",
		DaemonBinary: "kubelogin-daemon",
		Workload: WorkloadConfig{
			SteadyWeight: 70,
			BurstWeight:  20,
			QuietWeight:  10,

			SteadyMinConc:  1,
			SteadyMaxConc:  10,
			SteadyMinDelay: 100 * time.Millisecond,
			SteadyMaxDelay: 2 * time.Second,

			BurstMinConc:  20,
			BurstMaxConc:  100,
			BurstMinDelay: 0,
			BurstMaxDelay: 500 * time.Millisecond,

			QuietMinConc:  0,
			QuietMaxConc:  1,
			QuietMinDelay: 2 * time.Second,
			QuietMaxDelay: 5 * time.Second,

			PhaseDurationMin: 5 * time.Minute,
			PhaseDurationMax: 15 * time.Minute,

			CommandWeights: CommandWeights{
				Read:    60,
				Mutate:  20,
				Invalid: 10,
				Fuzz:    10,
			},

			DirectIPCWorkers: 5,
			DirectIPCRate:    5,
			KubectlTimeout:   30 * time.Second,
			SLAThreshold:     2 * time.Second,

			RateLimit: RateLimitConfig{
				SteadyQPS:   50,
				SteadyBurst: 100,
				BurstQPS:    200,
				BurstBurst:  200,
				QuietQPS:    5,
				QuietBurst:  10,
			},

			MaxResources: 200,

			// Raw strings for serialization
			SteadyMinDelayStr:  "100ms",
			SteadyMaxDelayStr:  "2s",
			BurstMinDelayStr:   "0ms",
			BurstMaxDelayStr:   "500ms",
			QuietMinDelayStr:   "2s",
			QuietMaxDelayStr:   "5s",
			PhaseDurationMinStr: "5m",
			PhaseDurationMaxStr: "15m",
			KubectlTimeoutStr:  "30s",
			SLAThresholdStr:    "2s",
		},
		Chaos: ChaosConfig{
			Enabled:                true,
			InitialStabilityPeriod: 5 * time.Minute,
			GlobalCooldown:         30 * time.Second,
			InitialStabilityPeriodStr: "5m",
			GlobalCooldownStr:         "30s",

			KillDaemon: ChaosTypeConfig{
				Enabled:        true,
				IntervalMin:    30 * time.Minute,
				IntervalMax:    60 * time.Minute,
				IntervalMinStr: "30m",
				IntervalMaxStr: "60m",
			},
			DeleteSocket: ChaosTypeConfig{
				Enabled:        true,
				IntervalMin:    15 * time.Minute,
				IntervalMax:    45 * time.Minute,
				IntervalMinStr: "15m",
				IntervalMaxStr: "45m",
			},
			CorruptTokenFiles: ChaosTypeConfig{
				Enabled:        true,
				IntervalMin:    30 * time.Minute,
				IntervalMax:    90 * time.Minute,
				IntervalMinStr: "30m",
				IntervalMaxStr: "90m",
			},
			FillConnections: ChaosTypeConfig{
				Enabled:         true,
				IntervalMin:     30 * time.Minute,
				IntervalMax:     60 * time.Minute,
				HoldDuration:    5 * time.Second,
				TargetCount:     260,
				IntervalMinStr:  "30m",
				IntervalMaxStr:  "60m",
				HoldDurationStr: "5s",
			},
			FillDisk: ChaosTypeConfig{
				Enabled:         true,
				IntervalMin:     45 * time.Minute,
				IntervalMax:     90 * time.Minute,
				HoldDuration:    10 * time.Second,
				MaxFillBytes:    1073741824, // 1GB
				IntervalMinStr:  "45m",
				IntervalMaxStr:  "90m",
				HoldDurationStr: "10s",
			},
		},
		Health: HealthConfig{
			PollInterval:     10 * time.Second,
			HangThreshold:    30 * time.Second,
			ExitThreshold:    5 * time.Minute,
			MemoryWarnMB:     100,
			MemoryKillMB:     500,
			IdleAwareProbing: true,
			PollIntervalStr:  "10s",
			HangThresholdStr: "30s",
			ExitThresholdStr: "5m",
		},
		Reaper: ReaperConfig{
			Interval:    5 * time.Minute,
			MaxAge:      1 * time.Hour,
			IntervalStr: "5m",
			MaxAgeStr:   "1h",
		},
		Report: ReportConfig{
			Percentiles:     []int{50, 90, 95, 99},
			IncludeTimeline: true,
		},
	}
}
