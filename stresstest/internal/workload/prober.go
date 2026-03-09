package workload

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/daemon"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/metrics"
)

// DirectSocketProber tests the daemon via direct IPC (bypassing kubectl).
type DirectSocketProber struct {
	socketPath string
	runtimeDir string
	maxWorkers int
	recorder   *metrics.Recorder
	slaThresh  time.Duration
}

// NewDirectSocketProber creates a new prober.
func NewDirectSocketProber(socketPath, runtimeDir string, maxWorkers int, recorder *metrics.Recorder, slaThreshold time.Duration) *DirectSocketProber {
	return &DirectSocketProber{
		socketPath: socketPath,
		runtimeDir: runtimeDir,
		maxWorkers: maxWorkers,
		recorder:   recorder,
		slaThresh:  slaThreshold,
	}
}

// ProbeHealth performs a single health probe via the daemon socket.
func (p *DirectSocketProber) ProbeHealth() (time.Duration, error) {
	start := time.Now()
	conn, err := daemon.TransportDial(daemon.TransportAddress(p.runtimeDir), 2*time.Second)
	if err != nil {
		return time.Since(start), err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Reload nonce from file on every probe — daemon restarts regenerate the nonce
	nonce, err := os.ReadFile(filepath.Join(p.runtimeDir, "nonce"))
	if err != nil {
		return time.Since(start), fmt.Errorf("read nonce: %w", err)
	}

	req := daemon.Request{
		Version: daemon.ProtocolVersion,
		Command: "health",
		Nonce:   string(nonce),
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return time.Since(start), fmt.Errorf("encode request: %w", err)
	}

	var resp daemon.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return time.Since(start), fmt.Errorf("decode response: %w", err)
	}
	if resp.Status != "ok" {
		return time.Since(start), fmt.Errorf("daemon returned status %q: %s", resp.Status, resp.Error)
	}

	return time.Since(start), nil
}

// RunProbes runs count probes using a bounded worker pool.
func (p *DirectSocketProber) RunProbes(count int) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, p.maxWorkers)

	for i := 0; i < count; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			dur, err := p.ProbeHealth()
			ts := time.Now()

			failClass := ""
			errText := ""
			if err != nil {
				errText = err.Error()
				failClass = string(FailDaemonDown)
				if errText != "" && !isConnectionError(errText) {
					failClass = string(FailDaemonError)
				}
			}

			slaViolation := dur > p.slaThresh

			p.recorder.RecordResult(
				ts,
				string(CatDirectIPC),
				"health_probe",
				nil,
				0,
				dur,
				failClass,
				errText,
				"",
				slaViolation,
				false,
			)
		}()
	}
	wg.Wait()
}

func isConnectionError(errText string) bool {
	for _, pat := range []string{"connection refused", "no such file", "read nonce"} {
		if len(errText) > 0 && contains(errText, pat) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && findSubstring(s, substr))
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
