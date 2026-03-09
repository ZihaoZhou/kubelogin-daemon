package chaos

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// fillDisk writes files to the runtime dir until ENOSPC or cap is reached.
func (e *Engine) fillDisk(ctx context.Context) (ChaosEvent, error) {
	event := ChaosEvent{
		Timestamp: time.Now(),
		Type:      "fill_disk",
	}

	holdDuration := e.cfg.FillDisk.HoldDuration
	maxBytes := e.cfg.FillDisk.MaxFillBytes

	// Create temp files to fill the disk
	const chunkSize = 1024 * 1024 // 1MB chunks
	chunk := make([]byte, chunkSize)
	// Fill with non-zero bytes to ensure actual disk usage
	for i := range chunk {
		chunk[i] = 0xAA
	}

	var filledBytes int64
	var files []string
	enospcReached := false

	for filledBytes < maxBytes {
		if ctx.Err() != nil {
			break
		}

		name := filepath.Join(e.runtimeDir, fmt.Sprintf("kldst-fill-%d", len(files)))
		f, err := os.Create(name)
		if err != nil {
			enospcReached = true
			break
		}

		n, err := f.Write(chunk)
		f.Close()
		filledBytes += int64(n)
		files = append(files, name)

		if err != nil {
			enospcReached = true
			break
		}
	}

	if enospcReached {
		event.Description = fmt.Sprintf("fill_disk: ENOSPC after %d bytes (%d files)", filledBytes, len(files))
	} else {
		event.Description = fmt.Sprintf("fill_disk: wrote %d bytes (%d files, cap reached without ENOSPC)", filledBytes, len(files))
	}
	event.DurationHeld = holdDuration

	// Hold the disk full state
	select {
	case <-time.After(holdDuration):
	case <-ctx.Done():
	}

	// Cleanup: remove all fill files
	cleanupErrors := 0
	for _, name := range files {
		if err := os.Remove(name); err != nil {
			cleanupErrors++
		}
	}

	if cleanupErrors > 0 {
		event.Description += fmt.Sprintf(", cleanup errors: %d", cleanupErrors)
	}

	return event, nil
}
