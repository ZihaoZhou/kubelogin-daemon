package chaos

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

// corruptTokenFiles corrupts persisted token files using one of 4 strategies.
func (e *Engine) corruptTokenFiles(ctx context.Context) (ChaosEvent, error) {
	event := ChaosEvent{
		Timestamp: time.Now(),
		Type:      "corrupt_token_files",
	}

	// Find token files in runtime dir (*.json)
	pattern := filepath.Join(e.runtimeDir, "*.json")
	files, err := filepath.Glob(pattern)
	if err != nil || len(files) == 0 {
		event.Description = "corrupt_token_files: no token files found"
		return event, nil
	}

	// Pick a random file and strategy
	target := files[e.rng.Intn(len(files))]
	strategy := e.rng.Intn(4)

	var strategyName string
	switch strategy {
	case 0:
		// Random bytes
		strategyName = "random_bytes"
		garbage := make([]byte, 128)
		rand.Read(garbage)
		err = os.WriteFile(target, garbage, 0600)
	case 1:
		// Truncate to zero
		strategyName = "truncate_zero"
		err = os.WriteFile(target, []byte{}, 0600)
	case 2:
		// Wrong format_version
		strategyName = "wrong_format_version"
		err = os.WriteFile(target, []byte(`{"format_version":9999,"key":"test"}`), 0600)
	case 3:
		// Partial JSON (unexpected end of input)
		strategyName = "partial_json"
		err = os.WriteFile(target, []byte(`{"format_version":1,"id_token":"eyJ`), 0600)
	}

	if err != nil {
		event.Description = fmt.Sprintf("corrupt_token_files: strategy %s failed on %s: %v",
			strategyName, filepath.Base(target), err)
		return event, err
	}

	event.Description = fmt.Sprintf("corrupt_token_files: applied %s to %s",
		strategyName, filepath.Base(target))

	return event, nil
}
