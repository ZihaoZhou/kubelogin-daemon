package internal

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// RandomDuration returns a random duration between min and max using crypto/rand.
func RandomDuration(rng interface{ Int63n(int64) int64 }, min, max time.Duration) time.Duration {
	if min >= max {
		return min
	}
	delta := max - min
	n := rng.Int63n(int64(delta))
	return min + time.Duration(n)
}

// RandomInt returns a random int in [min, max] inclusive.
func RandomInt(rng interface{ Intn(int) int }, min, max int) int {
	if min >= max {
		return min
	}
	return min + rng.Intn(max-min+1)
}

// RandomHex returns n random hex characters.
func RandomHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)[:n]
}

// SecureRandomInt64 returns a cryptographically random int64.
func SecureRandomInt64() int64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	return n.Int64()
}

// RedactArgs sanitizes kubectl arguments for logging, removing sensitive values.
func RedactArgs(args []string) []string {
	redacted := make([]string, len(args))
	for i, a := range args {
		// Redact values that look like tokens or secrets
		if strings.HasPrefix(a, "eyJ") || len(a) > 100 {
			redacted[i] = "[REDACTED]"
		} else {
			redacted[i] = a
		}
	}
	return redacted
}

// Truncate truncates a string to maxLen, appending "..." if truncated.
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
