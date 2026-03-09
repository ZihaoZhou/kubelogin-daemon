package main

import (
	"strings"
	"testing"
)

// Attack vector: parseExecArgs with empty args.
func TestAdversarial_ParseExecArgs_Empty(t *testing.T) {
	cfg := parseExecArgs(nil)
	if cfg.issuerURL != "" || cfg.clientID != "" {
		t.Error("empty args should return empty config")
	}

	cfg2 := parseExecArgs([]string{})
	if cfg2.issuerURL != "" || cfg2.clientID != "" {
		t.Error("empty slice should return empty config")
	}
}

// Attack vector: parseExecArgs with just the command name.
func TestAdversarial_ParseExecArgs_CommandOnly(t *testing.T) {
	cfg := parseExecArgs([]string{"get-token"})
	if cfg.issuerURL != "" || cfg.clientID != "" {
		t.Error("command-only should return empty OIDC config")
	}
}

// Attack vector: parseExecArgs with --flag=value format.
func TestAdversarial_ParseExecArgs_EqualsFormat(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-issuer-url=https://example.com",
		"--oidc-client-id=test-client",
	})
	if cfg.issuerURL != "https://example.com" {
		t.Errorf("issuer URL: %q", cfg.issuerURL)
	}
	if cfg.clientID != "test-client" {
		t.Errorf("client ID: %q", cfg.clientID)
	}
}

// Attack vector: parseExecArgs with --flag value format.
func TestAdversarial_ParseExecArgs_SpaceFormat(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-issuer-url", "https://example.com",
		"--oidc-client-id", "test-client",
	})
	if cfg.issuerURL != "https://example.com" {
		t.Errorf("issuer URL: %q", cfg.issuerURL)
	}
	if cfg.clientID != "test-client" {
		t.Errorf("client ID: %q", cfg.clientID)
	}
}

// Attack vector: parseExecArgs with flag value that starts with "--".
// The parser uses HasPrefix(args[i+1], "--") to decide if next arg is a value.
// This means a value like "--weird-value" would be treated as a flag, not a value.
func TestAdversarial_ParseExecArgs_ValueStartsWithDash(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-issuer-url", "--https://example.com",
	})
	// The parser sees "--https://example.com" starts with "--" and treats it as a new flag.
	// So issuerURL should be empty (the value was consumed as a flag name).
	if cfg.issuerURL == "--https://example.com" {
		t.Log("parseExecArgs correctly handled value starting with -- (treated as flag)")
	} else if cfg.issuerURL == "" {
		t.Log("FINDING: parseExecArgs cannot handle values starting with '--' in space-separated format. Value is lost.")
	} else {
		t.Errorf("unexpected issuer URL: %q", cfg.issuerURL)
	}
}

// Attack vector: parseExecArgs with duplicate flags — last one wins?
func TestAdversarial_ParseExecArgs_DuplicateFlags(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-issuer-url", "https://first.com",
		"--oidc-issuer-url", "https://second.com",
	})
	if cfg.issuerURL != "https://second.com" {
		t.Errorf("duplicate flags: expected last-wins, got %q", cfg.issuerURL)
	}
}

// Attack vector: parseExecArgs with --oidc-extra-scope repeated.
func TestAdversarial_ParseExecArgs_MultipleExtraScopes(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-extra-scope", "groups",
		"--oidc-extra-scope", "email",
		"--oidc-extra-scope", "profile",
	})
	if len(cfg.extraScopes) != 3 {
		t.Errorf("expected 3 extra scopes, got %d: %v", len(cfg.extraScopes), cfg.extraScopes)
	}
}

// Attack vector: --oidc-use-access-token edge cases (boolean flag).
func TestAdversarial_ParseExecArgs_UseAccessTokenEdgeCases(t *testing.T) {
	// Bare flag
	cfg1 := parseExecArgs([]string{"get-token", "--oidc-use-access-token"})
	if !cfg1.useAccessToken {
		t.Error("bare --oidc-use-access-token should be true")
	}

	// --flag=true
	cfg2 := parseExecArgs([]string{"get-token", "--oidc-use-access-token=true"})
	if !cfg2.useAccessToken {
		t.Error("--oidc-use-access-token=true should be true")
	}

	// --flag=false
	cfg3 := parseExecArgs([]string{"get-token", "--oidc-use-access-token=false"})
	if cfg3.useAccessToken {
		t.Error("--oidc-use-access-token=false should be false")
	}

	// --flag= (empty value)
	cfg4 := parseExecArgs([]string{"get-token", "--oidc-use-access-token="})
	if !cfg4.useAccessToken {
		t.Error("--oidc-use-access-token= (empty) should be true per code logic")
	}
}

// Attack vector: --oidc-use-access-token followed by another flag.
func TestAdversarial_ParseExecArgs_UseAccessTokenFollowedByFlag(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-use-access-token",
		"--oidc-client-id", "test",
	})
	if !cfg.useAccessToken {
		t.Error("--oidc-use-access-token before another flag should be true")
	}
	if cfg.clientID != "test" {
		t.Errorf("client ID should be 'test', got %q", cfg.clientID)
	}
}

// Attack vector: --oidc-use-access-token followed by a non-flag value.
// Since --oidc-use-access-token is a known boolean flag, it should NOT consume
// the next argument as its value.
func TestAdversarial_ParseExecArgs_UseAccessTokenFollowedByValue(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-use-access-token", "some-value",
		"--oidc-client-id", "test",
	})
	// --oidc-use-access-token is a boolean flag — bare form means true.
	// "some-value" should NOT be consumed as its value.
	if !cfg.useAccessToken {
		t.Error("bare --oidc-use-access-token should be true")
	}
	// "some-value" is a positional arg (non-flag), skipped by the parser.
	// The client ID should still be "test".
	if cfg.clientID != "test" {
		t.Errorf("client ID mismatch: %q (value consumption issue)", cfg.clientID)
	}
}

// Attack vector: parseExecArgs with trailing flag without value.
func TestAdversarial_ParseExecArgs_TrailingFlagNoValue(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-issuer-url",
	})
	// The flag is at the end with no next arg — should result in empty value
	if cfg.issuerURL != "" {
		t.Errorf("trailing flag without value: expected empty, got %q", cfg.issuerURL)
	}
}

// Attack vector: parseExecArgs with empty string values.
func TestAdversarial_ParseExecArgs_EmptyValues(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-issuer-url=",
		"--oidc-client-id=",
	})
	if cfg.issuerURL != "" {
		t.Errorf("empty value via =: expected empty, got %q", cfg.issuerURL)
	}
}

// Attack vector: parseExecArgs with values containing = sign.
func TestAdversarial_ParseExecArgs_ValueWithEquals(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-issuer-url=https://example.com?foo=bar",
	})
	if cfg.issuerURL != "https://example.com?foo=bar" {
		t.Errorf("value with equals: expected 'https://example.com?foo=bar', got %q", cfg.issuerURL)
	}
}

// Attack vector: parseExecArgs with very long values.
func TestAdversarial_ParseExecArgs_VeryLongValues(t *testing.T) {
	longValue := "https://" + strings.Repeat("a", 1<<20) + ".example.com"
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-issuer-url", longValue,
	})
	if cfg.issuerURL != longValue {
		t.Error("very long value should be preserved")
	}
}

// Attack vector: parseExecArgs with unknown flags (silently ignored).
func TestAdversarial_ParseExecArgs_UnknownFlags(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--evil-flag", "evil-value",
		"--oidc-issuer-url", "https://example.com",
		"--another-bad-flag=bad",
	})
	if cfg.issuerURL != "https://example.com" {
		t.Errorf("issuer URL after unknown flags: %q", cfg.issuerURL)
	}
}

// Attack vector: parseExecArgs with flag injection via value.
// If a value contains a newline or special chars, it might cause issues.
func TestAdversarial_ParseExecArgs_SpecialCharsInValue(t *testing.T) {
	specialValues := []struct {
		name  string
		value string
	}{
		{"newline", "https://example.com\n--evil-flag"},
		{"tab", "https://example.com\t--evil-flag"},
		{"null byte", "https://example.com\x00--evil"},
		{"unicode", "https://\u4e2d\u6587.example.com"},
		{"spaces", "https://example.com/path with spaces"},
		{"quotes", `https://example.com/'test'`},
		{"backslash", `https://example.com\test`},
	}

	for _, tc := range specialValues {
		t.Run(tc.name, func(t *testing.T) {
			cfg := parseExecArgs([]string{
				"get-token",
				"--oidc-issuer-url=" + tc.value,
			})
			if cfg.issuerURL != tc.value {
				t.Errorf("special value not preserved: want %q, got %q", tc.value, cfg.issuerURL)
			}
		})
	}
}

// Attack vector: --oidc-extra-scope with empty value.
func TestAdversarial_ParseExecArgs_ExtraScopeEmpty(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-extra-scope", "",
	})
	// Code checks: if val != "" { append }
	// But "" doesn't start with "--", so it's consumed as the value and skipped
	if len(cfg.extraScopes) > 0 {
		t.Errorf("empty extra scope should not be added, got %v", cfg.extraScopes)
	}
}

// Attack vector: --oidc-extra-scope=  (equals with empty).
func TestAdversarial_ParseExecArgs_ExtraScopeEqualsEmpty(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-extra-scope=",
	})
	if len(cfg.extraScopes) > 0 {
		t.Errorf("--oidc-extra-scope= should not add empty scope, got %v", cfg.extraScopes)
	}
}

// Attack vector: interleaved flags from different commands.
func TestAdversarial_ParseExecArgs_InterleavedFlags(t *testing.T) {
	cfg := parseExecArgs([]string{
		"get-token",
		"--oidc-issuer-url", "https://example.com",
		"--grant-type", "device-code",
		"--oidc-client-id", "test",
		"--oidc-client-secret", "secret",
		"--oidc-extra-scope", "groups",
		"--oidc-use-access-token",
	})
	if cfg.issuerURL != "https://example.com" {
		t.Errorf("issuer URL: %q", cfg.issuerURL)
	}
	if cfg.clientID != "test" {
		t.Errorf("client ID: %q", cfg.clientID)
	}
	if cfg.clientSecret != "secret" {
		t.Errorf("client secret: %q", cfg.clientSecret)
	}
	if cfg.grantType != "device-code" {
		t.Errorf("grant type: %q", cfg.grantType)
	}
	if len(cfg.extraScopes) != 1 || cfg.extraScopes[0] != "groups" {
		t.Errorf("extra scopes: %v", cfg.extraScopes)
	}
	if !cfg.useAccessToken {
		t.Error("use access token should be true")
	}
}
