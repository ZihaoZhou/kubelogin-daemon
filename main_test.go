package main

import (
	"testing"
)

func TestParseExecArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantURL  string
		wantID   string
		wantGT   string
		wantAT   bool
	}{
		{
			name:    "standard flags",
			args:    []string{"get-token", "--oidc-issuer-url", "https://auth.example.com", "--oidc-client-id", "k8s"},
			wantURL: "https://auth.example.com",
			wantID:  "k8s",
		},
		{
			name:    "equals style",
			args:    []string{"get-token", "--oidc-issuer-url=https://auth.example.com", "--oidc-client-id=k8s"},
			wantURL: "https://auth.example.com",
			wantID:  "k8s",
		},
		{
			name:    "with grant type and scopes",
			args:    []string{"get-token", "--oidc-issuer-url", "https://auth.example.com", "--oidc-client-id", "k8s", "--grant-type", "authcode-browser", "--oidc-extra-scope", "groups"},
			wantURL: "https://auth.example.com",
			wantID:  "k8s",
			wantGT:  "authcode-browser",
		},
		{
			name:   "use access token flag (bool)",
			args:   []string{"get-token", "--oidc-issuer-url", "https://auth.example.com", "--oidc-client-id", "k8s", "--oidc-use-access-token"},
			wantURL: "https://auth.example.com",
			wantID:  "k8s",
			wantAT:  true,
		},
		{
			name:    "use-access-token=true",
			args:    []string{"get-token", "--oidc-issuer-url", "https://auth.example.com", "--oidc-client-id", "k8s", "--oidc-use-access-token=true"},
			wantURL: "https://auth.example.com",
			wantID:  "k8s",
			wantAT:  true,
		},
		{
			name:    "use-access-token=false (no infinite loop)",
			args:    []string{"get-token", "--oidc-issuer-url", "https://auth.example.com", "--oidc-client-id", "k8s", "--oidc-use-access-token=false"},
			wantURL: "https://auth.example.com",
			wantID:  "k8s",
			wantAT:  false,
		},
		{
			name:    "use-access-token followed by other flag",
			args:    []string{"get-token", "--oidc-use-access-token", "--oidc-issuer-url", "https://auth.example.com", "--oidc-client-id", "k8s"},
			wantURL: "https://auth.example.com",
			wantID:  "k8s",
			wantAT:  true,
		},
		{
			name: "empty args",
			args: []string{"get-token"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := parseExecArgs(tt.args)
			if cfg.issuerURL != tt.wantURL {
				t.Errorf("issuerURL: want %q, got %q", tt.wantURL, cfg.issuerURL)
			}
			if cfg.clientID != tt.wantID {
				t.Errorf("clientID: want %q, got %q", tt.wantID, cfg.clientID)
			}
			if tt.wantGT != "" && cfg.grantType != tt.wantGT {
				t.Errorf("grantType: want %q, got %q", tt.wantGT, cfg.grantType)
			}
			if cfg.useAccessToken != tt.wantAT {
				t.Errorf("useAccessToken: want %v, got %v", tt.wantAT, cfg.useAccessToken)
			}
		})
	}
}
