package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/codewiresh/codewire/internal/config"
	"github.com/codewiresh/codewire/internal/platform"
)

func TestLoadRelayAuthUsesOverridesWithoutConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CODEWIRE_RELAY_URL", "")
	t.Setenv("CODEWIRE_API_KEY", "")
	t.Setenv("CODEWIRE_RELAY_NETWORK", "")

	dir := t.TempDir()
	relayURL, authToken, networkID, err := loadRelayAuth(dir, RelayAuthOptions{
		RelayURL:  "http://127.0.0.1:8080",
		AuthToken: "dev-secret",
		NetworkID: "alpha",
	})
	if err != nil {
		t.Fatalf("loadRelayAuth returned error: %v", err)
	}
	if relayURL != "http://127.0.0.1:8080" {
		t.Fatalf("relayURL = %q, want override", relayURL)
	}
	if authToken != "dev-secret" {
		t.Fatalf("authToken = %q, want override", authToken)
	}
	if networkID != "alpha" {
		t.Fatalf("networkID = %q, want override", networkID)
	}
}

func TestLoadRelayAuthUsesEnvFallback(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CODEWIRE_RELAY_URL", "http://127.0.0.1:8080")
	t.Setenv("CODEWIRE_API_KEY", "env-token")
	t.Setenv("CODEWIRE_RELAY_NETWORK", "env-network")

	dir := t.TempDir()
	relayURL, authToken, networkID, err := loadRelayAuth(dir, RelayAuthOptions{})
	if err != nil {
		t.Fatalf("loadRelayAuth returned error: %v", err)
	}
	if relayURL != "http://127.0.0.1:8080" {
		t.Fatalf("relayURL = %q, want env value", relayURL)
	}
	if authToken != "env-token" {
		t.Fatalf("authToken = %q, want env value", authToken)
	}
	if networkID != "env-network" {
		t.Fatalf("networkID = %q, want env value", networkID)
	}
}

func TestLoadRelayAuthOverridesConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CODEWIRE_RELAY_URL", "")
	t.Setenv("CODEWIRE_API_KEY", "")
	t.Setenv("CODEWIRE_RELAY_NETWORK", "")

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	content := []byte("relay_url = \"https://relay.example.com\"\nrelay_network = \"default\"\n")
	if err := os.WriteFile(configPath, content, 0o644); err != nil {
		t.Fatalf("WriteFile(config.toml): %v", err)
	}

	relayURL, authToken, networkID, err := loadRelayAuth(dir, RelayAuthOptions{
		RelayURL:  "http://127.0.0.1:8080",
		AuthToken: "dev-secret",
		NetworkID: "alpha",
	})
	if err != nil {
		t.Fatalf("loadRelayAuth returned error: %v", err)
	}
	if relayURL != "http://127.0.0.1:8080" {
		t.Fatalf("relayURL = %q, want override", relayURL)
	}
	if authToken != "dev-secret" {
		t.Fatalf("authToken = %q, want override", authToken)
	}
	if networkID != "alpha" {
		t.Fatalf("networkID = %q, want override", networkID)
	}
}

func TestUseNetworkPersistsConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	if err := UseNetwork(dir, "project-alpha"); err != nil {
		t.Fatalf("UseNetwork: %v", err)
	}

	_, _, networkID, err := loadRelayAuth(dir, RelayAuthOptions{
		RelayURL:  "http://127.0.0.1:8080",
		AuthToken: "dev-secret",
	})
	if err != nil {
		t.Fatalf("loadRelayAuth: %v", err)
	}
	if networkID != "project-alpha" {
		t.Fatalf("networkID = %q, want project-alpha", networkID)
	}
}

func TestLoadRelayAuthFallsBackToPlatformLogin(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEWIRE_RELAY_URL", "")
	t.Setenv("CODEWIRE_API_KEY", "")
	t.Setenv("CODEWIRE_RELAY_NETWORK", "")

	if err := platform.SaveConfig(&platform.PlatformConfig{
		ServerURL:    "https://codewire.sh",
		SessionToken: "platform-token",
	}); err != nil {
		t.Fatalf("SaveConfig(platform): %v", err)
	}

	dir := t.TempDir()
	relayURL, authToken, networkID, err := loadRelayAuth(dir, RelayAuthOptions{})
	if err != nil {
		t.Fatalf("loadRelayAuth returned error: %v", err)
	}
	if relayURL != "https://relay.codewire.sh" {
		t.Fatalf("relayURL = %q, want hosted relay URL", relayURL)
	}
	if authToken != "platform-token" {
		t.Fatalf("authToken = %q, want platform token", authToken)
	}
	if networkID != "" {
		t.Fatalf("networkID = %q, want empty", networkID)
	}
}

func TestCreateNetworkCreatesAndSelectsNetwork(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	origClient := relayHTTPClient
	defer func() { relayHTTPClient = origClient }()

	dir := t.TempDir()

	sawCreate := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/networks" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer dev-secret" {
			t.Fatalf("Authorization = %q", got)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if body["network_id"] != "project-beta" {
			t.Fatalf("network_id = %q", body["network_id"])
		}
		sawCreate = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":     "created",
			"network_id": "project-beta",
		})
	}))
	defer srv.Close()
	relayHTTPClient = srv.Client()

	if err := CreateNetwork(dir, "project-beta", RelayAuthOptions{
		RelayURL:  srv.URL,
		AuthToken: "dev-secret",
	}, true); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if !sawCreate {
		t.Fatal("expected create request")
	}

	_, _, networkID, err := loadRelayAuth(dir, RelayAuthOptions{
		RelayURL:  srv.URL,
		AuthToken: "dev-secret",
	})
	if err != nil {
		t.Fatalf("loadRelayAuth: %v", err)
	}
	if networkID != "project-beta" {
		t.Fatalf("networkID = %q, want project-beta", networkID)
	}
}

func TestJoinNetworkPersistsEnrollment(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := platform.SaveConfig(&platform.PlatformConfig{
		ServerURL:    "https://codewire.sh",
		SessionToken: "platform-token",
	}); err != nil {
		t.Fatalf("SaveConfig(platform): %v", err)
	}

	dir := t.TempDir()
	if err := JoinNetwork(dir, "https://relay.example.com", "CW-INV-TEST"); err == nil {
		t.Fatal("expected error without a relay test server")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/networks/join" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer platform-token" {
			t.Fatalf("Authorization = %q", got)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if body["invite_token"] != "CW-INV-TEST" {
			t.Fatalf("invite_token = %q", body["invite_token"])
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"network_id": "project-alpha",
		})
	}))
	defer srv.Close()

	if err := JoinNetwork(dir, srv.URL, "CW-INV-TEST"); err != nil {
		t.Fatalf("JoinNetwork: %v", err)
	}

	cfg, err := config.LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.RelayURL == nil || *cfg.RelayURL != srv.URL {
		t.Fatalf("RelayURL = %#v", cfg.RelayURL)
	}
	if cfg.RelayNetwork == nil || *cfg.RelayNetwork != "project-alpha" {
		t.Fatalf("RelayNetwork = %#v", cfg.RelayNetwork)
	}
	if cfg.RelayToken != nil {
		t.Fatalf("RelayToken = %#v, want nil", cfg.RelayToken)
	}
}
