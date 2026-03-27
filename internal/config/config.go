package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/codewiresh/codewire/internal/platform"
)

// Config is the top-level configuration loaded from config.toml.
type Config struct {
	Node                 NodeConfig           `toml:"node"`
	RelayURL             *string              `toml:"relay_url,omitempty"`
	RelayNetwork         *string              `toml:"relay_network,omitempty"`
	RelayToken           *string              `toml:"relay_token,omitempty"`             // node auth token for relay agent
	RelayInviteToken     *string              `toml:"relay_invite_token,omitempty"`      // one-time invite token for bootstrap
	RelayAutoJoinPrivate *bool                `toml:"relay_auto_join_private,omitempty"` // consent for auto-joining the selected private network
	CurrentTarget        *CurrentTargetConfig `toml:"current_target,omitempty"`
}

type CurrentTargetConfig struct {
	Kind string `toml:"kind"`
	Ref  string `toml:"ref"`
	Name string `toml:"name,omitempty"`
}

// NodeConfig describes the local node identity and network settings.
type NodeConfig struct {
	// Human-readable name for this node (used in relay discovery).
	Name string `toml:"name"`
	// WebSocket listen address (e.g. "0.0.0.0:9100"). Nil means no listener.
	Listen *string `toml:"listen,omitempty"`
	// Externally-accessible WSS URL for relay discovery
	// (e.g. "wss://9100--workspace.coder.codewire.sh/ws").
	ExternalURL *string `toml:"external_url,omitempty"`
}

// ServerEntry is a saved remote server (client-side).
type ServerEntry struct {
	URL   string `toml:"url"`
	Token string `toml:"token"`
}

// ServersConfig is the client-side servers list (~/.codewire/servers.toml).
type ServersConfig struct {
	Servers map[string]ServerEntry `toml:"servers"`
}

var validNodeName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// ValidateNodeName checks that name is non-empty and contains only
// alphanumeric characters, hyphens, or underscores. Dots are forbidden
// because NATS uses them as subject delimiters.
func ValidateNodeName(name string) error {
	if name == "" || !validNodeName.MatchString(name) {
		return fmt.Errorf("node name must be non-empty and alphanumeric (with - or _), got: %q", name)
	}
	return nil
}

// defaultName derives a node name from the HOSTNAME or HOST environment
// variable, sanitising invalid characters to hyphens. Falls back to
// "codewire" if neither variable is set.
func defaultName() string {
	raw := os.Getenv("HOSTNAME")
	if raw == "" {
		raw = os.Getenv("HOST")
	}
	if raw == "" {
		return "codewire"
	}
	out := make([]byte, len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			out[i] = c
		} else {
			out[i] = '-'
		}
	}
	return string(out)
}

// LoadConfig reads config.toml from dataDir, applies environment variable
// overrides, and validates the node name before returning.
func LoadConfig(dataDir string) (*Config, error) {
	path := filepath.Join(dataDir, "config.toml")

	cfg := &Config{
		Node: NodeConfig{
			Name: defaultName(),
		},
	}

	if _, err := os.Stat(path); err == nil {
		if _, err := toml.DecodeFile(path, cfg); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		// If the file was parsed but node.name was empty/missing, apply default.
		if cfg.Node.Name == "" {
			cfg.Node.Name = defaultName()
		}
	}

	// Override node config from env vars.
	if name := os.Getenv("CODEWIRE_NODE_NAME"); name != "" {
		cfg.Node.Name = name
	}
	if cfg.Node.Listen == nil {
		if listen := os.Getenv("CODEWIRE_LISTEN"); listen != "" {
			cfg.Node.Listen = &listen
		}
	}
	if cfg.Node.ExternalURL == nil {
		if extURL := os.Getenv("CODEWIRE_EXTERNAL_URL"); extURL != "" {
			cfg.Node.ExternalURL = &extURL
		}
	}

	// Relay URL from env var.
	if cfg.RelayURL == nil {
		if relayURL := os.Getenv("CODEWIRE_RELAY_URL"); relayURL != "" {
			cfg.RelayURL = &relayURL
		}
	}
	// Relay token from env var.
	if cfg.RelayToken == nil {
		if t := os.Getenv("CODEWIRE_RELAY_TOKEN"); t != "" {
			cfg.RelayToken = &t
		}
	}
	if cfg.RelayInviteToken == nil {
		if invite := os.Getenv("CODEWIRE_RELAY_INVITE_TOKEN"); invite != "" {
			cfg.RelayInviteToken = &invite
		}
	}
	if cfg.RelayNetwork == nil {
		if network := os.Getenv("CODEWIRE_RELAY_NETWORK"); network != "" {
			cfg.RelayNetwork = &network
		}
	}
	if cfg.RelayURL == nil {
		if relayURL := deriveHostedRelayURL(); relayURL != "" {
			cfg.RelayURL = &relayURL
		}
	}

	if err := ValidateNodeName(cfg.Node.Name); err != nil {
		return nil, err
	}

	return cfg, nil
}

func deriveHostedRelayURL() string {
	platformCfg, err := platform.LoadConfig()
	if err != nil || strings.TrimSpace(platformCfg.ServerURL) == "" {
		return ""
	}

	serverURL, err := url.Parse(strings.TrimSpace(platformCfg.ServerURL))
	if err != nil || serverURL.Hostname() == "" {
		return ""
	}

	host := serverURL.Hostname()
	switch host {
	case "codewire.sh", "www.codewire.sh", "app.codewire.sh", "api.codewire.sh":
		host = "relay.codewire.sh"
	default:
		return ""
	}

	scheme := serverURL.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + host
}

// SaveConfig writes config.toml inside dataDir, creating the directory if needed.
func SaveConfig(dataDir string, cfg *Config) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}

	path := filepath.Join(dataDir, "config.toml")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()

	if err := toml.NewEncoder(f).Encode(cfg); err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}

	return nil
}

// LoadServersConfig reads servers.toml from dataDir. If the file does not
// exist an empty ServersConfig is returned.
func LoadServersConfig(dataDir string) (*ServersConfig, error) {
	path := filepath.Join(dataDir, "servers.toml")

	sc := &ServersConfig{
		Servers: make(map[string]ServerEntry),
	}

	if _, err := os.Stat(path); err != nil {
		// File does not exist — return empty config.
		return sc, nil
	}

	if _, err := toml.DecodeFile(path, sc); err != nil {
		return nil, fmt.Errorf("parsing servers.toml: %w", err)
	}

	return sc, nil
}

// Save writes the ServersConfig to servers.toml inside dataDir, creating
// the directory if necessary.
func (s *ServersConfig) Save(dataDir string) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}

	path := filepath.Join(dataDir, "servers.toml")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()

	enc := toml.NewEncoder(f)
	if err := enc.Encode(s); err != nil {
		return fmt.Errorf("encoding servers.toml: %w", err)
	}

	return nil
}
