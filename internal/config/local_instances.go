package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// LocalInstancesConfig stores local runtime instances managed by cw.
type LocalInstancesConfig struct {
	Instances map[string]LocalInstance `toml:"instances"`
}

// LocalInstance records the persisted state for a local runtime instance.
type LocalInstance struct {
	Name               string            `toml:"name"`
	Backend            string            `toml:"backend"`
	RuntimeName        string            `toml:"runtime_name"`
	RepoPath           string            `toml:"repo_path"`
	Workdir            string            `toml:"workdir"`
	Preset             string            `toml:"preset,omitempty"`
	Image              string            `toml:"image,omitempty"`
	Install            string            `toml:"install,omitempty"`
	Startup            string            `toml:"startup,omitempty"`
	Secrets            string            `toml:"secrets,omitempty"`
	Env                map[string]string `toml:"env,omitempty"`
	Ports              []PortConfig      `toml:"ports,omitempty"`
	CPU                int               `toml:"cpu,omitempty"`
	Memory             int               `toml:"memory,omitempty"`
	Disk               int               `toml:"disk,omitempty"`
	Agent              string            `toml:"agent,omitempty"`
	IncludeOrgSecrets  *bool             `toml:"include_org_secrets,omitempty"`
	IncludeUserSecrets *bool             `toml:"include_user_secrets,omitempty"`

	// Firecracker-specific fields (only populated when Backend == "firecracker")
	FirecrackerPID    int    `toml:"firecracker_pid,omitempty"`
	FirecrackerSocket string `toml:"firecracker_socket,omitempty"`
	KernelPath        string `toml:"kernel_path,omitempty"`
	RootfsPath        string `toml:"rootfs_path,omitempty"`
	CreatedAt          string            `toml:"created_at"`
	LastUsedAt         string            `toml:"last_used_at,omitempty"`
}

func defaultLocalInstancesConfig() *LocalInstancesConfig {
	return &LocalInstancesConfig{
		Instances: map[string]LocalInstance{},
	}
}

// LoadLocalInstancesConfig reads local instance state from dataDir.
func LoadLocalInstancesConfig(dataDir string) (*LocalInstancesConfig, error) {
	path := filepath.Join(dataDir, "local_instances.toml")
	cfg := defaultLocalInstancesConfig()

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if cfg.Instances == nil {
		cfg.Instances = map[string]LocalInstance{}
	}
	return cfg, nil
}

// SaveLocalInstancesConfig writes local instance state to dataDir.
func SaveLocalInstancesConfig(dataDir string, cfg *LocalInstancesConfig) error {
	if cfg == nil {
		cfg = defaultLocalInstancesConfig()
	}
	if cfg.Instances == nil {
		cfg.Instances = map[string]LocalInstance{}
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}

	path := filepath.Join(dataDir, "local_instances.toml")
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
