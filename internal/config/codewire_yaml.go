package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// CodewireConfig represents the codewire.yaml schema.
type CodewireConfig struct {
	Preset             string            `yaml:"preset,omitempty"`
	Image              string            `yaml:"image,omitempty"`
	Install            string            `yaml:"install,omitempty"`
	Startup            string            `yaml:"startup,omitempty"`
	Secrets            string            `yaml:"secrets,omitempty"`
	Env                map[string]string `yaml:"env,omitempty"`
	Ports              []PortConfig      `yaml:"ports,omitempty"`
	CPU                int               `yaml:"cpu,omitempty"`
	Memory             int               `yaml:"memory,omitempty"`
	Disk               int               `yaml:"disk,omitempty"`
	Agent              string            `yaml:"agent,omitempty"`
	IncludeOrgSecrets  *bool             `yaml:"include_org_secrets,omitempty"`
	IncludeUserSecrets *bool             `yaml:"include_user_secrets,omitempty"`
}

// PortConfig represents a port in codewire.yaml.
type PortConfig struct {
	Port  int    `yaml:"port"`
	Label string `yaml:"label"`
}

// LoadCodewireConfig reads and parses a codewire.yaml file.
func LoadCodewireConfig(path string) (*CodewireConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg CodewireConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	return &cfg, nil
}

// WriteCodewireConfig writes a codewire.yaml file.
func WriteCodewireConfig(path string, cfg *CodewireConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
