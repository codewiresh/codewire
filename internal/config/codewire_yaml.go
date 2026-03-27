package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// CodewireConfig represents the codewire.yaml schema.
type CodewireConfig struct {
	Preset             string                 `yaml:"preset,omitempty"`
	Image              string                 `yaml:"image,omitempty"`
	Install            string                 `yaml:"install,omitempty"`
	Startup            string                 `yaml:"startup,omitempty"`
	Secrets            *CodewireSecretsConfig `yaml:"secrets,omitempty"`
	Env                map[string]string      `yaml:"env,omitempty"`
	Ports              []PortConfig           `yaml:"ports,omitempty"`
	CPU                int                    `yaml:"cpu,omitempty"`
	Memory             int                    `yaml:"memory,omitempty"`
	Disk               int                    `yaml:"disk,omitempty"`
	Agents             *CodewireAgentsConfig  `yaml:"agents,omitempty"`
	Agent              string                 `yaml:"agent,omitempty"`
	InstallAgents      *bool                  `yaml:"install_agents,omitempty"`
	IncludeOrgSecrets  *bool                  `yaml:"include_org_secrets,omitempty"`
	IncludeUserSecrets *bool                  `yaml:"include_user_secrets,omitempty"`
}

// PortConfig represents a port in codewire.yaml.
type PortConfig struct {
	Port  int    `yaml:"port"`
	Label string `yaml:"label"`
}

type CodewireAgentsConfig struct {
	Install *bool    `yaml:"install,omitempty"`
	Tools   []string `yaml:"tools,omitempty"`
}

type CodewireSecretsConfig struct {
	Org     *bool  `yaml:"org,omitempty"`
	User    *bool  `yaml:"user,omitempty"`
	Project string `yaml:"project,omitempty"`
}

func (c *CodewireAgentsConfig) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		c.Tools = []string{strings.TrimSpace(value.Value)}
		return nil
	case yaml.SequenceNode:
		var tools []string
		if err := value.Decode(&tools); err != nil {
			return err
		}
		c.Tools = tools
		return nil
	case yaml.MappingNode:
		type rawAgentsConfig CodewireAgentsConfig
		var out rawAgentsConfig
		if err := value.Decode(&out); err != nil {
			return err
		}
		*c = CodewireAgentsConfig(out)
		return nil
	default:
		return fmt.Errorf("parse agents: expected string, list, or mapping")
	}
}

func (c *CodewireSecretsConfig) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		c.Project = strings.TrimSpace(value.Value)
		return nil
	case yaml.MappingNode:
		type rawSecretsConfig CodewireSecretsConfig
		var out rawSecretsConfig
		if err := value.Decode(&out); err != nil {
			return err
		}
		*c = CodewireSecretsConfig(out)
		return nil
	default:
		return fmt.Errorf("parse secrets: expected string or mapping")
	}
}

func CanonicalAgentID(raw string) string {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "claude", "claude-code":
		return "claude-code"
	case "codex":
		return "codex"
	case "gemini", "gemini-cli":
		return "gemini-cli"
	case "aider":
		return "aider"
	default:
		return strings.TrimSpace(raw)
	}
}

func DisplayAgentID(raw string) string {
	switch CanonicalAgentID(raw) {
	case "claude-code":
		return "claude"
	case "gemini-cli":
		return "gemini"
	default:
		return CanonicalAgentID(raw)
	}
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
