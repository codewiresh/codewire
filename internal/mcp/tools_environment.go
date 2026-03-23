package mcp

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/codewiresh/codewire/internal/platform"
)

func parseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

// getPlatformClient returns a platform client and the default org ID.
func getPlatformClient() (*platform.Client, string, error) {
	client, err := platform.NewClient()
	if err != nil {
		return nil, "", fmt.Errorf("not logged in to Codewire platform (run 'cw login'): %w", err)
	}
	cfg, err := platform.LoadConfig()
	if err != nil {
		return nil, "", err
	}
	if cfg.DefaultOrg == "" {
		return nil, "", fmt.Errorf("no default org set (run 'cw login' and select an org)")
	}
	return client, cfg.DefaultOrg, nil
}

func environmentTools() []tool {
	return []tool{
		{
			Name:        "codewire_list_environments",
			Description: "List environments in the default organization. Returns ID, name, state, type, CPU/memory, TTL, and creation time.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"type": map[string]interface{}{
						"type":        "string",
						"description": "Filter by environment type: 'coder' or 'sandbox'",
						"enum":        []string{"coder", "sandbox"},
					},
					"state": map[string]interface{}{
						"type":        "string",
						"description": "Filter by state (e.g. 'running', 'stopped', 'pending')",
					},
				},
			},
		},
		{
			Name:        "codewire_create_environment",
			Description: "Create a new environment from a preset. Returns the created environment details.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"preset_id": map[string]interface{}{
						"type":        "string",
						"description": "Preset ID to create the environment from (required)",
					},
					"name": map[string]interface{}{
						"type":        "string",
						"description": "Optional name for the environment",
					},
					"ttl": map[string]interface{}{
						"type":        "string",
						"description": "Time to live as duration (e.g. '1h', '30m'). Environment auto-destroys after this.",
					},
					"cpu": map[string]interface{}{
						"type":        "integer",
						"description": "CPU in millicores (e.g. 2000 = 2 cores)",
					},
					"memory": map[string]interface{}{
						"type":        "integer",
						"description": "Memory in MB",
					},
					"disk": map[string]interface{}{
						"type":        "integer",
						"description": "Disk in GB",
					},
				},
				"required": []string{"preset_id"},
			},
		},
		{
			Name:        "codewire_get_environment",
			Description: "Get detailed information about a specific environment including state, resources, and timestamps.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"environment_id": map[string]interface{}{
						"type":        "string",
						"description": "The environment ID",
					},
				},
				"required": []string{"environment_id"},
			},
		},
		{
			Name:        "codewire_stop_environment",
			Description: "Stop a running environment. The environment can be started again later.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"environment_id": map[string]interface{}{
						"type":        "string",
						"description": "The environment ID to stop",
					},
				},
				"required": []string{"environment_id"},
			},
		},
		{
			Name:        "codewire_start_environment",
			Description: "Start a stopped environment.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"environment_id": map[string]interface{}{
						"type":        "string",
						"description": "The environment ID to start",
					},
				},
				"required": []string{"environment_id"},
			},
		},
		{
			Name:        "codewire_delete_environment",
			Description: "Permanently delete an environment. This cannot be undone.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"environment_id": map[string]interface{}{
						"type":        "string",
						"description": "The environment ID to delete",
					},
				},
				"required": []string{"environment_id"},
			},
		},
		{
			Name:        "codewire_list_presets",
			Description: "List available environment presets. Presets define the base configuration for creating environments.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "codewire_exec_in_environment",
			Description: "Execute a command in a running sandbox environment. Returns stdout, stderr, and exit code.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"environment_id": map[string]interface{}{
						"type":        "string",
						"description": "The environment ID to execute in",
					},
					"command": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Command and arguments (e.g. [\"ls\", \"-la\"])",
					},
					"working_dir": map[string]interface{}{
						"type":        "string",
						"description": "Working directory (default: /workspace)",
					},
					"timeout": map[string]interface{}{
						"type":        "integer",
						"description": "Timeout in seconds (default: 30)",
					},
				},
				"required": []string{"environment_id", "command"},
			},
		},
		{
			Name:        "codewire_list_files",
			Description: "List files in a directory in a running sandbox environment.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"environment_id": map[string]interface{}{
						"type":        "string",
						"description": "The environment ID",
					},
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Directory path to list (default: /workspace)",
					},
				},
				"required": []string{"environment_id"},
			},
		},
	}
}

func toolListEnvironments(args map[string]interface{}) (string, error) {
	client, orgID, err := getPlatformClient()
	if err != nil {
		return "", err
	}

	envType, _ := args["type"].(string)
	state, _ := args["state"].(string)

	includeDestroyed, _ := args["include_destroyed"].(bool)
	envs, err := client.ListEnvironments(orgID, envType, state, includeDestroyed)
	if err != nil {
		return "", fmt.Errorf("list environments: %w", err)
	}

	if len(envs) == 0 {
		return "No environments found.", nil
	}

	out, err := json.MarshalIndent(envs, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func toolCreateEnvironment(args map[string]interface{}) (string, error) {
	client, orgID, err := getPlatformClient()
	if err != nil {
		return "", err
	}

	presetID, _ := args["preset_id"].(string)
	if presetID == "" {
		return "", fmt.Errorf("preset_id is required")
	}

	req := &platform.CreateEnvironmentRequest{
		PresetID: presetID,
	}
	if name, ok := args["name"].(string); ok && name != "" {
		req.Name = name
	}
	if cpu, ok := args["cpu"].(float64); ok && cpu > 0 {
		c := int(cpu)
		req.CPUMillicores = &c
	}
	if mem, ok := args["memory"].(float64); ok && mem > 0 {
		m := int(mem)
		req.MemoryMB = &m
	}
	if disk, ok := args["disk"].(float64); ok && disk > 0 {
		d := int(disk)
		req.DiskGB = &d
	}
	if ttl, ok := args["ttl"].(string); ok && ttl != "" {
		// Parse duration string to seconds
		// For now, pass the raw TTL — the server handles parsing
		// The CLI already handles this, but MCP tools pass it as TTLSeconds
		// We need to parse here since the API expects seconds
		dur, parseErr := parseDuration(ttl)
		if parseErr != nil {
			return "", fmt.Errorf("invalid ttl: %w", parseErr)
		}
		secs := int(dur.Seconds())
		req.TTLSeconds = &secs
	}

	env, err := client.CreateEnvironment(orgID, req)
	if err != nil {
		return "", fmt.Errorf("create environment: %w", err)
	}

	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Environment created:\n%s", string(out)), nil
}

func toolGetEnvironment(args map[string]interface{}) (string, error) {
	client, orgID, err := getPlatformClient()
	if err != nil {
		return "", err
	}

	envID, _ := args["environment_id"].(string)
	if envID == "" {
		return "", fmt.Errorf("environment_id is required")
	}

	env, err := client.GetEnvironment(orgID, envID)
	if err != nil {
		return "", fmt.Errorf("get environment: %w", err)
	}

	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func toolStopEnvironment(args map[string]interface{}) (string, error) {
	client, orgID, err := getPlatformClient()
	if err != nil {
		return "", err
	}

	envID, _ := args["environment_id"].(string)
	if envID == "" {
		return "", fmt.Errorf("environment_id is required")
	}

	resp, err := client.StopEnvironment(orgID, envID)
	if err != nil {
		return "", fmt.Errorf("stop environment: %w", err)
	}
	return fmt.Sprintf("Environment %s: %s", envID, resp.Status), nil
}

func toolStartEnvironment(args map[string]interface{}) (string, error) {
	client, orgID, err := getPlatformClient()
	if err != nil {
		return "", err
	}

	envID, _ := args["environment_id"].(string)
	if envID == "" {
		return "", fmt.Errorf("environment_id is required")
	}

	resp, err := client.StartEnvironment(orgID, envID)
	if err != nil {
		return "", fmt.Errorf("start environment: %w", err)
	}
	return fmt.Sprintf("Environment %s: %s", envID, resp.Status), nil
}

func toolDeleteEnvironment(args map[string]interface{}) (string, error) {
	client, orgID, err := getPlatformClient()
	if err != nil {
		return "", err
	}

	envID, _ := args["environment_id"].(string)
	if envID == "" {
		return "", fmt.Errorf("environment_id is required")
	}

	if err := client.DeleteEnvironment(orgID, envID); err != nil {
		return "", fmt.Errorf("delete environment: %w", err)
	}
	return fmt.Sprintf("Environment %s deleted.", envID), nil
}

func toolExecInEnvironment(args map[string]interface{}) (string, error) {
	client, orgID, err := getPlatformClient()
	if err != nil {
		return "", err
	}

	envID, _ := args["environment_id"].(string)
	if envID == "" {
		return "", fmt.Errorf("environment_id is required")
	}

	cmdArg, _ := args["command"].([]interface{})
	if len(cmdArg) == 0 {
		return "", fmt.Errorf("command is required")
	}
	var command []string
	for _, c := range cmdArg {
		if s, ok := c.(string); ok {
			command = append(command, s)
		}
	}

	req := &platform.ExecRequest{
		Command: command,
	}
	if wd, ok := args["working_dir"].(string); ok && wd != "" {
		req.WorkingDir = wd
	}
	if t, ok := args["timeout"].(float64); ok && t > 0 {
		req.Timeout = int(t)
	}

	result, err := client.ExecInEnvironment(orgID, envID, req)
	if err != nil {
		return "", fmt.Errorf("exec: %w", err)
	}

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func toolListFiles(args map[string]interface{}) (string, error) {
	client, orgID, err := getPlatformClient()
	if err != nil {
		return "", err
	}

	envID, _ := args["environment_id"].(string)
	if envID == "" {
		return "", fmt.Errorf("environment_id is required")
	}

	path, _ := args["path"].(string)

	entries, err := client.ListFiles(orgID, envID, path)
	if err != nil {
		return "", fmt.Errorf("list files: %w", err)
	}

	if len(entries) == 0 {
		return "No files found.", nil
	}

	out, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func toolListPresets(args map[string]interface{}) (string, error) {
	client, orgID, err := getPlatformClient()
	if err != nil {
		return "", err
	}

	presets, err := client.ListPresets(orgID)
	if err != nil {
		return "", fmt.Errorf("list presets: %w", err)
	}

	if len(presets) == 0 {
		return "No presets found.", nil
	}

	out, err := json.MarshalIndent(presets, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}
