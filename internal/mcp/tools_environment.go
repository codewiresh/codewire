package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
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
					"include_destroyed": map[string]interface{}{
						"type":        "boolean",
						"description": "Include destroyed environments (default: false)",
					},
				},
			},
		},
		{
			Name:        "codewire_create_environment",
			Description: "Create a new environment. Specify either preset_id/preset_slug for a preset-based environment, or image for a custom container.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"preset_id": map[string]interface{}{
						"type":        "string",
						"description": "Preset ID to use",
					},
					"preset_slug": map[string]interface{}{
						"type":        "string",
						"description": "Preset slug (e.g. 'go', 'node', 'python'). Alternative to preset_id.",
					},
					"image": map[string]interface{}{
						"type":        "string",
						"description": "Container image (e.g. 'python:3.12', 'ghcr.io/codewiresh/openclaw:latest'). Used when not using a preset.",
					},
					"name": map[string]interface{}{
						"type":        "string",
						"description": "Environment name",
					},
					"ttl": map[string]interface{}{
						"type":        "string",
						"description": "Time to live (e.g. '1h', '30m'). Auto-destroys after this.",
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
					"repo_url": map[string]interface{}{
						"type":        "string",
						"description": "Git repository URL to clone",
					},
					"branch": map[string]interface{}{
						"type":        "string",
						"description": "Git branch to checkout",
					},
					"install_command": map[string]interface{}{
						"type":        "string",
						"description": "Command to run after cloning (e.g. 'pip install -r requirements.txt')",
					},
					"startup_script": map[string]interface{}{
						"type":        "string",
						"description": "Script to run on environment startup",
					},
					"agent": map[string]interface{}{
						"type":        "string",
						"description": "AI agent to run (e.g. 'claude-code')",
					},
					"env_vars": map[string]interface{}{
						"type":        "object",
						"description": "Environment variables as key-value pairs",
						"additionalProperties": map[string]interface{}{"type": "string"},
					},
					"secret_project": map[string]interface{}{
						"type":        "string",
						"description": "Secret project name to bind",
					},
					"include_org_secrets": map[string]interface{}{
						"type":        "boolean",
						"description": "Include org-level secrets (default: true)",
					},
					"include_user_secrets": map[string]interface{}{
						"type":        "boolean",
						"description": "Include user-level secrets (default: true)",
					},
					"network": map[string]interface{}{
						"type":        "string",
						"description": "Relay network to join on boot",
					},
				},
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
						"description": "Timeout in seconds (default: server-side, currently 600)",
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
		{
			Name:        "codewire_upload_file",
			Description: "Upload a file to a running sandbox environment. Content is provided as a string.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"environment_id": map[string]interface{}{
						"type":        "string",
						"description": "The environment ID",
					},
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Remote file path (e.g. '/workspace/script.py')",
					},
					"content": map[string]interface{}{
						"type":        "string",
						"description": "File content as text",
					},
				},
				"required": []string{"environment_id", "path", "content"},
			},
		},
		{
			Name:        "codewire_download_file",
			Description: "Download a file from a running sandbox environment. Returns content as text.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"environment_id": map[string]interface{}{
						"type":        "string",
						"description": "The environment ID",
					},
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Remote file path to download",
					},
				},
				"required": []string{"environment_id", "path"},
			},
		},
		{
			Name:        "codewire_get_environment_logs",
			Description: "Get startup/provisioning logs for an environment.",
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

	req := &platform.CreateEnvironmentRequest{}

	if v, ok := args["preset_id"].(string); ok && v != "" {
		req.PresetID = v
	}
	if v, ok := args["preset_slug"].(string); ok && v != "" {
		req.PresetSlug = v
	}
	if v, ok := args["image"].(string); ok && v != "" {
		req.Image = v
	}
	if req.PresetID == "" && req.PresetSlug == "" && req.Image == "" {
		return "", fmt.Errorf("one of preset_id, preset_slug, or image is required")
	}
	if v, ok := args["name"].(string); ok && v != "" {
		req.Name = v
	}
	if v, ok := args["cpu"].(float64); ok && v > 0 {
		c := int(v)
		req.CPUMillicores = &c
	}
	if v, ok := args["memory"].(float64); ok && v > 0 {
		m := int(v)
		req.MemoryMB = &m
	}
	if v, ok := args["disk"].(float64); ok && v > 0 {
		d := int(v)
		req.DiskGB = &d
	}
	if v, ok := args["ttl"].(string); ok && v != "" {
		dur, parseErr := parseDuration(v)
		if parseErr != nil {
			return "", fmt.Errorf("invalid ttl: %w", parseErr)
		}
		secs := int(dur.Seconds())
		req.TTLSeconds = &secs
	}
	if v, ok := args["repo_url"].(string); ok && v != "" {
		req.RepoURL = v
	}
	if v, ok := args["branch"].(string); ok && v != "" {
		req.Branch = v
	}
	if v, ok := args["install_command"].(string); ok && v != "" {
		req.InstallCommand = v
	}
	if v, ok := args["startup_script"].(string); ok && v != "" {
		req.StartupScript = v
	}
	if v, ok := args["agent"].(string); ok && v != "" {
		req.Agent = v
	}
	if v, ok := args["env_vars"].(map[string]interface{}); ok {
		envVars := make(map[string]string)
		for k, val := range v {
			if s, ok := val.(string); ok {
				envVars[k] = s
			}
		}
		req.EnvVars = envVars
	}
	if v, ok := args["secret_project"].(string); ok && v != "" {
		req.SecretProject = v
	}
	if v, ok := args["include_org_secrets"].(bool); ok {
		req.IncludeOrgSecrets = &v
	}
	if v, ok := args["include_user_secrets"].(bool); ok {
		req.IncludeUserSecrets = &v
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

func toolUploadFile(args map[string]interface{}) (string, error) {
	client, orgID, err := getPlatformClient()
	if err != nil {
		return "", err
	}

	envID, _ := args["environment_id"].(string)
	if envID == "" {
		return "", fmt.Errorf("environment_id is required")
	}

	path, _ := args["path"].(string)
	if path == "" {
		return "", fmt.Errorf("path is required")
	}

	content, _ := args["content"].(string)

	if err := client.UploadFile(orgID, envID, path, strings.NewReader(content)); err != nil {
		return "", fmt.Errorf("upload: %w", err)
	}
	return fmt.Sprintf("Uploaded %d bytes to %s", len(content), path), nil
}

func toolDownloadFile(args map[string]interface{}) (string, error) {
	client, orgID, err := getPlatformClient()
	if err != nil {
		return "", err
	}

	envID, _ := args["environment_id"].(string)
	if envID == "" {
		return "", fmt.Errorf("environment_id is required")
	}

	path, _ := args["path"].(string)
	if path == "" {
		return "", fmt.Errorf("path is required")
	}

	rc, err := client.DownloadFile(orgID, envID, path)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return "", fmt.Errorf("reading download: %w", err)
	}
	return string(data), nil
}

func toolGetEnvironmentLogs(args map[string]interface{}) (string, error) {
	client, orgID, err := getPlatformClient()
	if err != nil {
		return "", err
	}

	envID, _ := args["environment_id"].(string)
	if envID == "" {
		return "", fmt.Errorf("environment_id is required")
	}

	logs, err := client.GetEnvironmentLogs(orgID, envID)
	if err != nil {
		return "", fmt.Errorf("get logs: %w", err)
	}

	if len(logs) == 0 {
		return "No logs found.", nil
	}

	out, err := json.MarshalIndent(logs, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}
