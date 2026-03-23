package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	cwconfig "github.com/codewiresh/codewire/internal/config"
	"github.com/codewiresh/codewire/internal/platform"
)

type presetAuthoringOptions struct {
	Args              []string
	RepoFlags         []string
	PresetSlug        string
	PresetID          string
	Name              string
	TTL               string
	CPU               int
	Memory            int
	Disk              int
	Branch            string
	Image             string
	Install           string
	Startup           string
	Agent             string
	EnvVars           []string
	SecretProject     string
	NoOrgSecrets      bool
	NoUserSecrets     bool
	Yes               bool
	AllowCodewireYAML bool
	PromptOnAnalyze   bool
	PromptOnDetection bool
	ShowDetection     bool
}

type resolvedPresetAuthoring struct {
	Request        *platform.CreateEnvironmentRequest
	Detection      *platform.DetectionResult
	ResolvedPreset *platform.Preset
}

func parseEnvVarFlags(values []string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(values))
	for _, ev := range values {
		parts := strings.SplitN(ev, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid --env format %q, expected KEY=val", ev)
		}
		out[parts[0]] = parts[1]
	}
	return out, nil
}

func collectRepoInputs(args, repoFlags []string, branch string) (string, string, []platform.RepoEntry) {
	var (
		repoURL string
		repos   []platform.RepoEntry
	)

	allRepoSpecs := append([]string{}, args...)
	allRepoSpecs = append(allRepoSpecs, repoFlags...)
	for _, spec := range allRepoSpecs {
		u, b := parseRepoSpec(spec)
		repos = append(repos, platform.RepoEntry{URL: u, Branch: b})
	}

	if len(repos) == 1 {
		repoURL = repos[0].URL
		if repos[0].Branch != "" && branch == "" {
			branch = repos[0].Branch
		}
	} else if len(repos) > 1 {
		repoURL = repos[0].URL
	}

	return repoURL, branch, repos
}

func applyCodewireYAMLDefaults(opts *presetAuthoringOptions) bool {
	if !opts.AllowCodewireYAML || opts.PresetSlug != "" || opts.PresetID != "" || opts.Image != "" {
		return false
	}

	cfg, err := loadCodewireYAML("codewire.yaml")
	if err != nil {
		return false
	}

	fmt.Println("Using ./codewire.yaml")
	if cfg.Preset != "" && opts.PresetSlug == "" {
		opts.PresetSlug = cfg.Preset
	}
	if cfg.Image != "" && opts.Image == "" {
		opts.Image = cfg.Image
	}
	if cfg.Install != "" && opts.Install == "" {
		opts.Install = cfg.Install
	}
	if cfg.Startup != "" && opts.Startup == "" {
		opts.Startup = cfg.Startup
	}
	if cfg.Secrets != "" && opts.SecretProject == "" {
		opts.SecretProject = cfg.Secrets
	}
	if cfg.Agent != "" && opts.Agent == "" {
		opts.Agent = cfg.Agent
	}
	if cfg.CPU > 0 && opts.CPU == 0 {
		opts.CPU = cfg.CPU
	}
	if cfg.Memory > 0 && opts.Memory == 0 {
		opts.Memory = cfg.Memory
	}
	if cfg.Disk > 0 && opts.Disk == 0 {
		opts.Disk = cfg.Disk
	}
	if cfg.IncludeOrgSecrets != nil && !*cfg.IncludeOrgSecrets {
		opts.NoOrgSecrets = true
	}
	if cfg.IncludeUserSecrets != nil && !*cfg.IncludeUserSecrets {
		opts.NoUserSecrets = true
	}
	for k, v := range cfg.Env {
		opts.EnvVars = append(opts.EnvVars, k+"="+v)
	}
	return true
}

func resolvePresetAuthoring(cmd *cobra.Command, opts *presetAuthoringOptions) (string, *platform.Client, *resolvedPresetAuthoring, error) {
	repoURL, branch, repos := collectRepoInputs(opts.Args, opts.RepoFlags, opts.Branch)

	if opts.AllowCodewireYAML && repoURL == "" {
		_ = applyCodewireYAMLDefaults(opts)
	}

	if opts.PresetSlug == "" && opts.PresetID == "" && opts.Image == "" && repoURL == "" {
		if url, detectedBranch, err := detectLocalRepo("."); err == nil && url != "" {
			repoURL = url
			if branch == "" {
				branch = detectedBranch
			}
			fmt.Printf("Using repo: %s\n", repoURL)
		} else {
			return "", nil, nil, fmt.Errorf("provide a repo URL, --image, or --preset")
		}
	}

	parsedEnvVars, err := parseEnvVarFlags(opts.EnvVars)
	if err != nil {
		return "", nil, nil, err
	}

	orgID, client, err := getOrgContext(cmd)
	if err != nil {
		return "", nil, nil, err
	}

	var (
		detection        *platform.DetectionResult
		preparedAppPorts []platform.AppPort
		resolvedPreset   *platform.Preset
	)

	if repoURL != "" || opts.PresetSlug != "" || opts.PresetID != "" || opts.Image != "" {
		var analyze *bool
		if repoURL != "" && opts.PresetSlug == "" && opts.PresetID == "" && opts.Image == "" && opts.PromptOnAnalyze && !opts.Yes {
			idx, promptErr := promptSelect("Do you want to auto analyze for setup suggestions?", []string{"Yes", "No"})
			if promptErr != nil {
				return "", nil, nil, promptErr
			}
			v := idx == 0
			analyze = &v
		}

		prepared, prepErr := client.PrepareLaunch(orgID, &platform.PrepareLaunchRequest{
			PresetID:           strPtrOrNil(opts.PresetID),
			PresetSlug:         opts.PresetSlug,
			Name:               strPtrOrNil(opts.Name),
			CPUMillicores:      intPtrOrNil(opts.CPU),
			MemoryMB:           intPtrOrNil(opts.Memory),
			DiskGB:             intPtrOrNil(opts.Disk),
			TTLSeconds:         durationSecondsPtr(opts.TTL),
			RepoURL:            repoURL,
			Branch:             branch,
			Repos:              repos,
			Image:              opts.Image,
			InstallCommand:     opts.Install,
			StartupScript:      opts.Startup,
			EnvVars:            parsedEnvVars,
			Agent:              opts.Agent,
			SecretProject:      opts.SecretProject,
			IncludeOrgSecrets:  boolPtrOrNil(!opts.NoOrgSecrets, opts.NoOrgSecrets),
			IncludeUserSecrets: boolPtrOrNil(!opts.NoUserSecrets, opts.NoUserSecrets),
			Analyze:            analyze,
		})
		if prepErr != nil {
			return "", nil, nil, fmt.Errorf("prepare launch: %w", prepErr)
		}

		if prepared.Draft.PresetID != "" {
			opts.PresetID = prepared.Draft.PresetID
		}
		if opts.PresetSlug == "" {
			opts.PresetSlug = prepared.Draft.PresetSlug
		}
		if opts.Name == "" {
			opts.Name = prepared.Draft.Name
		}
		if repoURL == "" {
			repoURL = prepared.Draft.RepoURL
		}
		if branch == "" {
			branch = prepared.Draft.Branch
		}
		if len(repos) == 0 && len(prepared.Draft.Repos) > 0 {
			repos = prepared.Draft.Repos
		}
		if opts.Image == "" {
			opts.Image = prepared.Draft.Image
		}
		if opts.Install == "" {
			opts.Install = prepared.Draft.InstallCommand
		}
		if opts.Startup == "" {
			opts.Startup = prepared.Draft.StartupScript
		}
		if opts.SecretProject == "" {
			opts.SecretProject = prepared.Draft.SecretProject
		}
		if opts.Agent == "" {
			opts.Agent = prepared.Draft.Agent
		}
		if opts.CPU == 0 && prepared.Draft.CPUMillicores != nil {
			opts.CPU = *prepared.Draft.CPUMillicores
		}
		if opts.Memory == 0 && prepared.Draft.MemoryMB != nil {
			opts.Memory = *prepared.Draft.MemoryMB
		}
		if opts.Disk == 0 && prepared.Draft.DiskGB != nil {
			opts.Disk = *prepared.Draft.DiskGB
		}
		if opts.TTL == "" && prepared.Draft.TTLSeconds != nil {
			opts.TTL = fmt.Sprintf("%ds", *prepared.Draft.TTLSeconds)
		}
		preparedAppPorts = prepared.Draft.AppPorts
		detection = prepared.Detection
		resolvedPreset = prepared.ResolvedPreset
		if detection != nil && opts.ShowDetection {
			printDetectionSummary(detection)
		}

		if detection != nil && opts.PromptOnDetection && !opts.Yes {
			idx, promptErr := promptSelect("Create environment?", []string{"Yes", "Edit options", "Cancel"})
			if promptErr != nil {
				return "", nil, nil, promptErr
			}
			switch idx {
			case 2:
				return "", nil, nil, fmt.Errorf("canceled")
			case 1:
				if v, err := promptDefault("Image", opts.Image); err == nil {
					opts.Image = v
				}
				if v, err := promptDefault("Install command", opts.Install); err == nil {
					opts.Install = v
				}
				if v, err := promptDefault("Startup script", opts.Startup); err == nil {
					opts.Startup = v
				}
				if v, err := promptDefault("Environment name", opts.Name); err == nil {
					opts.Name = v
				}
			}
		}
	}

	if opts.Image != "" {
		opts.Image = expandImageRef(opts.Image)
	}

	req := &platform.CreateEnvironmentRequest{
		PresetID:       opts.PresetID,
		PresetSlug:     opts.PresetSlug,
		Name:           opts.Name,
		RepoURL:        repoURL,
		Branch:         branch,
		Image:          opts.Image,
		InstallCommand: opts.Install,
		StartupScript:  opts.Startup,
		Agent:          opts.Agent,
		SecretProject:  opts.SecretProject,
	}
	if len(repos) > 0 {
		req.Repos = repos
	}
	if len(preparedAppPorts) > 0 {
		req.AppPorts = preparedAppPorts
	} else if detection != nil && len(detection.AppPorts) > 0 {
		req.AppPorts = detection.AppPorts
	}
	if len(parsedEnvVars) > 0 {
		req.EnvVars = parsedEnvVars
	}
	if opts.CPU > 0 {
		req.CPUMillicores = &opts.CPU
	}
	if opts.Memory > 0 {
		req.MemoryMB = &opts.Memory
	}
	if opts.Disk > 0 {
		req.DiskGB = &opts.Disk
	}
	if opts.TTL != "" {
		req.TTLSeconds = durationSecondsPtr(opts.TTL)
		if req.TTLSeconds == nil {
			return "", nil, nil, fmt.Errorf("invalid --ttl duration")
		}
	}
	if opts.NoOrgSecrets {
		f := false
		req.IncludeOrgSecrets = &f
	}
	if opts.NoUserSecrets {
		f := false
		req.IncludeUserSecrets = &f
	}

	return orgID, client, &resolvedPresetAuthoring{
		Request:        req,
		Detection:      detection,
		ResolvedPreset: resolvedPreset,
	}, nil
}

func codewireConfigFromRequest(req *platform.CreateEnvironmentRequest) *cwconfig.CodewireConfig {
	cfg := &cwconfig.CodewireConfig{
		Image:              req.Image,
		Install:            req.InstallCommand,
		Startup:            req.StartupScript,
		Secrets:            req.SecretProject,
		Env:                req.EnvVars,
		CPU:                valueOrZero(req.CPUMillicores),
		Memory:             valueOrZero(req.MemoryMB),
		Disk:               valueOrZero(req.DiskGB),
		Agent:              req.Agent,
		IncludeOrgSecrets:  req.IncludeOrgSecrets,
		IncludeUserSecrets: req.IncludeUserSecrets,
	}
	if len(req.AppPorts) > 0 {
		cfg.Ports = make([]cwconfig.PortConfig, 0, len(req.AppPorts))
		for _, port := range req.AppPorts {
			cfg.Ports = append(cfg.Ports, cwconfig.PortConfig{
				Port:  port.Port,
				Label: port.Label,
			})
		}
	}
	return cfg
}

func valueOrZero(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}

func writeResolvedCodewireYAML(path string, req *platform.CreateEnvironmentRequest) error {
	return cwconfig.WriteCodewireConfig(path, codewireConfigFromRequest(req))
}

func slugifyPresetName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ""
	}
	var b strings.Builder
	lastDash := false
	for _, r := range name {
		isAlpha := r >= 'a' && r <= 'z'
		isDigit := r >= '0' && r <= '9'
		if isAlpha || isDigit {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	return out
}

func createPresetRequestFromEnvironment(name string, req *platform.CreateEnvironmentRequest) (*platform.CreatePresetRequest, error) {
	slug := slugifyPresetName(name)
	if slug == "" {
		return nil, fmt.Errorf("preset name is required")
	}
	out := &platform.CreatePresetRequest{
		Name:                 name,
		Slug:                 slug,
		DefaultCPUMillicores: req.CPUMillicores,
		DefaultMemoryMB:      req.MemoryMB,
		DefaultDiskGB:        req.DiskGB,
		DefaultTTLSeconds:    req.TTLSeconds,
		Image:                req.Image,
		InstallCommand:       req.InstallCommand,
		StartupScript:        req.StartupScript,
		EnvVars:              req.EnvVars,
		Agent:                req.Agent,
		AgentEnv:             req.AgentEnv,
		AppPorts:             req.AppPorts,
		IncludeOrgSecrets:    req.IncludeOrgSecrets,
		IncludeUserSecrets:   req.IncludeUserSecrets,
		SecretProject:        req.SecretProject,
	}
	return out, nil
}
