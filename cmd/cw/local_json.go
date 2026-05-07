package main

import (
	"encoding/json"
	"fmt"
	"os"

	cwconfig "github.com/codewiresh/codewire/internal/config"
)

// localInstanceJSON is the stable, public-facing JSON shape for a local
// instance. SDKs depend on this schema — see cli/docs/local-json-schema.md.
type localInstanceJSON struct {
	Name        string            `json:"name"`
	Backend     string            `json:"backend"`
	Status      string            `json:"status"`
	RuntimeName string            `json:"runtime_name"`
	RepoPath    string            `json:"repo_path"`
	Workdir     string            `json:"workdir"`
	Image       string            `json:"image,omitempty"`
	Preset      string            `json:"preset,omitempty"`
	Install     string            `json:"install,omitempty"`
	Startup     string            `json:"startup,omitempty"`
	Secrets     string            `json:"secrets,omitempty"`
	Agent       string            `json:"agent,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	Ports       []localPortJSON   `json:"ports,omitempty"`
	Mounts      []localMountJSON  `json:"mounts,omitempty"`
	CPU         int               `json:"cpu,omitempty"`
	Memory      int               `json:"memory,omitempty"`
	Disk        int               `json:"disk,omitempty"`
	CreatedAt   string            `json:"created_at,omitempty"`
	LastUsedAt  string            `json:"last_used_at,omitempty"`
	Lima        *localLimaJSON    `json:"lima,omitempty"`
}

type localPortJSON struct {
	HostPort  int    `json:"host_port"`
	GuestPort int    `json:"guest_port"`
	Label     string `json:"label,omitempty"`
}

type localMountJSON struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Readonly bool   `json:"readonly,omitempty"`
}

type localLimaJSON struct {
	InstanceName string `json:"instance_name,omitempty"`
	MountType    string `json:"mount_type,omitempty"`
	VMType       string `json:"vm_type,omitempty"`
}

// localInstanceToJSON converts a LocalInstance plus a derived status into the
// stable JSON shape. Keep this function the single source of truth for how
// instances are serialized for SDK consumers.
func localInstanceToJSON(instance *cwconfig.LocalInstance, status string) localInstanceJSON {
	if instance == nil {
		return localInstanceJSON{}
	}

	out := localInstanceJSON{
		Name:        instance.Name,
		Backend:     instance.Backend,
		Status:      status,
		RuntimeName: instance.RuntimeName,
		RepoPath:    instance.RepoPath,
		Workdir:     instance.Workdir,
		Image:       instance.Image,
		Preset:      instance.Preset,
		Install:     instance.Install,
		Startup:     instance.Startup,
		Secrets:     instance.Secrets,
		Agent:       instance.Agent,
		Env:         instance.Env,
		CPU:         instance.CPU,
		Memory:      instance.Memory,
		Disk:        instance.Disk,
		CreatedAt:   instance.CreatedAt,
		LastUsedAt:  instance.LastUsedAt,
	}

	for _, port := range instance.Ports {
		p := port.Canonical()
		host, guest := p.EffectiveHostPort(), p.EffectiveGuestPort()
		if host <= 0 || guest <= 0 {
			continue
		}
		out.Ports = append(out.Ports, localPortJSON{
			HostPort:  host,
			GuestPort: guest,
			Label:     p.Label,
		})
	}

	for _, mount := range instance.Mounts {
		readonly := false
		if mount.Readonly != nil {
			readonly = *mount.Readonly
		}
		out.Mounts = append(out.Mounts, localMountJSON{
			Source:   mount.Source,
			Target:   mount.Target,
			Readonly: readonly,
		})
	}

	if instance.Backend == "lima" {
		lima := &localLimaJSON{
			InstanceName: instance.LimaInstanceName,
			MountType:    instance.LimaMountType,
			VMType:       instance.LimaVMType,
		}
		if lima.InstanceName != "" || lima.MountType != "" || lima.VMType != "" {
			out.Lima = lima
		}
	}

	return out
}

// emitJSON writes a JSON value to stdout with pretty indentation. Shared
// between `cw local` subcommands, `cw exec --output json`, and any other command
// that emits machine-readable output for SDK consumers.
func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("emit json: %w", err)
	}
	return nil
}
