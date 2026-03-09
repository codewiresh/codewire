package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/codewiresh/codewire/internal/platform"
)

// withReauth runs fn. If it returns ErrUnauthorized, prompts the user
// to re-authenticate via device login, updates the client token, and retries.
func withReauth(client *platform.Client, fn func() error) error {
	err := fn()
	if err == nil || !errors.Is(err, platform.ErrUnauthorized) {
		return err
	}

	fmt.Println("Session expired. Re-authenticating...")

	name, loginErr := loginWithDevice(client)
	if loginErr != nil {
		return fmt.Errorf("re-authentication failed: %w", loginErr)
	}

	// Save the new token
	cfg, cfgErr := platform.LoadConfig()
	if cfgErr != nil {
		cfg = &platform.PlatformConfig{ServerURL: client.ServerURL}
	}
	cfg.SessionToken = client.SessionToken
	if saveErr := platform.SaveConfig(cfg); saveErr != nil {
		return fmt.Errorf("save config after re-auth: %w", saveErr)
	}

	fmt.Printf("Re-authenticated as %s\n", name)
	return fn()
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// slugify converts a name to a URL-safe slug.
func slugify(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = nonAlnum.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	// Collapse consecutive hyphens
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	if len(s) > 48 {
		s = s[:48]
		s = strings.TrimRight(s, "-")
	}
	return s
}

// resolveOrgID resolves an org ID from a flag value or config default.
// If orgFlag is a slug, it looks up the ID via ListOrgs.
func resolveOrgID(pc *platform.Client, orgFlag string) (string, error) {
	if orgFlag == "" {
		cfg, err := platform.LoadConfig()
		if err != nil {
			return "", fmt.Errorf("no org specified (pass --org or run 'cw setup')")
		}
		if cfg.DefaultOrg == "" {
			return "", fmt.Errorf("no default org configured (pass --org or run 'cw setup')")
		}
		return cfg.DefaultOrg, nil
	}

	// Could be an ID (UUID) or slug — try listing orgs to resolve
	orgs, err := pc.ListOrgs()
	if err != nil {
		return "", fmt.Errorf("list orgs: %w", err)
	}
	for _, org := range orgs {
		if org.ID == orgFlag || org.Slug == orgFlag {
			return org.ID, nil
		}
	}
	return "", fmt.Errorf("organization %q not found", orgFlag)
}

// confirmDelete prompts the user to type the name to confirm deletion.
func confirmDelete(resourceType, name string) error {
	input, err := prompt(fmt.Sprintf("Type %q to confirm deletion of %s %q: ", name, resourceType, name))
	if err != nil {
		return err
	}
	if strings.TrimSpace(input) != name {
		return fmt.Errorf("confirmation failed — aborting")
	}
	return nil
}
