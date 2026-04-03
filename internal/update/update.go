package update

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

const (
	githubAPI  = "https://api.github.com/repos/codewiresh/codewire/releases/latest"
	cacheTTL   = 24 * time.Hour
	cacheFile  = "update-check.json"
	fetchTimeout = 5 * time.Second
)

type cacheEntry struct {
	LatestVersion  string    `json:"latest_version"`
	CurrentVersion string    `json:"current_version"`
	CheckedAt      time.Time `json:"checked_at"`
}

type githubRelease struct {
	TagName string `json:"tag_name"`
}

// FetchLatestVersion queries the GitHub Releases API and returns the latest tag_name.
func FetchLatestVersion() (string, error) {
	return fetchLatestVersionFrom(githubAPI)
}

// httpClient is the client used for API requests. Tests may override this.
var httpClient = &http.Client{Timeout: fetchTimeout}

func fetchLatestVersionFrom(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github API returned %d", resp.StatusCode)
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", err
	}
	if rel.TagName == "" {
		return "", fmt.Errorf("empty tag_name in response")
	}
	return rel.TagName, nil
}

// IsNewer returns true if latest is a higher semver than current.
// Returns false on any parse error.
func IsNewer(current, latest string) bool {
	cMaj, cMin, cPatch, ok := parseSemver(current)
	if !ok {
		return false
	}
	lMaj, lMin, lPatch, ok := parseSemver(latest)
	if !ok {
		return false
	}
	if lMaj != cMaj {
		return lMaj > cMaj
	}
	if lMin != cMin {
		return lMin > cMin
	}
	return lPatch > cPatch
}

// parseSemver parses "v0.2.48" or "0.2.48" into (major, minor, patch, ok).
func parseSemver(s string) (int, int, int, bool) {
	s = strings.TrimPrefix(s, "v")
	// Strip git-describe suffix (e.g. "0.2.52-2-gf2fe21a" → "0.2.52")
	if idx := strings.Index(s, "-"); idx != -1 {
		s = s[:idx]
	}
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, false
	}
	min, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, 0, false
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, 0, 0, false
	}
	return maj, min, patch, true
}

// BackgroundCheck starts a goroutine that checks for updates and returns a
// closure that prints a notice to stderr if an update is available.
// The closure should be called after the main command completes.
// Silent on all errors. Skipped for dev builds.
func BackgroundCheck(currentVersion string) func() {
	if currentVersion == "dev" {
		return func() {}
	}

	type result struct {
		latest string
		newer  bool
	}
	ch := make(chan result, 1)

	go func() {
		latest, newer := checkWithCache(currentVersion)
		ch <- result{latest, newer}
	}()

	return func() {
		select {
		case r := <-ch:
			if r.newer {
				msg := fmt.Sprintf("A new version of cw is available: %s → %s", currentVersion, r.latest)
				style := lipgloss.NewRenderer(os.Stderr).NewStyle().Foreground(lipgloss.Color("3"))
				msg = style.Render(msg)
				fmt.Fprintf(os.Stderr, "\n%s\nRun `cw update` to upgrade.\n", msg)
			}
		default:
		}
	}
}

func checkWithCache(currentVersion string) (string, bool) {
	cached, ok := loadCache()
	if ok && cached.CurrentVersion == currentVersion && time.Since(cached.CheckedAt) < cacheTTL {
		return cached.LatestVersion, IsNewer(currentVersion, cached.LatestVersion)
	}

	latest, err := FetchLatestVersion()
	if err != nil {
		return "", false
	}

	saveCache(cacheEntry{
		LatestVersion:  latest,
		CurrentVersion: currentVersion,
		CheckedAt:      time.Now(),
	})

	return latest, IsNewer(currentVersion, latest)
}

func cachePath() string {
	if dir := os.Getenv("CW_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, cacheFile)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "cw", cacheFile)
}

func loadCache() (cacheEntry, bool) {
	data, err := os.ReadFile(cachePath())
	if err != nil {
		return cacheEntry{}, false
	}
	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return cacheEntry{}, false
	}
	return entry, true
}

func saveCache(entry cacheEntry) {
	path := cachePath()
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o644)
}
