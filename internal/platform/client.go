package platform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrUnauthorized is returned when the server responds with HTTP 401.
var ErrUnauthorized = fmt.Errorf("session expired or invalid")

// Client is an HTTP client for the Codewire platform API.
type Client struct {
	ServerURL    string
	SessionToken string
	HTTP         *http.Client
}

// NewClient creates a client from a saved config.
func NewClient() (*Client, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("not logged in (run 'cw setup' or 'cw login'): %w", err)
	}
	return &Client{
		ServerURL:    cfg.ServerURL,
		SessionToken: cfg.SessionToken,
		HTTP:         &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// NewClientWithURL creates a client for a specific server (used during setup/login before config exists).
func NewClientWithURL(serverURL string) *Client {
	return &Client{
		ServerURL: strings.TrimRight(serverURL, "/"),
		HTTP:      &http.Client{Timeout: 30 * time.Second},
	}
}

// Login authenticates with email/password. Returns the sign-in response which
// may require 2FA validation.
func (c *Client) Login(email, password string) (*SignInResponse, error) {
	var resp SignInResponse
	err := c.do("POST", "/api/auth/sign-in", &SignInRequest{
		Email:    email,
		Password: password,
	}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Session != nil {
		c.SessionToken = resp.Session.Token
	}
	return &resp, nil
}

// ValidateTOTP completes the 2FA login flow.
func (c *Client) ValidateTOTP(code, token string) (*AuthResponse, error) {
	var resp AuthResponse
	err := c.do("POST", "/api/auth/two-factor/validate", &ValidateTOTPRequest{
		Code:  code,
		Token: token,
	}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Session != nil {
		c.SessionToken = resp.Session.Token
	}
	return &resp, nil
}

// GetSession checks the current auth state.
func (c *Client) GetSession() (*AuthResponse, error) {
	var resp AuthResponse
	if err := c.do("GET", "/api/auth/get-session", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Logout invalidates the current session.
func (c *Client) Logout() error {
	return c.do("POST", "/api/auth/sign-out", nil, nil)
}

// DeviceAuthorize starts the device authorization flow.
func (c *Client) DeviceAuthorize() (*DeviceAuthResponse, error) {
	var resp DeviceAuthResponse
	if err := c.do("POST", "/api/auth/device/authorize", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeviceToken polls for the device authorization result.
// Returns the response and HTTP status code.
func (c *Client) DeviceToken(deviceCode string) (*DeviceTokenResponse, int, error) {
	body := map[string]string{"device_code": deviceCode}
	resp, statusCode, err := c.doWithStatus("POST", "/api/auth/device/token", body)
	if err != nil {
		return nil, statusCode, err
	}
	if resp.SessionToken != "" {
		c.SessionToken = resp.SessionToken
	}
	return resp, statusCode, nil
}

// Healthz checks if the server is reachable.
func (c *Client) Healthz() error {
	resp, err := c.HTTP.Get(c.ServerURL + "/healthz")
	if err != nil {
		return fmt.Errorf("cannot reach server: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

func debugEnabled() bool {
	return os.Getenv("CW_DEBUG") != ""
}

// do makes an authenticated HTTP request.
func (c *Client) do(method, path string, body any, result any) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.ServerURL+path, bodyReader)
	if err != nil {
		return err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.SessionToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.SessionToken)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if debugEnabled() {
		fmt.Fprintf(os.Stderr, "DEBUG %s %s → %d (%d bytes)\n", method, path, resp.StatusCode, len(respBody))
		fmt.Fprintf(os.Stderr, "DEBUG body: %s\n", string(respBody))
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}

	if resp.StatusCode >= 400 {
		var apiErr APIError
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Title != "" {
			apiErr.Status = resp.StatusCode
			return &apiErr
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}

	return nil
}

// doWithStatus is like do but returns a DeviceTokenResponse and the HTTP status code.
// It handles 2xx as success (not just 200) and returns errors for 4xx/5xx.
func (c *Client) doWithStatus(method, path string, body any) (*DeviceTokenResponse, int, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.ServerURL+path, bodyReader)
	if err != nil {
		return nil, 0, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.SessionToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.SessionToken)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}

	if debugEnabled() {
		fmt.Fprintf(os.Stderr, "DEBUG %s %s → %d (%d bytes)\n", method, path, resp.StatusCode, len(respBody))
		fmt.Fprintf(os.Stderr, "DEBUG body: %s\n", string(respBody))
	}

	if resp.StatusCode >= 400 {
		var apiErr APIError
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Title != "" {
			apiErr.Status = resp.StatusCode
			return nil, resp.StatusCode, &apiErr
		}
		return nil, resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result DeviceTokenResponse
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &result); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("decode response: %w", err)
		}
	}

	return &result, resp.StatusCode, nil
}

// Config file management

func configDir() string {
	if dir := os.Getenv("CW_CONFIG_DIR"); dir != "" {
		return dir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "cw")
}

func configPath() string {
	return filepath.Join(configDir(), "config.json")
}

func csConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "cs", "config.json")
}

func migrateCSConfig(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

// LoadConfig reads the platform config from ~/.config/cw/config.json.
func LoadConfig() (*PlatformConfig, error) {
	// Migrate from cs config if cw config doesn't exist yet
	cwPath := configPath()
	if _, err := os.Stat(cwPath); os.IsNotExist(err) {
		csPath := csConfigPath()
		if _, err := os.Stat(csPath); err == nil {
			if err := migrateCSConfig(csPath, cwPath); err == nil {
				fmt.Fprintf(os.Stderr, "Migrated config from %s to %s\n", csPath, cwPath)
			}
		}
	}

	data, err := os.ReadFile(configPath())
	if err != nil {
		return nil, err
	}
	var cfg PlatformConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.ServerURL == "" || cfg.SessionToken == "" {
		return nil, fmt.Errorf("incomplete config (missing server_url or session_token)")
	}
	return &cfg, nil
}

// SaveConfig writes the platform config to ~/.config/cw/config.json.
func SaveConfig(cfg *PlatformConfig) error {
	dir := configDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')
	return os.WriteFile(configPath(), data, 0600)
}

// DeleteConfig removes the platform config file.
func DeleteConfig() error {
	return os.Remove(configPath())
}

// HasConfig returns true if a platform config exists.
func HasConfig() bool {
	_, err := os.Stat(configPath())
	return err == nil
}

// SetCurrentWorkspace updates just the current_workspace field in config.
func SetCurrentWorkspace(name string) error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	cfg.CurrentWorkspace = name
	return SaveConfig(cfg)
}

// GetCurrentWorkspace returns the current workspace name from config.
func GetCurrentWorkspace() string {
	cfg, err := LoadConfig()
	if err != nil {
		return ""
	}
	return cfg.CurrentWorkspace
}
