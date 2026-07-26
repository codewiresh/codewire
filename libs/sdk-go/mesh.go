package codewire

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MeshClient is the client for the Codewire mesh API.
// Separate from the platform Client -- the mesh uses its own URL and auth.
type MeshClient struct {
	Networks    *MeshNetworkService
	Nodes       *MeshNodeService
	KV          *MeshKVService
	Groups      *MeshGroupService
	Credentials *MeshCredentialService

	baseURL    string
	authToken  string
	httpClient *http.Client
}

// MeshOption configures a MeshClient.
type MeshOption func(*MeshClient)

// WithMeshHTTPClient sets a custom HTTP client.
func WithMeshHTTPClient(hc *http.Client) MeshOption {
	return func(c *MeshClient) { c.httpClient = hc }
}

// NewMeshClient creates a client for the Codewire mesh API.
func NewMeshClient(meshURL, authToken string, opts ...MeshOption) *MeshClient {
	c := &MeshClient{
		baseURL:    strings.TrimRight(meshURL, "/"),
		authToken:  authToken,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	c.Networks = &MeshNetworkService{client: c}
	c.Nodes = &MeshNodeService{client: c}
	c.KV = &MeshKVService{client: c}
	c.Groups = &MeshGroupService{client: c}
	c.Credentials = &MeshCredentialService{client: c}
	return c
}

func (c *MeshClient) doAuth(ctx context.Context, method, path string, body, result any) error {
	return c.doRequest(ctx, method, path, c.authToken, body, result)
}

func (c *MeshClient) doPublic(ctx context.Context, method, path string, body, result any) error {
	return c.doRequest(ctx, method, path, "", body, result)
}

func (c *MeshClient) doRequest(ctx context.Context, method, path, token string, body, result any) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("mesh: marshal: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("mesh: create request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("mesh: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return &Error{StatusCode: resp.StatusCode, Detail: strings.TrimSpace(string(detail))}
	}

	if resp.StatusCode == 204 || result == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(result)
}

func (c *MeshClient) doRawBody(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("mesh: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.authToken)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mesh: request: %w", err)
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, &Error{StatusCode: resp.StatusCode, Detail: strings.TrimSpace(string(detail))}
	}
	return resp, nil
}
