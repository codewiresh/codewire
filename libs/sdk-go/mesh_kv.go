package codewire

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// MeshKVService handles mesh key-value store operations.
type MeshKVService struct {
	client *MeshClient
}

// Set stores a value in the KV store. Pass empty ttl for no expiry.
func (s *MeshKVService) Set(ctx context.Context, networkID, namespace, key string, value []byte, ttl string) error {
	path := fmt.Sprintf("/api/v1/kv/%s/%s?network_id=%s",
		url.PathEscape(namespace), url.PathEscape(key), url.QueryEscape(networkID))

	req, err := http.NewRequestWithContext(ctx, "PUT", s.client.baseURL+path, strings.NewReader(string(value)))
	if err != nil {
		return fmt.Errorf("mesh: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.client.authToken)
	req.Header.Set("Content-Type", "application/octet-stream")
	if ttl != "" {
		req.Header.Set("X-TTL", ttl)
	}

	resp, err := s.client.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("mesh: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return &Error{StatusCode: resp.StatusCode, Detail: strings.TrimSpace(string(detail))}
	}
	return nil
}

// Get retrieves a value from the KV store.
func (s *MeshKVService) Get(ctx context.Context, networkID, namespace, key string) ([]byte, error) {
	path := fmt.Sprintf("/api/v1/kv/%s/%s?network_id=%s",
		url.PathEscape(namespace), url.PathEscape(key), url.QueryEscape(networkID))
	resp, err := s.client.doRawBody(ctx, "GET", path, nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// List returns KV entries matching a prefix.
func (s *MeshKVService) List(ctx context.Context, networkID, namespace, prefix string) ([]MeshKVEntry, error) {
	path := fmt.Sprintf("/api/v1/kv/%s?prefix=%s&network_id=%s",
		url.PathEscape(namespace), url.QueryEscape(prefix), url.QueryEscape(networkID))
	var entries []MeshKVEntry
	err := s.client.doAuth(ctx, "GET", path, nil, &entries)
	return entries, err
}

// Delete removes a key from the KV store (owner required).
func (s *MeshKVService) Delete(ctx context.Context, networkID, namespace, key string) error {
	path := fmt.Sprintf("/api/v1/kv/%s/%s?network_id=%s",
		url.PathEscape(namespace), url.PathEscape(key), url.QueryEscape(networkID))
	return s.client.doAuth(ctx, "DELETE", path, nil, nil)
}
