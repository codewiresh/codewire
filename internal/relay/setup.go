package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	qrcode "github.com/skip2/go-qrcode"
	"io"
	"net/http"
	"net/url"
	"os"
)

func RegisterWithAuthToken(ctx context.Context, relayURL, networkID, nodeName, authToken string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"node_name":  nodeName,
		"network_id": networkID,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, relayURL+"/api/v1/nodes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("contacting relay: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("registration failed (%d): %s", resp.StatusCode, b)
	}

	var result struct {
		NodeToken string `json:"node_token"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.NodeToken, nil
}

type JoinResult struct {
	NetworkID string `json:"network_id"`
}

func JoinNetworkWithInvite(ctx context.Context, relayURL, authToken, inviteToken string) (*JoinResult, error) {
	body, _ := json.Marshal(map[string]string{
		"invite_token": inviteToken,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, relayURL+"/api/v1/networks/join", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("contacting relay: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("invite rejected (%d): %s", resp.StatusCode, b)
	}

	var result JoinResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("parsing join response: %w", err)
	}
	return &result, nil
}

// RegisterWithInvite exchanges an invite token for a node token.
func RegisterWithInvite(ctx context.Context, relayURL, nodeName, inviteToken string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"node_name":    nodeName,
		"invite_token": inviteToken,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, relayURL+"/api/v1/join", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("contacting relay: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("invite rejected (%d): %s", resp.StatusCode, b)
	}

	var result struct {
		NodeToken string `json:"node_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("parsing join response: %w", err)
	}
	return result.NodeToken, nil
}

// SSHURI builds an ssh:// URI for the given relay and node credentials.
func SSHURI(relayURL, networkID, nodeName, nodeToken string, port int) string {
	host := extractHost(relayURL)
	user := nodeName
	if networkID != "" {
		user = networkID + "/" + nodeName
	}
	return fmt.Sprintf("ssh://%s:%s@%s:%d", user, nodeToken, host, port)
}

// extractHost returns the hostname from a URL, falling back to the raw string.
func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return rawURL
	}
	return u.Hostname()
}

// printSetupQR renders a QR code to stderr using Unicode half-blocks.
func printSetupQR(content string) {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n(QR generation failed: %v)\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "\n%s\n", q.ToSmallString(false))
}
