package networkauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// FetchVerifierBundle fetches the current verifier bundle for a network.
func FetchVerifierBundle(ctx context.Context, client *http.Client, relayURL, networkID string) (*VerifierBundle, error) {
	if client == nil {
		client = http.DefaultClient
	}
	networkID = ResolveNetworkID(networkID)
	if networkID == "" {
		return nil, fmt.Errorf("network_id required")
	}
	requestURL := strings.TrimRight(strings.TrimSpace(relayURL), "/") + "/api/v1/network-auth/bundle?network_id=" + url.QueryEscape(networkID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building verifier bundle request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching verifier bundle: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching verifier bundle returned HTTP %d", resp.StatusCode)
	}
	var bundle VerifierBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return nil, fmt.Errorf("decoding verifier bundle response: %w", err)
	}
	return &bundle, nil
}

// IssueClientRuntimeCredential asks the relay for a client runtime credential.
func IssueClientRuntimeCredential(ctx context.Context, client *http.Client, relayURL, authToken, networkID string) (*RuntimeCredentialResponse, error) {
	networkID = ResolveNetworkID(networkID)
	if networkID == "" {
		return nil, fmt.Errorf("network_id required")
	}
	return issueRuntimeCredential(ctx, client, strings.TrimRight(strings.TrimSpace(relayURL), "/")+"/api/v1/network-auth/runtime/client?network_id="+url.QueryEscape(networkID), authToken)
}

// IssueNodeRuntimeCredential asks the relay for a node runtime credential.
func IssueNodeRuntimeCredential(ctx context.Context, client *http.Client, relayURL, nodeToken string) (*RuntimeCredentialResponse, error) {
	return issueRuntimeCredential(ctx, client, strings.TrimRight(strings.TrimSpace(relayURL), "/")+"/api/v1/network-auth/runtime/node", nodeToken)
}

func issueRuntimeCredential(ctx context.Context, client *http.Client, requestURL, authToken string) (*RuntimeCredentialResponse, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, fmt.Errorf("building runtime credential request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(authToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(authToken))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("issuing runtime credential: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuing runtime credential returned HTTP %d", resp.StatusCode)
	}
	var issued RuntimeCredentialResponse
	if err := json.NewDecoder(resp.Body).Decode(&issued); err != nil {
		return nil, fmt.Errorf("decoding runtime credential response: %w", err)
	}
	return &issued, nil
}

// IssueNodeSenderDelegation asks the relay for a node-authored sender delegation.
func IssueNodeSenderDelegation(ctx context.Context, client *http.Client, relayURL, nodeToken, sourceNode string, fromSessionID *uint32, fromSessionName string, verbs []string, audienceNode string) (*SenderDelegationResponse, error) {
	if client == nil {
		client = http.DefaultClient
	}

	body := map[string]any{
		"source_node":       strings.TrimSpace(sourceNode),
		"from_session_name": strings.TrimSpace(fromSessionName),
		"verbs":             verbs,
		"audience_node":     strings.TrimSpace(audienceNode),
	}
	if fromSessionID != nil {
		body["from_session_id"] = *fromSessionID
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encoding sender delegation request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(strings.TrimSpace(relayURL), "/")+"/api/v1/network-auth/delegation/node", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("building sender delegation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(nodeToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(nodeToken))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("issuing sender delegation: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuing sender delegation returned HTTP %d", resp.StatusCode)
	}

	var issued SenderDelegationResponse
	if err := json.NewDecoder(resp.Body).Decode(&issued); err != nil {
		return nil, fmt.Errorf("decoding sender delegation response: %w", err)
	}
	return &issued, nil
}
