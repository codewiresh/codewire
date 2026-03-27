package relay_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codewiresh/codewire/internal/oauth"
	"github.com/codewiresh/codewire/internal/relay"
	"github.com/codewiresh/codewire/internal/store"
)

// newTestSQLiteStore creates a temporary SQLite store for testing.
func newTestSQLiteStore(t *testing.T) store.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// newTestOIDCProvider creates an OIDCProvider with pre-populated endpoints
// pointing at the provided mock server URL.
func newTestOIDCProvider(mockURL string) *oauth.OIDCProvider {
	p := &oauth.OIDCProvider{
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		AllowedGroups: nil, // allow all
	}
	// Inject endpoints directly so Discover() is not needed.
	p.SetEndpointsForTest(mockURL+"/device/auth", mockURL+"/token", mockURL+"/userinfo")
	return p
}

// TestDeviceAuthorizeHandler verifies that the authorize endpoint:
//   - POSTs to the OIDC provider's device authorization endpoint
//   - stores an OIDCDeviceFlow in the store
//   - returns poll_token, user_code, verification_uri, and interval to the caller
func TestDeviceAuthorizeHandler(t *testing.T) {
	// Mock Dex device authorization endpoint.
	mockDex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/device/auth" {
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":      "dex_device_code_123",
			"user_code":        "ABCD-EFGH",
			"verification_uri": "https://auth.example.com/device",
			"expires_in":       300,
			"interval":         5,
		})
	}))
	defer mockDex.Close()

	st := newTestSQLiteStore(t)
	p := newTestOIDCProvider(mockDex.URL)

	// Register the handler via the exported test helper.
	mux := http.NewServeMux()
	relay.RegisterDeviceHandlersForTest(mux, st, p)

	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := srv.Client()

	// POST /api/v1/device/authorize with node_name.
	body, _ := json.Marshal(map[string]string{
		"node_name":  "my-node",
		"network_id": "project-alpha",
	})
	resp, err := client.Post(srv.URL+"/api/v1/device/authorize", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/v1/device/authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var got struct {
		PollToken       string `json:"poll_token"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		Interval        int    `json:"interval"`
		ExpiresIn       int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}

	if got.PollToken == "" {
		t.Error("poll_token should not be empty")
	}
	if got.UserCode != "ABCD-EFGH" {
		t.Errorf("user_code = %q, want %q", got.UserCode, "ABCD-EFGH")
	}
	if got.VerificationURI != "https://auth.example.com/device" {
		t.Errorf("verification_uri = %q, want %q", got.VerificationURI, "https://auth.example.com/device")
	}
	if got.Interval != 5 {
		t.Errorf("interval = %d, want 5", got.Interval)
	}
}

// TestDevicePollHandler_Pending verifies that when Dex returns
// authorization_pending the relay returns {"status":"pending"} with 202.
func TestDevicePollHandler_Pending(t *testing.T) {
	mockDex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/device/auth":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"device_code":      "pending_device_code",
				"user_code":        "XXXX-YYYY",
				"verification_uri": "https://auth.example.com/device",
				"expires_in":       300,
				"interval":         5,
			})
		case "/token":
			// Simulate user not having approved yet.
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
		default:
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer mockDex.Close()

	st := newTestSQLiteStore(t)
	p := newTestOIDCProvider(mockDex.URL)

	mux := http.NewServeMux()
	relay.RegisterDeviceHandlersForTest(mux, st, p)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := srv.Client()

	// First: authorize to get a poll_token.
	authBody, _ := json.Marshal(map[string]string{
		"node_name":  "pending-node",
		"network_id": "project-alpha",
	})
	authResp, err := client.Post(srv.URL+"/api/v1/device/authorize", "application/json", bytes.NewReader(authBody))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("authorize returned %d", authResp.StatusCode)
	}
	var authGot struct {
		PollToken string `json:"poll_token"`
	}
	json.NewDecoder(authResp.Body).Decode(&authGot)
	if authGot.PollToken == "" {
		t.Fatal("empty poll_token from authorize")
	}

	// Now poll — Dex says authorization_pending.
	pollBody, _ := json.Marshal(map[string]string{"poll_token": authGot.PollToken})
	pollResp, err := client.Post(srv.URL+"/api/v1/device/poll", "application/json", bytes.NewReader(pollBody))
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	defer pollResp.Body.Close()

	if pollResp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", pollResp.StatusCode)
	}
	var pollGot struct {
		Status string `json:"status"`
	}
	json.NewDecoder(pollResp.Body).Decode(&pollGot)
	if pollGot.Status != "pending" {
		t.Errorf("status = %q, want %q", pollGot.Status, "pending")
	}
}

// TestDevicePollHandler_Authorized verifies the happy path: Dex returns an
// access token, userinfo is fetched, and the relay returns a node_token.
func TestDevicePollHandler_Authorized(t *testing.T) {
	const accessToken = "dex_access_token_xyz"

	mockDex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/device/auth":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"device_code":      "approved_device_code",
				"user_code":        "DONE-DONE",
				"verification_uri": "https://auth.example.com/device",
				"expires_in":       300,
				"interval":         5,
			})
		case "/token":
			// Simulate user having approved.
			json.NewEncoder(w).Encode(map[string]string{
				"access_token": accessToken,
				"token_type":   "Bearer",
			})
		case "/userinfo":
			// Validate the Authorization header contains the access token.
			if r.Header.Get("Authorization") != "Bearer "+accessToken {
				http.Error(w, "bad token", http.StatusUnauthorized)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sub":                "user_sub_abc",
				"preferred_username": "testuser",
				"groups":             []string{"developers"},
			})
		default:
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer mockDex.Close()

	st := newTestSQLiteStore(t)
	p := newTestOIDCProvider(mockDex.URL)

	mux := http.NewServeMux()
	relay.RegisterDeviceHandlersForTest(mux, st, p)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := srv.Client()

	// Step 1: authorize.
	authBody, _ := json.Marshal(map[string]string{
		"node_name":  "auth-node",
		"network_id": "project-alpha",
	})
	authResp, err := client.Post(srv.URL+"/api/v1/device/authorize", "application/json", bytes.NewReader(authBody))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("authorize returned %d", authResp.StatusCode)
	}
	var authGot struct {
		PollToken string `json:"poll_token"`
	}
	json.NewDecoder(authResp.Body).Decode(&authGot)
	if authGot.PollToken == "" {
		t.Fatal("empty poll_token from authorize")
	}

	// Step 2: poll — Dex returns an access token this time.
	pollBody, _ := json.Marshal(map[string]string{"poll_token": authGot.PollToken})
	pollResp, err := client.Post(srv.URL+"/api/v1/device/poll", "application/json", bytes.NewReader(pollBody))
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	defer pollResp.Body.Close()

	if pollResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", pollResp.StatusCode)
	}
	var pollGot struct {
		Status    string `json:"status"`
		NodeToken string `json:"node_token"`
		NodeName  string `json:"node_name"`
	}
	if err := json.NewDecoder(pollResp.Body).Decode(&pollGot); err != nil {
		t.Fatalf("decoding poll response: %v", err)
	}

	if pollGot.Status != "authorized" {
		t.Errorf("status = %q, want %q", pollGot.Status, "authorized")
	}
	if pollGot.NodeToken == "" {
		t.Error("node_token should not be empty")
	}
	if pollGot.NodeName != "auth-node" {
		t.Errorf("node_name = %q, want %q", pollGot.NodeName, "auth-node")
	}

	// Step 3: verify the node was registered in the store.
	node, err := st.NodeGetByToken(context.Background(), pollGot.NodeToken)
	if err != nil {
		t.Fatalf("NodeGetByToken: %v", err)
	}
	if node == nil {
		t.Fatal("expected node in store after authorization")
	}
	if node.Name != "auth-node" {
		t.Errorf("node.Name = %q, want %q", node.Name, "auth-node")
	}

	// Step 4: poll again — should return cached authorized result.
	pollBody2, _ := json.Marshal(map[string]string{"poll_token": authGot.PollToken})
	pollResp2, err := client.Post(srv.URL+"/api/v1/device/poll", "application/json", bytes.NewReader(pollBody2))
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	defer pollResp2.Body.Close()
	if pollResp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on second poll, got %d", pollResp2.StatusCode)
	}
	var pollGot2 struct {
		Status    string `json:"status"`
		NodeToken string `json:"node_token"`
	}
	json.NewDecoder(pollResp2.Body).Decode(&pollGot2)
	if pollGot2.Status != "authorized" {
		t.Errorf("second poll status = %q, want %q", pollGot2.Status, "authorized")
	}
	if pollGot2.NodeToken != pollGot.NodeToken {
		t.Errorf("second poll returned different node_token: %q vs %q", pollGot2.NodeToken, pollGot.NodeToken)
	}

	// Step 5: verify the OIDC user was upserted.
	user, err := st.OIDCUserGetBySub(context.Background(), "user_sub_abc")
	if err != nil {
		t.Fatalf("OIDCUserGetBySub: %v", err)
	}
	if user == nil {
		t.Fatal("expected OIDC user in store after authorization")
	}
	if user.Username != "testuser" {
		t.Errorf("user.Username = %q, want %q", user.Username, "testuser")
	}
}
