package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codewiresh/codewire/internal/networkauth"
	"github.com/codewiresh/codewire/internal/store"
	"nhooyr.io/websocket"
)

func createGitHubSession(t *testing.T, st store.Store, githubID int64, username string) string {
	t.Helper()
	now := time.Now().UTC()
	if err := st.UserUpsert(context.Background(), store.User{
		GitHubID:    githubID,
		Username:    username,
		CreatedAt:   now,
		LastLoginAt: now,
	}); err != nil {
		t.Fatalf("UserUpsert: %v", err)
	}
	token := "sess_" + username
	if err := st.SessionCreate(context.Background(), store.Session{
		Token:     token,
		GitHubID:  githubID,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("SessionCreate: %v", err)
	}
	return token
}

func TestNodesListRequiresMembershipAndScopesByNetwork(t *testing.T) {
	st, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	memberToken := createGitHubSession(t, st, 101, "member")
	outsiderToken := createGitHubSession(t, st, 202, "outsider")
	now := time.Now().UTC()
	if err := st.NetworkMemberUpsert(context.Background(), store.NetworkMember{
		NetworkID: "network-a",
		Subject:   "github:101",
		Role:      store.NetworkRoleOwner,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("NetworkMemberUpsert: %v", err)
	}

	hub := NewNodeHub()
	sessions := NewPendingSessions()
	srv := httptest.NewServer(buildMux(hub, sessions, st, RelayConfig{
		BaseURL:   "http://relay.test",
		AuthMode:  "token",
		AuthToken: "admin-token",
	}, nil, networkauth.NewReplayCache(), nil))
	defer srv.Close()
	client := srv.Client()

	registerNode := func(networkID, nodeName string) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{
			"network_id": networkID,
			"node_name":  nodeName,
		})
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/nodes", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer admin-token")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("register node: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("register node status = %d", resp.StatusCode)
		}
	}

	registerNode("network-a", "shared-node")
	registerNode("network-b", "shared-node")

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/nodes?network_id=network-a", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unauthenticated list nodes: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/v1/nodes?network_id=network-a", nil)
	req.Header.Set("Authorization", "Bearer "+outsiderToken)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("outsider list nodes: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("outsider status = %d, want 403", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/v1/nodes?network_id=network-a", nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("member list nodes: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member status = %d", resp.StatusCode)
	}

	var nodes []nodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		t.Fatalf("decode nodes: %v", err)
	}
	if len(nodes) != 1 || nodes[0].Name != "shared-node" {
		t.Fatalf("nodes = %#v, want one network-a node", nodes)
	}

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/v1/nodes?all=true", nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("member list all nodes: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member all status = %d", resp.StatusCode)
	}

	nodes = nil
	if err := json.NewDecoder(resp.Body).Decode(&nodes); err != nil {
		t.Fatalf("decode all nodes: %v", err)
	}
	if len(nodes) != 1 || nodes[0].NetworkID != "network-a" {
		t.Fatalf("all nodes = %#v, want only network-a membership scope", nodes)
	}
}

func TestOIDCAuthAcceptsPlatformSessionBearer(t *testing.T) {
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                        upstream.URL,
				"authorization_endpoint":        upstream.URL + "/auth",
				"token_endpoint":                upstream.URL + "/token",
				"userinfo_endpoint":             upstream.URL + "/userinfo",
				"device_authorization_endpoint": upstream.URL + "/device",
			})
		case "/api/auth/get-session":
			if got := r.Header.Get("Authorization"); got != "Bearer platform-session-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user": map[string]string{
					"id":    "user_123",
					"email": "n@noeljackson.com",
					"name":  "Noel Jackson",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	st, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	srv := httptest.NewServer(buildMux(NewNodeHub(), NewPendingSessions(), st, RelayConfig{
		BaseURL:          "http://relay.test",
		AuthMode:         "oidc",
		OIDCIssuer:       upstream.URL,
		OIDCClientID:     "codewire-relay",
		OIDCClientSecret: "secret",
	}, nil, networkauth.NewReplayCache(), nil))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/networks", nil)
	req.Header.Set("Authorization", "Bearer platform-session-token")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("authenticated list networks: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var networks []networkResponse
	if err := json.NewDecoder(resp.Body).Decode(&networks); err != nil {
		t.Fatalf("decode networks: %v", err)
	}
	if len(networks) != 0 {
		t.Fatalf("networks = %#v, want no memberships by default", networks)
	}
}

func TestKVIsNetworkScopedAndRequiresAuth(t *testing.T) {
	st, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	srv := httptest.NewServer(buildMux(NewNodeHub(), NewPendingSessions(), st, RelayConfig{
		BaseURL:   "http://relay.test",
		AuthMode:  "token",
		AuthToken: "admin-token",
	}, nil, networkauth.NewReplayCache(), nil))
	defer srv.Close()
	client := srv.Client()

	putKV := func(networkID, value string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/api/v1/kv/tasks/build?network_id="+networkID, bytes.NewBufferString(value))
		req.Header.Set("Authorization", "Bearer admin-token")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("put kv: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("put kv status = %d", resp.StatusCode)
		}
	}

	putKV("network-a", "alpha")
	putKV("network-b", "beta")

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/kv/tasks/build?network_id=network-a", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unauthenticated kv get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated kv status = %d, want 401", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/v1/kv/tasks/build?network_id=network-a", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("network-a kv get: %v", err)
	}
	defer resp.Body.Close()
	var valueA bytes.Buffer
	if _, err := valueA.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read valueA: %v", err)
	}
	if valueA.String() != "alpha" {
		t.Fatalf("network-a value = %q, want alpha", valueA.String())
	}

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/v1/kv/tasks/build?network_id=network-b", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("network-b kv get: %v", err)
	}
	defer resp.Body.Close()
	var valueB bytes.Buffer
	if _, err := valueB.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read valueB: %v", err)
	}
	if valueB.String() != "beta" {
		t.Fatalf("network-b value = %q, want beta", valueB.String())
	}
}

func TestAuthenticatedNetworkJoinAddsMembership(t *testing.T) {
	st, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	memberToken := createGitHubSession(t, st, 101, "member")

	now := time.Now().UTC()
	if err := st.InviteCreate(context.Background(), store.Invite{
		NetworkID:     "network-invite",
		Token:         "CW-INV-TEST",
		UsesRemaining: 1,
		ExpiresAt:     now.Add(1 * time.Hour),
		CreatedAt:     now,
	}); err != nil {
		t.Fatalf("InviteCreate: %v", err)
	}

	srv := httptest.NewServer(buildMux(NewNodeHub(), NewPendingSessions(), st, RelayConfig{
		BaseURL:   "http://relay.test",
		AuthMode:  "token",
		AuthToken: "admin-token",
	}, nil, networkauth.NewReplayCache(), nil))
	defer srv.Close()
	client := srv.Client()

	body, _ := json.Marshal(map[string]string{"invite_token": "CW-INV-TEST"})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/networks/join", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+memberToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("join status = %d", resp.StatusCode)
	}

	member, err := st.NetworkMemberGet(context.Background(), "network-invite", "github:101")
	if err != nil {
		t.Fatalf("NetworkMemberGet: %v", err)
	}
	if member == nil || member.Role != store.NetworkRoleMember {
		t.Fatalf("member = %#v, want joined member", member)
	}
}

func TestNetworksCanBeCreatedAndListedForOwner(t *testing.T) {
	st, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	memberToken := createGitHubSession(t, st, 101, "member")
	otherToken := createGitHubSession(t, st, 202, "other")

	srv := httptest.NewServer(buildMux(NewNodeHub(), NewPendingSessions(), st, RelayConfig{
		BaseURL:   "http://relay.test",
		AuthMode:  "token",
		AuthToken: "admin-token",
	}, nil, networkauth.NewReplayCache(), nil))
	defer srv.Close()
	client := srv.Client()

	createBody, _ := json.Marshal(map[string]string{"network_id": "project-alpha"})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/networks", bytes.NewReader(createBody))
	req.Header.Set("Authorization", "Bearer "+memberToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create network status = %d", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/v1/networks", nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("list networks: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list networks status = %d", resp.StatusCode)
	}

	var networks []networkResponse
	if err := json.NewDecoder(resp.Body).Decode(&networks); err != nil {
		t.Fatalf("decode networks: %v", err)
	}

	found := map[string]networkResponse{}
	for _, network := range networks {
		found[network.ID] = network
	}
	if _, ok := found["project-alpha"]; !ok {
		t.Fatal("expected project-alpha network")
	}

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/v1/networks", nil)
	req.Header.Set("Authorization", "Bearer "+otherToken)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("list outsider networks: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("outsider list status = %d", resp.StatusCode)
	}
	networks = nil
	if err := json.NewDecoder(resp.Body).Decode(&networks); err != nil {
		t.Fatalf("decode outsider networks: %v", err)
	}
	if len(networks) != 0 {
		t.Fatalf("outsider networks = %#v, want none", networks)
	}
}

func TestClientRuntimeCredentialRequiresMembership(t *testing.T) {
	st, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	memberToken := createGitHubSession(t, st, 101, "member")
	outsiderToken := createGitHubSession(t, st, 202, "outsider")
	now := time.Now().UTC()
	if err := st.NetworkMemberUpsert(context.Background(), store.NetworkMember{
		NetworkID: "network-a",
		Subject:   "github:101",
		Role:      store.NetworkRoleOwner,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("NetworkMemberUpsert: %v", err)
	}

	srv := httptest.NewServer(buildMux(NewNodeHub(), NewPendingSessions(), st, RelayConfig{
		BaseURL:   "http://relay.test",
		AuthMode:  "token",
		AuthToken: "admin-token",
	}, nil, networkauth.NewReplayCache(), nil))
	defer srv.Close()
	client := srv.Client()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/network-auth/runtime/client?network_id=network-a", nil)
	req.Header.Set("Authorization", "Bearer "+outsiderToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("outsider runtime credential: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("outsider runtime status = %d, want 403", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/api/v1/network-auth/runtime/client?network_id=network-a", nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("member runtime credential: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member runtime status = %d", resp.StatusCode)
	}
}

func TestNodeConnectPersistsPeerURL(t *testing.T) {
	st, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	token := "node-token"
	now := time.Now().UTC()
	if err := st.NodeRegister(context.Background(), store.NodeRecord{
		NetworkID:    "network-a",
		Name:         "builder",
		Token:        token,
		AuthorizedAt: now,
		LastSeenAt:   now,
	}); err != nil {
		t.Fatalf("NodeRegister: %v", err)
	}

	srv := httptest.NewServer(buildMux(NewNodeHub(), NewPendingSessions(), st, RelayConfig{
		BaseURL:  "http://relay.test",
		AuthMode: "none",
	}, nil, networkauth.NewReplayCache(), nil))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/node/connect"
	ws, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization":       {"Bearer " + token},
			"X-CodeWire-Peer-URL": {"https://builder.example.com/ws"},
		},
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer ws.CloseNow()

	node, err := st.NodeGet(context.Background(), "network-a", "builder")
	if err != nil {
		t.Fatalf("NodeGet: %v", err)
	}
	if node == nil {
		t.Fatal("expected node")
	}
	if node.PeerURL != "https://builder.example.com/ws" {
		t.Fatalf("PeerURL = %q, want advertised URL", node.PeerURL)
	}
}
