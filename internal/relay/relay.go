package relay

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/codewiresh/codewire/internal/networkauth"
	"github.com/codewiresh/codewire/internal/oauth"
	"github.com/codewiresh/codewire/internal/store"
	tailnetlib "github.com/codewiresh/tailnet"
)

// RelayConfig configures the relay server.
type RelayConfig struct {
	// BaseURL is the public-facing HTTPS URL of the relay.
	BaseURL string
	// ListenAddr is the HTTP listen address (default ":8080").
	ListenAddr string
	// SSHListenAddr is the SSH listen address (default ":2222").
	SSHListenAddr string
	// DataDir is where relay.db lives.
	DataDir string
	// AuthMode controls authentication: "oidc", "github", "token", "none".
	AuthMode string
	// AuthToken is the shared secret when AuthMode is "token" or as fallback.
	AuthToken string
	// AllowedUsers is a list of GitHub usernames allowed to authenticate.
	AllowedUsers []string
	// GitHubClientID is a manual override for GitHub OAuth App client ID.
	GitHubClientID string
	// GitHubClientSecret is a manual override for GitHub OAuth App client secret.
	GitHubClientSecret string
	// OIDCIssuer is the OIDC provider issuer URL (e.g. https://auth.codewire.sh).
	// Required when AuthMode is "oidc".
	OIDCIssuer string
	// OIDCClientID is the registered OIDC client ID.
	OIDCClientID string
	// OIDCClientSecret is the registered OIDC client secret.
	OIDCClientSecret string
	// OIDCAllowedGroups restricts access to members of these groups.
	// Empty means any authenticated user is allowed.
	OIDCAllowedGroups []string
}

// RunRelay starts the relay server. It blocks until ctx is cancelled.
func RunRelay(ctx context.Context, cfg RelayConfig) error {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}
	if cfg.SSHListenAddr == "" {
		cfg.SSHListenAddr = ":2222"
	}

	st, err := store.NewSQLiteStore(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer st.Close()

	hub := NewNodeHub()
	sessions := NewPendingSessions()
	tailnetCoord := tailnetlib.NewCoordinator(slog.Default())
	runtimeReplay := networkauth.NewReplayCache()
	defer tailnetCoord.Close()
	derpSrv := tailnetlib.NewDERPServer()
	derpHandler, derpCleanup := tailnetlib.DERPHandler(derpSrv)
	defer func() {
		derpCleanup()
		derpSrv.Close()
	}()

	sshSrv, err := NewSSHServer(st, hub, sessions)
	if err != nil {
		return fmt.Errorf("creating SSH server: %w", err)
	}

	// Start SSH listener.
	sshLn, err := net.Listen("tcp", cfg.SSHListenAddr)
	if err != nil {
		return fmt.Errorf("SSH listen: %w", err)
	}
	go sshSrv.Serve(ctx, sshLn)
	fmt.Fprintf(os.Stderr, "[relay] SSH listening on %s\n", cfg.SSHListenAddr)

	// Build HTTP mux.
	mux := buildMux(hub, sessions, st, cfg, tailnetCoord, runtimeReplay, derpHandler)

	httpSrv := &http.Server{Addr: cfg.ListenAddr, Handler: mux}
	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "[relay] HTTP listening on %s (base_url=%s)\n", cfg.ListenAddr, cfg.BaseURL)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

// BuildRelayMux creates an HTTP mux with node agent endpoints (no OAuth, no GitHub).
// Used in tests; RunRelay calls the full buildMux.
func BuildRelayMux(hub *NodeHub, sessions *PendingSessions, st store.Store) http.Handler {
	mux := http.NewServeMux()
	RegisterNodeConnectHandler(mux, hub, st)
	RegisterBackHandler(mux, sessions, st)
	return mux
}

func buildMux(hub *NodeHub, sessions *PendingSessions, st store.Store, cfg RelayConfig, tailnetCoord *tailnetlib.Coordinator, runtimeReplay *networkauth.ReplayCache, derpHandler http.Handler) *http.ServeMux {
	var fallbackAuth oauth.ExternalTokenValidator
	if cfg.AuthMode == "oidc" {
		fallbackAuth = platformSessionAuthValidator(cfg.OIDCIssuer)
	}
	authMiddleware := oauth.RequireAuthWithFallback(st, cfg.AuthToken, fallbackAuth)
	joinRL := newRateLimiter(10, time.Minute)

	mux := http.NewServeMux()

	// Node agent WebSocket endpoints.
	RegisterNodeConnectHandler(mux, hub, st)
	RegisterBackHandler(mux, sessions, st)
	if derpHandler != nil {
		mux.Handle("/derp", derpHandler)
		mux.Handle("/derp/", derpHandler)
	}
	mux.HandleFunc("GET /derp/latency-check", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /api/v1/tailnet/coordinate", tailnetCoordinateHandler(cfg, st, tailnetCoord, runtimeReplay))

	// GitHub OAuth (when AuthMode == "github").
	if cfg.AuthMode == "github" {
		mux.HandleFunc("GET /auth/github/manifest/callback", oauth.ManifestCallbackHandler(st, cfg.BaseURL))
		mux.HandleFunc("GET /auth/github", oauth.LoginHandler(st, cfg.BaseURL, cfg.AllowedUsers))
		mux.HandleFunc("GET /auth/github/callback", oauth.CallbackHandler(st, cfg.BaseURL, cfg.AllowedUsers))
		mux.HandleFunc("GET /auth/session", oauth.SessionInfoHandler(st))
		mux.HandleFunc("GET /{$}", oauth.SetupPageHandler(st, cfg.BaseURL))

		if cfg.GitHubClientID != "" && cfg.GitHubClientSecret != "" {
			existing, _ := st.GitHubAppGet(context.Background())
			if existing == nil {
				st.GitHubAppSet(context.Background(), store.GitHubApp{
					ClientID:     cfg.GitHubClientID,
					ClientSecret: cfg.GitHubClientSecret,
					Owner:        "manual",
					CreatedAt:    time.Now().UTC(),
				})
			}
		}
	}

	// OIDC auth (when AuthMode == "oidc").
	if cfg.AuthMode == "oidc" {
		oidcProvider := &oauth.OIDCProvider{
			Issuer:        cfg.OIDCIssuer,
			ClientID:      cfg.OIDCClientID,
			ClientSecret:  cfg.OIDCClientSecret,
			AllowedGroups: cfg.OIDCAllowedGroups,
		}
		if err := oidcProvider.Discover(context.Background()); err != nil {
			// Log but don't crash — relay will return errors on auth endpoints if discovery failed.
			fmt.Fprintf(os.Stderr, "[relay] OIDC discovery failed: %v\n", err)
		}
		mux.HandleFunc("GET /auth/oidc", oidcProvider.LoginHandler(st, cfg.BaseURL))
		mux.HandleFunc("GET /auth/oidc/callback", oidcProvider.CallbackHandler(st, cfg.BaseURL))
		mux.HandleFunc("GET /auth/session", oidcProvider.OIDCSessionInfoHandler(st))
		mux.HandleFunc("GET /{$}", oidcProvider.OIDCIndexHandler(cfg.BaseURL))

		// Device flow (public, rate-limited same as join).
		mux.HandleFunc("POST /api/v1/device/authorize", rateLimitMiddleware(joinRL, deviceAuthorizeHandler(st, oidcProvider)))
		mux.HandleFunc("POST /api/v1/device/poll", devicePollHandler(st, oidcProvider))
	}

	// Auth config discovery (unauthenticated, used by cw setup).
	mux.HandleFunc("GET /api/v1/auth/config", authConfigHandler(cfg.AuthMode))
	mux.Handle("GET /api/v1/auth/validate", authMiddleware(http.HandlerFunc(authValidateHandler())))
	mux.HandleFunc("GET /api/v1/network-auth/bundle", verifierBundleHandler(st))
	mux.Handle("POST /api/v1/network-auth/runtime/client", authMiddleware(http.HandlerFunc(clientRuntimeCredentialHandler(st))))
	mux.HandleFunc("POST /api/v1/network-auth/runtime/node", nodeRuntimeCredentialHandler(st))
	mux.HandleFunc("POST /api/v1/network-auth/delegation/node", nodeSenderDelegationHandler(st))

	// Node registration (issues a random node token).
	mux.Handle("GET /api/v1/networks", authMiddleware(http.HandlerFunc(networkListHandler(st))))
	mux.Handle("POST /api/v1/networks", authMiddleware(http.HandlerFunc(networkCreateHandler(st))))
	mux.Handle("POST /api/v1/nodes", authMiddleware(http.HandlerFunc(nodeRegisterHandler(st))))
	mux.Handle("DELETE /api/v1/nodes/{name}", authMiddleware(http.HandlerFunc(nodeRevokeHandler(st))))
	mux.Handle("GET /api/v1/nodes", authMiddleware(http.HandlerFunc(nodesListHandler(st))))

	// Invite management (owner-only).
	mux.Handle("POST /api/v1/invites", authMiddleware(http.HandlerFunc(inviteCreateHandler(st))))
	mux.Handle("GET /api/v1/invites", authMiddleware(http.HandlerFunc(inviteListHandler(st))))
	mux.Handle("DELETE /api/v1/invites/{token}", authMiddleware(http.HandlerFunc(inviteDeleteHandler(st))))

	// Authenticated membership join.
	mux.Handle("POST /api/v1/networks/join", authMiddleware(http.HandlerFunc(networkJoinHandler(st))))

	// Invite redemption for node bootstrap (public, rate-limited).
	mux.HandleFunc("POST /api/v1/join", rateLimitMiddleware(joinRL, joinHandler(st)))
	mux.HandleFunc("GET /join", joinPageHandler(cfg.BaseURL))

	// KV API.
	mux.Handle("PUT /api/v1/kv/{namespace}/{key}", authMiddleware(http.HandlerFunc(kvSetHandler(st))))
	mux.Handle("GET /api/v1/kv/{namespace}/{key}", authMiddleware(http.HandlerFunc(kvGetHandler(st))))
	mux.Handle("DELETE /api/v1/kv/{namespace}/{key}", authMiddleware(http.HandlerFunc(kvDeleteHandler(st))))
	mux.Handle("GET /api/v1/kv/{namespace}", authMiddleware(http.HandlerFunc(kvListHandler(st))))

	// Health check.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	return mux
}

func resolveNetworkID(raw string) string {
	return strings.TrimSpace(raw)
}

func requiredNetworkID(raw string) (string, error) {
	networkID := resolveNetworkID(raw)
	if networkID == "" {
		return "", fmt.Errorf("network_id required")
	}
	return networkID, nil
}

func validateNetworkID(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("network id required")
	}
	for _, ch := range raw {
		isLetter := ch >= 'a' && ch <= 'z'
		isUpper := ch >= 'A' && ch <= 'Z'
		isDigit := ch >= '0' && ch <= '9'
		if isLetter || isUpper || isDigit || ch == '-' || ch == '_' {
			continue
		}
		return fmt.Errorf("network id may only contain letters, numbers, '-' or '_'")
	}
	return nil
}

func authValidateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

// --- Networks ---

type networkResponse struct {
	ID          string    `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	NodeCount   int       `json:"node_count"`
	InviteCount int       `json:"invite_count"`
}

func networkListHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := oauth.GetAuth(r.Context())
		var (
			networks []store.Network
			err      error
		)
		if auth != nil && auth.IsAdmin {
			networks, err = st.NetworkList(r.Context())
		} else {
			subject, subjectErr := membershipSubject(auth)
			if subjectErr != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			networks, err = st.NetworkListByMember(r.Context(), subject)
		}
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		resp := make([]networkResponse, 0, len(networks))
		for _, network := range networks {
			resp = append(resp, networkResponse{
				ID:          network.ID,
				CreatedAt:   network.CreatedAt,
				NodeCount:   network.NodeCount,
				InviteCount: network.InviteCount,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func networkCreateHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			NetworkID string `json:"network_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "network_id required", http.StatusBadRequest)
			return
		}

		networkID := strings.TrimSpace(req.NetworkID)
		if err := validateNetworkID(networkID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		auth := oauth.GetAuth(r.Context())
		if auth == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if auth.IsAdmin {
			if err := st.NetworkEnsure(r.Context(), networkID); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"status":     "created",
				"network_id": networkID,
			})
			return
		}

		subject, err := membershipSubject(auth)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := st.NetworkEnsure(r.Context(), networkID); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		count, err := st.NetworkMemberCount(r.Context(), networkID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		member, err := st.NetworkMemberGet(r.Context(), networkID, subject)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if count > 0 && member == nil {
			http.Error(w, "network already claimed", http.StatusConflict)
			return
		}
		if member == nil {
			if err := st.NetworkMemberUpsert(r.Context(), store.NetworkMember{
				NetworkID: networkID,
				Subject:   subject,
				Role:      store.NetworkRoleOwner,
				CreatedAt: time.Now().UTC(),
				CreatedBy: subject,
			}); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":     "created",
			"network_id": networkID,
		})
	}
}

// --- Node Registration ---

func nodeRegisterHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			NodeName  string `json:"node_name"`
			NetworkID string `json:"network_id,omitempty"`
			PeerURL   string `json:"peer_url,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NodeName == "" {
			http.Error(w, "node_name required", http.StatusBadRequest)
			return
		}
		networkID, err := requiredNetworkID(req.NetworkID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		auth := oauth.GetAuth(r.Context())
		if _, ok, err := requireMembership(r.Context(), st, networkID, auth); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		} else if !ok {
			writeMembershipRequired(w)
			return
		}

		token := generateToken()

		var githubID *int64
		if auth != nil && auth.UserID != 0 {
			githubID = &auth.UserID
		}

		node := store.NodeRecord{
			NetworkID:    networkID,
			Name:         req.NodeName,
			Token:        token,
			PeerURL:      strings.TrimSpace(req.PeerURL),
			GitHubID:     githubID,
			AuthorizedAt: time.Now().UTC(),
			LastSeenAt:   time.Now().UTC(),
		}
		if err := st.NodeRegister(r.Context(), node); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":     "registered",
			"node_token": token,
			"node_name":  req.NodeName,
			"network_id": networkID,
		})
	}
}

// --- Node Revocation ---

func nodeRevokeHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		networkID, err := requiredNetworkID(r.URL.Query().Get("network_id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		owner, err := requireOwner(r.Context(), st, networkID, oauth.GetAuth(r.Context()))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !owner {
			writeOwnerRequired(w)
			return
		}

		node, err := st.NodeGet(r.Context(), networkID, name)
		if err != nil || node == nil {
			http.Error(w, "node not found", http.StatusNotFound)
			return
		}

		if err := st.NodeDelete(r.Context(), networkID, name); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "revoked",
			"node":   name,
		})
	}
}

// --- Node Discovery ---

type nodeResponse struct {
	NetworkID string `json:"network_id,omitempty"`
	Name      string `json:"name"`
	PeerURL   string `json:"peer_url,omitempty"`
	Connected bool   `json:"connected"`
}

func nodesListHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		all := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("all")), "true")
		auth := oauth.GetAuth(r.Context())

		var (
			networkID string
			nodes     []store.NodeRecord
			err       error
		)
		if auth != nil && auth.IsAdmin && all {
			nodes, err = st.NodeListAll(r.Context())
		} else if all {
			subject, subjectErr := membershipSubject(auth)
			if subjectErr != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			networks, listErr := st.NetworkListByMember(r.Context(), subject)
			if listErr != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			for _, network := range networks {
				networkNodes, listNodesErr := st.NodeList(r.Context(), network.ID)
				if listNodesErr != nil {
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
				nodes = append(nodes, networkNodes...)
			}
		} else {
			networkID, err = requiredNetworkID(r.URL.Query().Get("network_id"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if _, ok, memberErr := requireMembership(r.Context(), st, networkID, auth); memberErr != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			} else if !ok {
				writeMembershipRequired(w)
				return
			}
			nodes, err = st.NodeList(r.Context(), networkID)
		}
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		resp := make([]nodeResponse, 0, len(nodes))
		for _, n := range nodes {
			connected := time.Since(n.LastSeenAt) < 2*time.Minute
			resp = append(resp, nodeResponse{
				NetworkID: n.NetworkID,
				Name:      n.Name,
				PeerURL:   n.PeerURL,
				Connected: connected,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// --- Invite Handlers ---

type inviteCreateRequest struct {
	NetworkID string `json:"network_id,omitempty"`
	Uses      int    `json:"uses"`
	TTL       string `json:"ttl"`
}

func inviteCreateHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req inviteCreateRequest
		json.NewDecoder(r.Body).Decode(&req)

		if req.Uses <= 0 {
			req.Uses = 1
		}
		networkID, err := requiredNetworkID(req.NetworkID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		owner, err := requireOwner(r.Context(), st, networkID, oauth.GetAuth(r.Context()))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !owner {
			writeOwnerRequired(w)
			return
		}

		ttl := time.Hour
		if req.TTL != "" {
			parsed, parseErr := time.ParseDuration(req.TTL)
			if parseErr != nil {
				http.Error(w, "invalid ttl", http.StatusBadRequest)
				return
			}
			ttl = parsed
		}

		auth := oauth.GetAuth(r.Context())
		var createdBy *int64
		if auth != nil && auth.UserID != 0 {
			createdBy = &auth.UserID
		}

		now := time.Now().UTC()
		invite := store.Invite{
			NetworkID:     networkID,
			Token:         oauth.GenerateInviteToken(),
			CreatedBy:     createdBy,
			UsesRemaining: req.Uses,
			ExpiresAt:     now.Add(ttl),
			CreatedAt:     now,
		}

		if err := st.InviteCreate(r.Context(), invite); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(invite)
	}
}

func inviteListHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		networkID, err := requiredNetworkID(r.URL.Query().Get("network_id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if owner, err := requireOwner(r.Context(), st, networkID, oauth.GetAuth(r.Context())); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		} else if !owner {
			writeOwnerRequired(w)
			return
		}
		invites, err := st.InviteList(r.Context(), networkID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(invites)
	}
}

func inviteDeleteHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.PathValue("token")
		networkID, err := requiredNetworkID(r.URL.Query().Get("network_id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if owner, err := requireOwner(r.Context(), st, networkID, oauth.GetAuth(r.Context())); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		} else if !owner {
			writeOwnerRequired(w)
			return
		}
		if err := st.InviteDelete(r.Context(), networkID, token); err != nil {
			http.Error(w, "invite not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- Invite Redemption ---

type joinRequest struct {
	NodeName    string `json:"node_name"`
	InviteToken string `json:"invite_token"`
}

func networkJoinHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			InviteToken string `json:"invite_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.InviteToken) == "" {
			http.Error(w, "invite_token required", http.StatusBadRequest)
			return
		}

		invite, _ := st.InviteGet(r.Context(), req.InviteToken)
		if invite == nil {
			http.Error(w, "invalid or expired invite", http.StatusForbidden)
			return
		}
		if err := st.InviteConsume(r.Context(), req.InviteToken); err != nil {
			http.Error(w, "invalid or expired invite", http.StatusForbidden)
			return
		}

		subject, err := membershipSubject(oauth.GetAuth(r.Context()))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		now := time.Now().UTC()
		role := store.NetworkRoleMember
		if existing, err := st.NetworkMemberGet(r.Context(), invite.NetworkID, subject); err == nil && existing != nil {
			role = existing.Role
		} else if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := st.NetworkMemberUpsert(r.Context(), store.NetworkMember{
			NetworkID: invite.NetworkID,
			Subject:   subject,
			Role:      role,
			CreatedAt: now,
			CreatedBy: invite.Token,
		}); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":     "joined",
			"network_id": invite.NetworkID,
		})
	}
}

func joinHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req joinRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		if req.NodeName == "" || req.InviteToken == "" {
			http.Error(w, "node_name and invite_token required", http.StatusBadRequest)
			return
		}

		// Look up invite before consuming (for github_id association).
		invite, _ := st.InviteGet(r.Context(), req.InviteToken)

		// Consume invite (validates + decrements uses).
		if err := st.InviteConsume(r.Context(), req.InviteToken); err != nil {
			http.Error(w, "invalid or expired invite", http.StatusForbidden)
			return
		}

		if invite == nil || strings.TrimSpace(invite.NetworkID) == "" {
			http.Error(w, "invalid or expired invite", http.StatusForbidden)
			return
		}

		var githubID *int64
		networkID := invite.NetworkID
		if invite.CreatedBy != nil {
			githubID = invite.CreatedBy
		}

		token := generateToken()
		node := store.NodeRecord{
			NetworkID:    networkID,
			Name:         req.NodeName,
			Token:        token,
			GitHubID:     githubID,
			AuthorizedAt: time.Now().UTC(),
			LastSeenAt:   time.Now().UTC(),
		}

		if err := st.NodeRegister(r.Context(), node); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":     "registered",
			"node_token": token,
			"node_name":  req.NodeName,
			"network_id": networkID,
		})
	}
}

func joinPageHandler(baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		invite := r.URL.Query().Get("invite")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Join CodeWire Relay</title>
<style>body{font-family:system-ui;max-width:480px;margin:80px auto;text-align:center;color:#1a1a1a}
h2{font-weight:600}
.code{font-family:monospace;background:#f5f5f5;padding:8px 16px;border-radius:6px;display:inline-block;margin:12px 0;word-break:break-all}
p{color:#525252;line-height:1.6}
</style></head><body>
<h2>Join CodeWire Relay</h2>
<p>Use this invite code to join the network:</p>
<div class="code">%s</div>
<p>Run on your device:</p>
<div class="code">cw login && cw network join --relay-url %s %s</div>
</body></html>`, invite, baseURL, invite)
	}
}

// --- KV API ---

func kvSetHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := r.PathValue("namespace")
		key := r.PathValue("key")
		networkID, err := requiredNetworkID(r.URL.Query().Get("network_id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		var ttl *time.Duration
		if ttlStr := r.Header.Get("X-TTL"); ttlStr != "" {
			d, err := time.ParseDuration(ttlStr)
			if err != nil {
				http.Error(w, "invalid X-TTL header", http.StatusBadRequest)
				return
			}
			ttl = &d
		}

		if err := st.KVSet(r.Context(), networkID, ns, key, body, ttl); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func kvGetHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := r.PathValue("namespace")
		key := r.PathValue("key")
		networkID, err := requiredNetworkID(r.URL.Query().Get("network_id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		val, err := st.KVGet(r.Context(), networkID, ns, key)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if val == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(val)
	}
}

func kvDeleteHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := r.PathValue("namespace")
		key := r.PathValue("key")
		networkID, err := requiredNetworkID(r.URL.Query().Get("network_id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := st.KVDelete(r.Context(), networkID, ns, key); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func kvListHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := r.PathValue("namespace")
		prefix := r.URL.Query().Get("prefix")
		networkID, err := requiredNetworkID(r.URL.Query().Get("network_id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		entries, err := st.KVList(r.Context(), networkID, ns, prefix)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	}
}

// --- Rate Limiter ---

type rateLimiter struct {
	mu      sync.Mutex
	entries map[string][]time.Time
	limit   int
	window  time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		entries: make(map[string][]time.Time),
		limit:   limit,
		window:  window,
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	times := rl.entries[ip]
	valid := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		rl.entries[ip] = valid
		return false
	}
	rl.entries[ip] = append(valid, now)
	return true
}

func remoteIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func rateLimitMiddleware(rl *rateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(remoteIP(r)) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// --- Auth Config ---

func authConfigHandler(authMode string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"auth_mode": authMode,
		})
	}
}

// --- Helpers ---

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
