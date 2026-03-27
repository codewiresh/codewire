package relay

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/codewiresh/codewire/internal/oauth"
	"github.com/codewiresh/codewire/internal/store"
)

// RegisterDeviceHandlersForTest registers the OIDC device flow handlers on the
// provided mux. This is exported for use in tests; production code wires these
// handlers through buildMux in relay.go.
func RegisterDeviceHandlersForTest(mux *http.ServeMux, st store.Store, p *oauth.OIDCProvider) {
	mux.HandleFunc("POST /api/v1/device/authorize", deviceAuthorizeHandler(st, p))
	mux.HandleFunc("POST /api/v1/device/poll", devicePollHandler(st, p))
}

// --- OIDC Device Flow ---

// deviceAuthorizeHandler handles POST /api/v1/device/authorize.
// It initiates an RFC 8628 device authorization request against the OIDC
// provider and stores the resulting device code alongside an opaque poll_token
// for the CLI to use when polling.
func deviceAuthorizeHandler(st store.Store, p *oauth.OIDCProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			NodeName  string `json:"node_name"`
			NetworkID string `json:"network_id,omitempty"`
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

		// Ask the OIDC provider to start the device authorization flow.
		data := url.Values{
			"client_id":     {p.ClientID},
			"client_secret": {p.ClientSecret},
			"scope":         {"openid profile email groups"},
		}
		dreq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, p.DeviceEndpoint(), strings.NewReader(data.Encode()))
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		dreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		dreq.Header.Set("Accept", "application/json")

		dresp, err := http.DefaultClient.Do(dreq)
		if err != nil {
			slog.Error("device authorize: OIDC provider unreachable", "err", err)
			http.Error(w, "upstream OIDC error", http.StatusBadGateway)
			return
		}
		defer dresp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(dresp.Body, 1<<20))
		if dresp.StatusCode != http.StatusOK {
			slog.Error("device authorize: OIDC provider error", "status", dresp.StatusCode, "body", string(body))
			http.Error(w, "upstream OIDC error", http.StatusBadGateway)
			return
		}

		var dauth struct {
			DeviceCode      string `json:"device_code"`
			UserCode        string `json:"user_code"`
			VerificationURI string `json:"verification_uri"`
			ExpiresIn       int    `json:"expires_in"`
			Interval        int    `json:"interval"`
		}
		if err := json.Unmarshal(body, &dauth); err != nil {
			http.Error(w, "parsing device auth response: "+err.Error(), http.StatusBadGateway)
			return
		}

		expiresIn := 300
		if dauth.ExpiresIn > 0 {
			expiresIn = dauth.ExpiresIn
		}
		interval := 5
		if dauth.Interval > 0 {
			interval = dauth.Interval
		}

		flow := store.OIDCDeviceFlow{
			PollToken:  generateToken(),
			DeviceCode: dauth.DeviceCode,
			NetworkID:  networkID,
			NodeName:   req.NodeName,
			ExpiresAt:  time.Now().UTC().Add(time.Duration(expiresIn) * time.Second),
		}
		if err := st.OIDCDeviceFlowCreate(r.Context(), flow); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"poll_token":       flow.PollToken,
			"user_code":        dauth.UserCode,
			"verification_uri": dauth.VerificationURI,
			"expires_in":       expiresIn,
			"interval":         interval,
		})
	}
}

// devicePollHandler handles POST /api/v1/device/poll.
// The CLI calls this endpoint repeatedly until the user approves the device in
// their browser. Once approved, the handler exchanges the device_code for an
// access token, validates the user's groups, registers the node, and returns
// the node_token.
func devicePollHandler(st store.Store, p *oauth.OIDCProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PollToken string `json:"poll_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PollToken == "" {
			http.Error(w, "poll_token required", http.StatusBadRequest)
			return
		}

		flow, err := st.OIDCDeviceFlowGet(r.Context(), req.PollToken)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if flow == nil {
			http.Error(w, "expired or invalid poll token", http.StatusGone)
			return
		}

		// Already completed in a prior poll?
		if flow.NodeToken != "" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"status":     "authorized",
				"node_token": flow.NodeToken,
				"node_name":  flow.NodeName,
			})
			return
		}

		// Poll the OIDC provider's token endpoint with the device code grant.
		data := url.Values{
			"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code":   {flow.DeviceCode},
			"client_id":     {p.ClientID},
			"client_secret": {p.ClientSecret},
		}
		treq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, p.TokenEndpoint(), strings.NewReader(data.Encode()))
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		treq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		treq.Header.Set("Accept", "application/json")

		tresp, err := http.DefaultClient.Do(treq)
		if err != nil {
			slog.Error("device poll: OIDC provider unreachable", "err", err)
			http.Error(w, "upstream OIDC error", http.StatusBadGateway)
			return
		}
		defer tresp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(tresp.Body, 1<<20))

		var tokenResp struct {
			AccessToken string `json:"access_token"`
			Error       string `json:"error"`
		}
		json.Unmarshal(body, &tokenResp)

		switch tokenResp.Error {
		case "authorization_pending":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
			return
		case "slow_down":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]string{"status": "slow_down"})
			return
		case "":
			// No error — proceed below.
		default:
			slog.Error("device poll: OIDC authorization failed", "error", tokenResp.Error)
			http.Error(w, "OIDC authorization failed", http.StatusForbidden)
			return
		}

		if tokenResp.AccessToken == "" {
			http.Error(w, "empty access_token from OIDC provider", http.StatusBadGateway)
			return
		}

		// Fetch claims and validate group membership.
		sub, username, groups, avatarURL, err := p.UserinfoClaims(r.Context(), tokenResp.AccessToken)
		if err != nil {
			http.Error(w, "userinfo failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		if err := p.CheckGroups(groups); err != nil {
			http.Error(w, "access denied: "+err.Error(), http.StatusForbidden)
			return
		}

		// Upsert user record.
		now := time.Now().UTC()
		if err := st.OIDCUserUpsert(r.Context(), store.OIDCUser{
			Sub: sub, Username: username, AvatarURL: avatarURL, CreatedAt: now, LastLoginAt: now,
		}); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Register node with a new random token.
		nodeToken := generateToken()
		if err := st.NodeRegister(r.Context(), store.NodeRecord{
			NetworkID:    flow.NetworkID,
			Name:         flow.NodeName,
			Token:        nodeToken,
			AuthorizedAt: now,
			LastSeenAt:   now,
		}); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Mark the device flow as complete.
		if err := st.OIDCDeviceFlowComplete(r.Context(), req.PollToken, nodeToken); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":     "authorized",
			"node_token": nodeToken,
			"node_name":  flow.NodeName,
			"network_id": flow.NetworkID,
		})
	}
}
