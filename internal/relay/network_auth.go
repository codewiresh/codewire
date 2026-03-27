package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/codewiresh/codewire/internal/networkauth"
	"github.com/codewiresh/codewire/internal/oauth"
	"github.com/codewiresh/codewire/internal/store"
)

const networkAuthNamespace = "relay.networkauth"
const networkAuthIssuerKey = "issuer.current"

func verifierBundleHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		networkID, err := requiredNetworkID(r.URL.Query().Get("network_id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		state, err := loadOrCreateIssuerState(r.Context(), st, networkID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state.Bundle(time.Now().UTC(), networkauth.DefaultBundleValidity))
	}
}

func clientRuntimeCredentialHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity := oauth.GetAuth(r.Context())
		if identity == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		networkID, err := requiredNetworkID(r.URL.Query().Get("network_id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !identity.IsAdmin {
			subject, err := membershipSubject(identity)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			member, err := st.NetworkMemberGet(r.Context(), networkID, subject)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if member == nil {
				writeMembershipRequired(w)
				return
			}
		}
		state, err := loadOrCreateIssuerState(r.Context(), st, networkID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		subjectID := clientSubjectID(identity)
		token, claims, err := networkauth.SignRuntimeCredential(state, networkauth.SubjectKindClient, subjectID, time.Now().UTC(), networkauth.DefaultRuntimeTTL)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(networkauth.RuntimeCredentialResponse{
			Credential:  token,
			NetworkID:   claims.NetworkID,
			SubjectKind: claims.SubjectKind,
			SubjectID:   claims.SubjectID,
			ExpiresAt:   claims.ExpiresAt,
		})
	}
}

func nodeRuntimeCredentialHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		node, err := nodeAuthFromRequest(r, st)
		if err != nil || node == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		state, err := loadOrCreateIssuerState(r.Context(), st, node.NetworkID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		token, claims, err := networkauth.SignRuntimeCredential(state, networkauth.SubjectKindNode, node.Name, time.Now().UTC(), networkauth.DefaultRuntimeTTL)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(networkauth.RuntimeCredentialResponse{
			Credential:  token,
			NetworkID:   claims.NetworkID,
			SubjectKind: claims.SubjectKind,
			SubjectID:   claims.SubjectID,
			ExpiresAt:   claims.ExpiresAt,
		})
	}
}

func nodeSenderDelegationHandler(st store.Store) http.HandlerFunc {
	type requestBody struct {
		SourceNode      string   `json:"source_node"`
		FromSessionID   *uint32  `json:"from_session_id,omitempty"`
		FromSessionName string   `json:"from_session_name,omitempty"`
		Verbs           []string `json:"verbs"`
		AudienceNode    string   `json:"audience_node,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		node, err := nodeAuthFromRequest(r, st)
		if err != nil || node == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var body requestBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(body.SourceNode) != "" && strings.TrimSpace(body.SourceNode) != node.Name {
			http.Error(w, "source_node must match authenticated node", http.StatusForbidden)
			return
		}

		state, err := loadOrCreateIssuerState(r.Context(), st, node.NetworkID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		token, claims, err := networkauth.SignSenderDelegation(
			state,
			node.Name,
			body.FromSessionID,
			body.FromSessionName,
			body.Verbs,
			body.AudienceNode,
			time.Now().UTC(),
			networkauth.DefaultSenderTTL,
		)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(networkauth.SenderDelegationResponse{
			Delegation:      token,
			NetworkID:       claims.NetworkID,
			SourceNode:      claims.SourceNode,
			FromSessionID:   claims.FromSessionID,
			FromSessionName: claims.FromSessionName,
			AudienceNode:    claims.AudienceNode,
			ExpiresAt:       claims.ExpiresAt,
		})
	}
}

func loadOrCreateIssuerState(ctx context.Context, st store.Store, networkID string) (*networkauth.IssuerState, error) {
	networkID = resolveNetworkID(networkID)
	if networkID == "" {
		return nil, fmt.Errorf("network_id required")
	}
	raw, err := st.KVGet(ctx, networkID, networkAuthNamespace, networkAuthIssuerKey)
	if err != nil {
		return nil, fmt.Errorf("loading issuer state: %w", err)
	}
	if len(raw) > 0 {
		var state networkauth.IssuerState
		if err := json.Unmarshal(raw, &state); err != nil {
			return nil, fmt.Errorf("decoding issuer state: %w", err)
		}
		return &state, nil
	}

	if err := st.NetworkEnsure(ctx, networkID); err != nil {
		return nil, fmt.Errorf("ensuring network: %w", err)
	}
	state, err := networkauth.NewIssuerState(networkID)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("encoding issuer state: %w", err)
	}
	if err := st.KVSet(ctx, networkID, networkAuthNamespace, networkAuthIssuerKey, encoded, nil); err != nil {
		return nil, fmt.Errorf("storing issuer state: %w", err)
	}
	return state, nil
}

func clientSubjectID(identity *oauth.AuthIdentity) string {
	switch {
	case identity == nil:
		return ""
	case identity.IsAdmin:
		return "admin"
	case identity.Sub != "":
		return "oidc:" + identity.Sub
	case identity.UserID != 0:
		return fmt.Sprintf("github:%d", identity.UserID)
	case strings.TrimSpace(identity.Username) != "":
		return "user:" + strings.TrimSpace(identity.Username)
	default:
		return "client"
	}
}
