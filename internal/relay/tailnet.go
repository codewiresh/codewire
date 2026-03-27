package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"nhooyr.io/websocket"

	"github.com/codewiresh/codewire/internal/networkauth"
	"github.com/codewiresh/codewire/internal/peer"
	"github.com/codewiresh/codewire/internal/store"
	tailnetlib "github.com/codewiresh/tailnet"
)

func tailnetCoordinateHandler(cfg RelayConfig, st store.Store, coord *tailnetlib.Coordinator, replay *networkauth.ReplayCache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if coord == nil {
			http.Error(w, "tailnet coordinator unavailable", http.StatusServiceUnavailable)
			return
		}

		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims, err := verifyRelayRuntimeCredential(r.Context(), st, token, replay)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if claims.SubjectKind != networkauth.SubjectKindClient && claims.SubjectKind != networkauth.SubjectKindNode {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch claims.SubjectKind {
		case networkauth.SubjectKindClient:
			if claims.SubjectID != "admin" {
				member, memberErr := st.NetworkMemberGet(r.Context(), claims.NetworkID, claims.SubjectID)
				if memberErr != nil {
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
				if member == nil {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			}
		case networkauth.SubjectKindNode:
			node, nodeErr := st.NodeGet(r.Context(), claims.NetworkID, claims.SubjectID)
			if nodeErr != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if node == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		derpMap, err := peer.NewDERPMapFromRelayURL(cfg.BaseURL)
		if err != nil {
			http.Error(w, "invalid relay base URL", http.StatusInternalServerError)
			return
		}

		wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer wsConn.CloseNow()

		peerID := peer.StablePrincipalUUID(claims.NetworkID, claims.SubjectKind, claims.SubjectID)
		if claims.SubjectKind == networkauth.SubjectKindClient {
			peerID = uuid.New()
		}
		respCh := coord.Register(peerID, claims.SubjectKind+":"+claims.SubjectID)
		defer coord.Deregister(peerID)

		if err := writeTailnetResponse(r.Context(), wsConn, peer.TailnetCoordinateResponse{
			Type:    "derp_map",
			DERPMap: derpMap,
		}); err != nil {
			return
		}

		ctx := r.Context()
		done := make(chan struct{})
		go func() {
			defer close(done)
			for nodes := range respCh {
				if len(nodes) == 0 {
					continue
				}
				if err := writeTailnetResponse(ctx, wsConn, peer.TailnetCoordinateResponse{
					Type:  "peer_update",
					Nodes: nodes,
				}); err != nil {
					return
				}
			}
		}()

		for {
			_, data, err := wsConn.Read(ctx)
			if err != nil {
				<-done
				return
			}

			var req peer.TailnetCoordinateRequest
			if err := json.Unmarshal(data, &req); err != nil {
				_ = writeTailnetResponse(ctx, wsConn, peer.TailnetCoordinateResponse{
					Type:  "error",
					Error: "bad request",
				})
				continue
			}

			switch req.Type {
			case "node":
				if req.Node == nil {
					_ = writeTailnetResponse(ctx, wsConn, peer.TailnetCoordinateResponse{
						Type:  "error",
						Error: "node update requires node payload",
					})
					continue
				}
				coord.UpdateNode(peerID, req.Node)
			case "subscribe":
				if claims.SubjectKind != networkauth.SubjectKindClient {
					_ = writeTailnetResponse(ctx, wsConn, peer.TailnetCoordinateResponse{
						Type:  "error",
						Error: "only client peers may subscribe",
					})
					continue
				}
				target := strings.TrimSpace(req.TargetNode)
				if target == "" {
					_ = writeTailnetResponse(ctx, wsConn, peer.TailnetCoordinateResponse{
						Type:  "error",
						Error: "subscribe requires target_node",
					})
					continue
				}
				coord.AddTunnel(peerID, peer.StablePrincipalUUID(claims.NetworkID, networkauth.SubjectKindNode, target))
			default:
				_ = writeTailnetResponse(ctx, wsConn, peer.TailnetCoordinateResponse{
					Type:  "error",
					Error: fmt.Sprintf("unsupported request type %q", req.Type),
				})
			}
		}
	}
}

func writeTailnetResponse(ctx context.Context, wsConn *websocket.Conn, resp peer.TailnetCoordinateResponse) error {
	payload, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return wsConn.Write(ctx, websocket.MessageText, payload)
}

func verifyRelayRuntimeCredential(ctx context.Context, st store.Store, token string, replay *networkauth.ReplayCache) (*networkauth.RuntimeClaims, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("missing runtime credential")
	}

	unverified, err := networkauth.ParseRuntimeCredential(token)
	if err != nil {
		return nil, err
	}

	state, err := loadIssuerState(ctx, st, unverified.NetworkID)
	if err != nil {
		return nil, err
	}
	claims, err := networkauth.VerifyRuntimeCredential(
		token,
		state.Bundle(time.Now().UTC(), networkauth.DefaultBundleValidity),
		time.Now().UTC(),
	)
	if err != nil {
		return nil, err
	}
	if err := replay.ConsumeRuntime(claims, time.Now().UTC()); err != nil {
		return nil, err
	}
	return claims, nil
}

func loadIssuerState(ctx context.Context, st store.Store, networkID string) (*networkauth.IssuerState, error) {
	networkID = resolveNetworkID(networkID)
	raw, err := st.KVGet(ctx, networkID, networkAuthNamespace, networkAuthIssuerKey)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("issuer state not found")
	}

	var state networkauth.IssuerState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}
	return &state, nil
}
