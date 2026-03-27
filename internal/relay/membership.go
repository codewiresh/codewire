package relay

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/codewiresh/codewire/internal/oauth"
	"github.com/codewiresh/codewire/internal/store"
)

func membershipSubject(identity *oauth.AuthIdentity) (string, error) {
	switch {
	case identity == nil:
		return "", fmt.Errorf("unauthorized")
	case identity.IsAdmin:
		return "admin", nil
	case identity.Sub != "":
		return "oidc:" + identity.Sub, nil
	case identity.UserID != 0:
		return fmt.Sprintf("github:%d", identity.UserID), nil
	default:
		return "", fmt.Errorf("unsupported identity")
	}
}

func membershipForRequest(ctx context.Context, st store.Store, networkID string, identity *oauth.AuthIdentity) (*store.NetworkMember, error) {
	if identity == nil {
		return nil, fmt.Errorf("unauthorized")
	}
	if identity.IsAdmin {
		return &store.NetworkMember{
			NetworkID: networkID,
			Subject:   "admin",
			Role:      store.NetworkRoleOwner,
			CreatedAt: time.Now().UTC(),
		}, nil
	}
	subject, err := membershipSubject(identity)
	if err != nil {
		return nil, err
	}
	return st.NetworkMemberGet(ctx, networkID, subject)
}

func requireMembership(ctx context.Context, st store.Store, networkID string, identity *oauth.AuthIdentity) (*store.NetworkMember, bool, error) {
	member, err := membershipForRequest(ctx, st, networkID, identity)
	if err != nil {
		return nil, false, err
	}
	if member == nil {
		return nil, false, nil
	}
	return member, true, nil
}

func requireOwner(ctx context.Context, st store.Store, networkID string, identity *oauth.AuthIdentity) (bool, error) {
	member, ok, err := requireMembership(ctx, st, networkID, identity)
	if err != nil || !ok {
		return false, err
	}
	return strings.EqualFold(member.Role, store.NetworkRoleOwner), nil
}

func writeMembershipRequired(w http.ResponseWriter) {
	http.Error(w, "membership required", http.StatusForbidden)
}

func writeOwnerRequired(w http.ResponseWriter) {
	http.Error(w, "owner access required", http.StatusForbidden)
}
