package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/codewiresh/codewire/internal/store"
)

const (
	sessionTokenPrefix = "sess_"
	inviteTokenPrefix  = "CW-INV-"
	alphanumeric       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// contextKey is unexported to prevent collisions.
type contextKey struct{}

// ExternalTokenValidator allows callers to trust an external bearer token
// source when local relay sessions do not apply.
type ExternalTokenValidator func(ctx context.Context, token string) *AuthIdentity

// AuthIdentity represents who made the request.
type AuthIdentity struct {
	// UserID is the GitHub user ID (0 if OIDC or admin token auth).
	UserID int64
	// Sub is the OIDC subject claim ("" if GitHub or admin token auth).
	Sub string
	// Username is the authenticated username.
	Username string
	// IsAdmin is true if authenticated via admin token.
	IsAdmin bool
}

// GetAuth extracts AuthIdentity from request context. Returns nil if not authenticated.
func GetAuth(ctx context.Context) *AuthIdentity {
	id, _ := ctx.Value(contextKey{}).(*AuthIdentity)
	return id
}

// WithAuth returns a context with the given AuthIdentity set.
func WithAuth(ctx context.Context, identity *AuthIdentity) context.Context {
	return context.WithValue(ctx, contextKey{}, identity)
}

// GenerateSessionToken returns a session token with the format sess_ + 32 random
// alphanumeric characters (~190 bits of entropy).
func GenerateSessionToken() string {
	return sessionTokenPrefix + randomAlphanumeric(32)
}

// GenerateInviteToken returns an invite token with the format CW-INV- + 24 random
// alphanumeric characters (~142 bits of entropy).
func GenerateInviteToken() string {
	return inviteTokenPrefix + randomAlphanumeric(24)
}

// GenerateState returns a 32-character hex string for use as an OAuth state parameter.
func GenerateState() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// RequireAuth returns middleware that validates session token, admin token, or rejects.
// It sets the AuthIdentity on the request context.
func RequireAuth(st store.Store, adminToken string) func(http.Handler) http.Handler {
	return RequireAuthWithFallback(st, adminToken, nil)
}

// RequireAuthWithFallback behaves like RequireAuth but allows a caller-provided
// external validator for bearer tokens that are not known to the local store.
func RequireAuthWithFallback(st store.Store, adminToken string, fallback ExternalTokenValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity := AuthenticateRequest(r, st, adminToken, fallback)
			if identity == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), contextKey{}, identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AuthenticateRequest resolves the caller identity from the request without
// mutating the request context.
func AuthenticateRequest(r *http.Request, st store.Store, adminToken string, fallback ExternalTokenValidator) *AuthIdentity {
	return authenticate(r, st, adminToken, fallback)
}

// authenticate checks all authentication methods and returns the identity,
// or nil if none succeeded.
func authenticate(r *http.Request, st store.Store, adminToken string, fallback ExternalTokenValidator) *AuthIdentity {
	// Check Authorization: Bearer header first.
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		if id := resolveToken(r.Context(), st, adminToken, token); id != nil {
			return id
		}
		if fallback != nil {
			if id := fallback(r.Context(), token); id != nil {
				return id
			}
		}
	}

	// Fall back to cw_session cookie.
	if cookie, err := r.Cookie("cw_session"); err == nil && cookie.Value != "" {
		if id := resolveToken(r.Context(), st, adminToken, cookie.Value); id != nil {
			return id
		}
	}

	return nil
}

// resolveToken checks a token against session store and admin token.
func resolveToken(ctx context.Context, st store.Store, adminToken, token string) *AuthIdentity {
	// Session tokens start with sess_.
	if strings.HasPrefix(token, sessionTokenPrefix) {
		// Try OIDC session first.
		if oidcSess, err := st.OIDCSessionGet(ctx, token); err == nil && oidcSess != nil {
			username := ""
			if user, err := st.OIDCUserGetBySub(ctx, oidcSess.Sub); err == nil && user != nil {
				username = user.Username
			}
			return &AuthIdentity{Sub: oidcSess.Sub, Username: username}
		}

		// Fall back to GitHub session.
		sess, err := st.SessionGet(ctx, token)
		if err != nil || sess == nil {
			return nil
		}
		if time.Now().After(sess.ExpiresAt) {
			return nil
		}
		user, err := st.UserGetByID(ctx, sess.GitHubID)
		if err != nil || user == nil {
			return nil
		}
		return &AuthIdentity{
			UserID:   user.GitHubID,
			Username: user.Username,
		}
	}

	// Check admin token.
	if adminToken != "" && token == adminToken {
		return &AuthIdentity{IsAdmin: true}
	}

	return nil
}

// randomAlphanumeric generates n random alphanumeric characters using crypto/rand.
func randomAlphanumeric(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	for i := range b {
		b[i] = alphanumeric[int(b[i])%len(alphanumeric)]
	}
	return string(b)
}
