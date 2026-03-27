// Package store provides a pluggable storage interface for the CodeWire relay.
// The default implementation uses SQLite (pure Go, no CGO). A PostgreSQL
// backend can be added later behind the same interface.
package store

import (
	"context"
	"time"
)

// KVEntry is a single key-value pair returned by KVList.
type KVEntry struct {
	Key       string     `json:"key"`
	Value     []byte     `json:"value"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Network describes a named relay network.
type Network struct {
	ID          string    `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	NodeCount   int       `json:"node_count"`
	InviteCount int       `json:"invite_count"`
}

const (
	NetworkRoleOwner  = "owner"
	NetworkRoleMember = "member"
)

// NetworkMember records which authenticated principals belong to a network.
type NetworkMember struct {
	NetworkID string    `json:"network_id"`
	Subject   string    `json:"subject"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
}

// NodeRecord is a registered relay node.
type NodeRecord struct {
	NetworkID    string    `json:"network_id"`
	Name         string    `json:"name"`
	Token        string    `json:"token"` // random auth token (replaces WireGuard public key)
	PeerURL      string    `json:"peer_url,omitempty"`
	GitHubID     *int64    `json:"github_id,omitempty"`
	AuthorizedAt time.Time `json:"authorized_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
}

// GitHubApp stores the GitHub App credentials (singleton, one row).
type GitHubApp struct {
	AppID         int64     `json:"app_id"`
	ClientID      string    `json:"client_id"`
	ClientSecret  string    `json:"client_secret"`
	PEM           string    `json:"pem"`
	WebhookSecret string    `json:"webhook_secret"`
	Owner         string    `json:"owner"`
	CreatedAt     time.Time `json:"created_at"`
}

// User represents a GitHub user who has logged in.
type User struct {
	GitHubID    int64     `json:"github_id"`
	Username    string    `json:"username"`
	AvatarURL   string    `json:"avatar_url"`
	CreatedAt   time.Time `json:"created_at"`
	LastLoginAt time.Time `json:"last_login_at"`
}

// Session is an authenticated session token tied to a user.
type Session struct {
	Token     string    `json:"token"`
	GitHubID  int64     `json:"github_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// OAuthState is an anti-CSRF state parameter for OAuth.
type OAuthState struct {
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Invite is an invite code for device onboarding.
type Invite struct {
	NetworkID     string    `json:"network_id"`
	Token         string    `json:"token"`
	CreatedBy     *int64    `json:"created_by"`
	UsesRemaining int       `json:"uses_remaining"`
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedAt     time.Time `json:"created_at"`
}

// OIDCUser represents a user authenticated via OIDC (any provider).
type OIDCUser struct {
	Sub         string    `json:"sub"`
	Username    string    `json:"username"`
	AvatarURL   string    `json:"avatar_url"`
	CreatedAt   time.Time `json:"created_at"`
	LastLoginAt time.Time `json:"last_login_at"`
}

// OIDCSession is an admin UI session backed by an OIDC login.
type OIDCSession struct {
	Token     string    `json:"token"`
	Sub       string    `json:"sub"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// OIDCDeviceFlow tracks an in-flight RFC 8628 device authorization request.
// PollToken is an opaque value given to the CLI to poll for completion.
// DeviceCode is the code used to poll the OIDC provider's token endpoint.
type OIDCDeviceFlow struct {
	PollToken  string    `json:"poll_token"`
	DeviceCode string    `json:"device_code"`
	NetworkID  string    `json:"network_id"`
	NodeName   string    `json:"node_name"`
	NodeToken  string    `json:"node_token"` // populated by OIDCDeviceFlowComplete
	ExpiresAt  time.Time `json:"expires_at"`
}

// RevokedKey is a WireGuard public key that has been revoked.
type RevokedKey struct {
	PublicKey string    `json:"public_key"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason"`
}

// DeviceCode is used for the device authorization flow.
type DeviceCode struct {
	Code      string    `json:"code"`
	PublicKey string    `json:"public_key"`
	NodeName  string    `json:"node_name"`
	Status    string    `json:"status"` // "pending", "authorized"
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Store is the relay's storage interface. All methods are safe for concurrent use.
type Store interface {
	// KV store — shared across all nodes.
	KVSet(ctx context.Context, networkID, namespace, key string, value []byte, ttl *time.Duration) error
	KVGet(ctx context.Context, networkID, namespace, key string) ([]byte, error)
	KVDelete(ctx context.Context, networkID, namespace, key string) error
	KVList(ctx context.Context, networkID, namespace, prefix string) ([]KVEntry, error)

	// Node registry — internal to relay.
	NetworkEnsure(ctx context.Context, networkID string) error
	NetworkList(ctx context.Context) ([]Network, error)
	NetworkListByMember(ctx context.Context, subject string) ([]Network, error)
	NetworkMemberGet(ctx context.Context, networkID, subject string) (*NetworkMember, error)
	NetworkMemberUpsert(ctx context.Context, member NetworkMember) error
	NetworkMemberCount(ctx context.Context, networkID string) (int, error)
	NodeRegister(ctx context.Context, node NodeRecord) error
	NodeList(ctx context.Context, networkID string) ([]NodeRecord, error)
	NodeListAll(ctx context.Context) ([]NodeRecord, error)
	NodeGet(ctx context.Context, networkID, name string) (*NodeRecord, error)
	NodeGetByToken(ctx context.Context, token string) (*NodeRecord, error)
	NodeDelete(ctx context.Context, networkID, name string) error
	NodeUpdateLastSeen(ctx context.Context, networkID, name string) error

	// Device authorization flow.
	DeviceCodeCreate(ctx context.Context, dc DeviceCode) error
	DeviceCodeGet(ctx context.Context, code string) (*DeviceCode, error)
	DeviceCodeConfirm(ctx context.Context, code string) error
	DeviceCodeCleanup(ctx context.Context) error

	// GitHub App (singleton).
	GitHubAppGet(ctx context.Context) (*GitHubApp, error)
	GitHubAppSet(ctx context.Context, app GitHubApp) error

	// Users.
	UserUpsert(ctx context.Context, user User) error
	UserGetByID(ctx context.Context, githubID int64) (*User, error)
	UserGetByUsername(ctx context.Context, username string) (*User, error)

	// Sessions.
	SessionCreate(ctx context.Context, sess Session) error
	SessionGet(ctx context.Context, token string) (*Session, error)
	SessionDelete(ctx context.Context, token string) error
	SessionDeleteByUser(ctx context.Context, githubID int64) error

	// OAuth State.
	OAuthStateCreate(ctx context.Context, state OAuthState) error
	OAuthStateConsume(ctx context.Context, state string) error

	// Invites.
	InviteCreate(ctx context.Context, invite Invite) error
	InviteGet(ctx context.Context, token string) (*Invite, error)
	InviteConsume(ctx context.Context, token string) error
	InviteList(ctx context.Context, networkID string) ([]Invite, error)
	InviteDelete(ctx context.Context, networkID, token string) error

	// OIDC Users.
	OIDCUserUpsert(ctx context.Context, user OIDCUser) error
	OIDCUserGetBySub(ctx context.Context, sub string) (*OIDCUser, error)

	// OIDC Sessions.
	OIDCSessionCreate(ctx context.Context, sess OIDCSession) error
	OIDCSessionGet(ctx context.Context, token string) (*OIDCSession, error)
	OIDCSessionDelete(ctx context.Context, token string) error

	// OIDC Device Flows.
	OIDCDeviceFlowCreate(ctx context.Context, flow OIDCDeviceFlow) error
	OIDCDeviceFlowGet(ctx context.Context, pollToken string) (*OIDCDeviceFlow, error)
	OIDCDeviceFlowComplete(ctx context.Context, pollToken, nodeToken string) error

	// Revoked Keys.
	RevokedKeyAdd(ctx context.Context, key RevokedKey) error
	RevokedKeyCheck(ctx context.Context, publicKey string) (bool, error)

	// Close releases resources (e.g. closes the database).
	Close() error
}
