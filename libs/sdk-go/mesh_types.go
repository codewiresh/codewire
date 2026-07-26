package codewire

import "time"

// MeshNetwork is a network managed by the mesh.
type MeshNetwork struct {
	ID          string    `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	NodeCount   int       `json:"node_count"`
	InviteCount int       `json:"invite_count"`
}

// MeshNode is a node registered with the mesh.
type MeshNode struct {
	NetworkID string `json:"network_id,omitempty"`
	Name      string `json:"name"`
	PeerURL   string `json:"peer_url,omitempty"`
	Connected bool   `json:"connected"`
}

// MeshEnrollment is an enrollment token for registering nodes.
type MeshEnrollment struct {
	ID              string    `json:"id"`
	NetworkID       string    `json:"network_id"`
	NodeName        string    `json:"node_name,omitempty"`
	EnrollmentToken string    `json:"enrollment_token"`
	UsesRemaining   int       `json:"uses_remaining"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// MeshNodeCredentials are returned when an enrollment token is redeemed.
type MeshNodeCredentials struct {
	NodeToken    string `json:"node_token"`
	NodeName     string `json:"node_name"`
	NetworkID    string `json:"network_id"`
	EnrollmentID string `json:"enrollment_id,omitempty"`
}

// MeshKVEntry is a key-value pair in the mesh store.
type MeshKVEntry struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
}

// MeshGroup is a named communication boundary in a network.
type MeshGroup struct {
	NetworkID string            `json:"network_id"`
	Name      string            `json:"name"`
	CreatedAt time.Time         `json:"created_at"`
	CreatedBy string            `json:"created_by,omitempty"`
	Members   []MeshGroupMember `json:"members,omitempty"`
	Policy    *MeshGroupPolicy  `json:"policy,omitempty"`
}

// MeshGroupMember binds a session to a group.
type MeshGroupMember struct {
	NetworkID   string    `json:"network_id"`
	GroupName   string    `json:"group_name"`
	NodeName    string    `json:"node_name"`
	SessionName string    `json:"session_name"`
	CreatedAt   time.Time `json:"created_at"`
}

// MeshGroupPolicy controls messaging and debug access within a group.
type MeshGroupPolicy struct {
	NetworkID      string `json:"network_id"`
	GroupName      string `json:"group_name"`
	MessagesPolicy string `json:"messages_policy"`
	DebugPolicy    string `json:"debug_policy"`
}

// MeshRuntimeCredential is an Ed25519-signed short-lived credential.
type MeshRuntimeCredential struct {
	Credential  string    `json:"credential"`
	NetworkID   string    `json:"network_id"`
	SubjectKind string    `json:"subject_kind"`
	SubjectID   string    `json:"subject_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// MeshVerifierKey is a public key for verifying credentials.
type MeshVerifierKey struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

// MeshVerifierBundle is the set of public keys for one network.
type MeshVerifierBundle struct {
	NetworkID string            `json:"network_id"`
	Issuer    string            `json:"issuer"`
	Keys      []MeshVerifierKey `json:"keys"`
	Version   uint64            `json:"version"`
	ExpiresAt time.Time         `json:"expires_at"`
}

// MeshSenderDelegation is a signed sender delegation token.
type MeshSenderDelegation struct {
	Delegation      string    `json:"delegation"`
	NetworkID       string    `json:"network_id"`
	SourceNode      string    `json:"source_node"`
	FromSessionID   *uint32   `json:"from_session_id,omitempty"`
	FromSessionName string    `json:"from_session_name,omitempty"`
	AudienceNode    string    `json:"audience_node,omitempty"`
	ExpiresAt       time.Time `json:"expires_at"`
}
