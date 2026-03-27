package networkauth

import "time"

const (
	RuntimeTokenPrefix    = "cwrt1"
	SenderTokenPrefix     = "cwsd1"
	AlgorithmEd25519      = "Ed25519"
	SubjectKindClient     = "client"
	SubjectKindNode       = "node"
	RuntimeKind           = "runtime"
	SenderDelegationKind  = "sender"
	DefaultBundleValidity = 15 * time.Minute
	DefaultRuntimeTTL     = 5 * time.Minute
	DefaultSenderTTL      = 2 * time.Minute
)

// VerifierKey is a public verification key for one issuer key ID.
type VerifierKey struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

// VerifierBundle is the public verifier set for one network.
type VerifierBundle struct {
	NetworkID string        `json:"network_id"`
	Issuer    string        `json:"issuer"`
	Keys      []VerifierKey `json:"keys"`
	Version   uint64        `json:"version"`
	ExpiresAt time.Time     `json:"expires_at"`
}

// RuntimeClaims are the signed claims for a runtime credential.
type RuntimeClaims struct {
	Kind        string    `json:"kind"`
	NetworkID   string    `json:"network_id"`
	SubjectKind string    `json:"subject_kind"`
	SubjectID   string    `json:"subject_id"`
	Issuer      string    `json:"issuer"`
	KeyID       string    `json:"kid"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	JTI         string    `json:"jti"`
}

// IssuerState is the relay-side private issuer state for one network.
type IssuerState struct {
	NetworkID  string    `json:"network_id"`
	Issuer     string    `json:"issuer"`
	KeyID      string    `json:"key_id"`
	PrivateKey string    `json:"private_key"`
	PublicKey  string    `json:"public_key"`
	CreatedAt  time.Time `json:"created_at"`
	Version    uint64    `json:"version"`
}

// RuntimeCredentialResponse is returned by the relay issuance endpoint.
type RuntimeCredentialResponse struct {
	Credential  string    `json:"credential"`
	NetworkID   string    `json:"network_id"`
	SubjectKind string    `json:"subject_kind"`
	SubjectID   string    `json:"subject_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// SenderDelegationClaims are the signed claims for a session sender delegation.
type SenderDelegationClaims struct {
	Kind            string    `json:"kind"`
	NetworkID       string    `json:"network_id"`
	SourceNode      string    `json:"source_node"`
	FromSessionID   *uint32   `json:"from_session_id,omitempty"`
	FromSessionName string    `json:"from_session_name,omitempty"`
	Verbs           []string  `json:"verbs"`
	AudienceNode    string    `json:"audience_node,omitempty"`
	Issuer          string    `json:"issuer"`
	KeyID           string    `json:"kid"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	JTI             string    `json:"jti"`
}

// SenderDelegationResponse is returned by the relay and local node delegation endpoints.
type SenderDelegationResponse struct {
	Delegation      string    `json:"delegation"`
	NetworkID       string    `json:"network_id"`
	SourceNode      string    `json:"source_node"`
	FromSessionID   *uint32   `json:"from_session_id,omitempty"`
	FromSessionName string    `json:"from_session_name,omitempty"`
	AudienceNode    string    `json:"audience_node,omitempty"`
	ExpiresAt       time.Time `json:"expires_at"`
}
