package codewire

import "time"

// MeshNetwork is a network managed by the mesh.
type MeshNetwork struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	CreatedAt   time.Time `json:"created_at"`
	NodeCount   int64     `json:"node_count"`
	InviteCount int64     `json:"invite_count"`
}

// MeshNode is a node registered with the mesh.
type MeshNode struct {
	OrgID     string `json:"org_id"`
	NetworkID string `json:"network_id,omitempty"`
	Name      string `json:"name"`
	PeerURL   string `json:"peer_url,omitempty"`
	Connected bool   `json:"connected"`
}

// MeshEnrollment is an enrollment token for registering nodes.
type MeshEnrollment struct {
	ID             string     `json:"id"`
	OrgID          string     `json:"org_id"`
	NetworkID      string     `json:"network_id"`
	NodeName       string     `json:"node_name,omitempty"`
	OwnerUserID    string     `json:"owner_user_id"`
	IssuedByUserID string     `json:"issued_by_user_id"`
	ExpiresAt      time.Time  `json:"expires_at"`
	CreatedAt      time.Time  `json:"created_at"`
	RedeemedAt     *time.Time `json:"redeemed_at,omitempty"`
	EnrollmentCode string     `json:"enrollment_code"`
}

// MeshNodeRegistration is the non-secret result of consuming a one-use node
// enrollment capability.
type MeshNodeRegistration struct {
	Node       MeshNode       `json:"node"`
	Enrollment MeshEnrollment `json:"enrollment"`
}

// MeshKVEntry is a key-value pair in the mesh store.
type MeshKVEntry struct {
	OrgID     string     `json:"org_id"`
	NetworkID string     `json:"network_id"`
	Namespace string     `json:"namespace"`
	Key       string     `json:"key"`
	Value     []byte     `json:"value,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// MeshGroup is a named communication boundary in a network.
type MeshGroup struct {
	OrgID           string            `json:"org_id"`
	NetworkID       string            `json:"network_id"`
	Name            string            `json:"name"`
	CreatedAt       time.Time         `json:"created_at"`
	CreatedByUserID string            `json:"created_by_user_id,omitempty"`
	Members         []MeshGroupMember `json:"members,omitempty"`
	Policy          *MeshGroupPolicy  `json:"policy,omitempty"`
}

// MeshGroupMember binds a session to a group.
type MeshGroupMember struct {
	OrgID       string    `json:"org_id"`
	NetworkID   string    `json:"network_id"`
	GroupName   string    `json:"group_name"`
	NodeName    string    `json:"node_name"`
	SessionName string    `json:"session_name"`
	CreatedAt   time.Time `json:"created_at"`
}

// MeshGroupMessagesPolicy controls which senders may message group members.
type MeshGroupMessagesPolicy string

const (
	MeshGroupMessagesPolicyUnspecified  MeshGroupMessagesPolicy = ""
	MeshGroupMessagesPolicyInternalOnly MeshGroupMessagesPolicy = "internal-only"
	MeshGroupMessagesPolicyOpen         MeshGroupMessagesPolicy = "open"
)

// MeshGroupDebugPolicy controls debug access to group members.
type MeshGroupDebugPolicy string

const (
	MeshGroupDebugPolicyUnspecified MeshGroupDebugPolicy = ""
	MeshGroupDebugPolicyNone        MeshGroupDebugPolicy = "none"
	MeshGroupDebugPolicyObserveOnly MeshGroupDebugPolicy = "observe-only"
	MeshGroupDebugPolicyFull        MeshGroupDebugPolicy = "full"
)

// MeshGroupPolicy controls messaging and debug access within a group.
type MeshGroupPolicy struct {
	OrgID          string                  `json:"org_id"`
	NetworkID      string                  `json:"network_id"`
	GroupName      string                  `json:"group_name"`
	MessagesPolicy MeshGroupMessagesPolicy `json:"messages_policy"`
	DebugPolicy    MeshGroupDebugPolicy    `json:"debug_policy"`
	UpdatedAt      time.Time               `json:"updated_at"`
}
