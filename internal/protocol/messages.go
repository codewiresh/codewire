package protocol

import "encoding/json"

// SessionInfo describes a terminal session, matching the Rust SessionInfo struct.
type SessionInfo struct {
	ID                uint32  `json:"id"`
	Name              string  `json:"name,omitempty"`
	Prompt            string  `json:"prompt"`
	WorkingDir        string  `json:"working_dir"`
	CreatedAt         string  `json:"created_at"`
	Status            string  `json:"status"`
	Attached          bool    `json:"attached"`
	PID               *uint32 `json:"pid,omitempty"`
	OutputSizeBytes   *uint64 `json:"output_size_bytes,omitempty"`
	LastOutputSnippet *string `json:"last_output_snippet,omitempty"`

	// Enriched fields (new — backward compatible via omitempty).
	Tags             []string `json:"tags,omitempty"`
	ExitCode         *int     `json:"exit_code,omitempty"`
	CompletedAt      *string  `json:"completed_at,omitempty"`
	DurationMs       *int64   `json:"duration_ms,omitempty"`
	OutputLines      *uint64  `json:"output_lines,omitempty"`
	OutputBytes      *uint64  `json:"output_bytes,omitempty"`
	LastOutputAt     *string  `json:"last_output_at,omitempty"`
	LastEventAt      *string  `json:"last_event_at,omitempty"`
	IdleSeconds      *int64   `json:"idle_seconds,omitempty"`
	LastEventPreview *string  `json:"last_event_preview,omitempty"`
	LastEvent        *string  `json:"last_event,omitempty"`
	AttachedCount    int32    `json:"attached_count"`
}

// Request is the union of all client-to-server control messages.
// The Type field is the serde tag discriminator.
// Optional fields use omitempty so only relevant fields appear in JSON.
type Request struct {
	Type           string   `json:"type"`
	Command        []string `json:"command,omitempty"`
	WorkingDir     string   `json:"working_dir,omitempty"`
	ID             *uint32  `json:"id,omitempty"`
	IncludeHistory *bool    `json:"include_history,omitempty"`
	HistoryLines   *uint    `json:"history_lines,omitempty"`
	Cols           *uint16  `json:"cols,omitempty"`
	Rows           *uint16  `json:"rows,omitempty"`
	Follow         *bool    `json:"follow,omitempty"`
	Tail           *uint    `json:"tail,omitempty"`
	Data           []byte   `json:"data,omitempty"`

	// Session name for Launch and name-based addressing.
	Name string `json:"name,omitempty"`

	// Environment variable overrides for Launch (KEY=VALUE strings).
	Env []string `json:"env,omitempty"`

	// StdinData is injected into the session's PTY after launch.
	StdinData []byte `json:"stdin_data,omitempty"`

	// StripANSI controls ANSI escape stripping in Logs responses (default: true).
	StripANSI *bool `json:"strip_ansi,omitempty"`

	// New fields for enriched protocol.
	Tags           []string `json:"tags,omitempty"`
	EventTypes     []string `json:"event_types,omitempty"`
	SubscriptionID *uint64  `json:"subscription_id,omitempty"`
	Condition      string   `json:"condition,omitempty"` // "any", "all"
	TimeoutSeconds *uint64  `json:"timeout_seconds,omitempty"`
	Full           *bool    `json:"full,omitempty"`

	// KV fields.
	Namespace string `json:"namespace,omitempty"`
	Key       string `json:"key,omitempty"`
	Value     []byte `json:"value,omitempty"`
	TTL       string `json:"ttl,omitempty"` // Go duration string

	// Messaging fields.
	ToID         *uint32 `json:"to_id,omitempty"`
	ToName       string  `json:"to_name,omitempty"`
	Body         string  `json:"body,omitempty"`
	RequestID    string  `json:"request_id,omitempty"`
	ReplyToken   string  `json:"reply_token,omitempty"`
	Delivery     string  `json:"delivery,omitempty"`
	Verb         string  `json:"verb,omitempty"`
	AudienceNode string  `json:"audience_node,omitempty"`
	SenderCap    string  `json:"sender_cap,omitempty"`
	Summary      string  `json:"summary,omitempty"`
	State        string  `json:"state,omitempty"`
}

// UnmarshalJSON implements custom JSON unmarshalling for Request.
// When the type is "Attach" or "WatchSession" and include_history is absent,
// it defaults to true (matching Rust's #[serde(default = "default_true")]).
func (r *Request) UnmarshalJSON(b []byte) error {
	// Use an alias to avoid infinite recursion.
	type Alias Request
	aux := &Alias{}
	if err := json.Unmarshal(b, aux); err != nil {
		return err
	}
	*r = Request(*aux)

	// Check if include_history was explicitly present in the JSON.
	if r.Type == "Attach" && r.IncludeHistory == nil {
		t := true
		r.IncludeHistory = &t
	}

	return nil
}

// Response is the union of all server-to-client control messages.
// The Type field is the serde tag discriminator.
type Response struct {
	Type       string         `json:"type"`
	Sessions   *[]SessionInfo `json:"sessions,omitempty"`
	ID         *uint32        `json:"id,omitempty"`
	Count      *uint          `json:"count,omitempty"`
	Data       string         `json:"data,omitempty"`
	Done       *bool          `json:"done,omitempty"`
	Bytes      *uint          `json:"bytes,omitempty"`
	Info       *SessionInfo   `json:"info,omitempty"`
	OutputSize *uint64        `json:"output_size,omitempty"`
	Status     string         `json:"status,omitempty"`
	Output     *string        `json:"output,omitempty"`
	Message    string         `json:"message,omitempty"`

	// Subscribe/Event fields.
	SubscriptionID *uint64       `json:"subscription_id,omitempty"`
	SessionID      *uint32       `json:"session_id,omitempty"`
	Event          *SessionEvent `json:"event,omitempty"`

	// KV fields.
	Value   []byte    `json:"value,omitempty"`
	Entries *[]KVPair `json:"entries,omitempty"`

	// Messaging fields.
	MessageID string             `json:"message_id,omitempty"`
	Messages  *[]MessageResponse `json:"messages,omitempty"`
	RequestID string             `json:"request_id,omitempty"`
	ReplyBody string             `json:"reply_body,omitempty"`
	FromID    *uint32            `json:"from_id,omitempty"`
	FromName  string             `json:"from_name,omitempty"`
	SenderCap string             `json:"sender_cap,omitempty"`
}

// MessageResponse represents a message in an inbox read result.
type MessageResponse struct {
	MessageID  string `json:"message_id"`
	Timestamp  string `json:"timestamp"`
	From       uint32 `json:"from"`
	FromName   string `json:"from_name,omitempty"`
	To         uint32 `json:"to"`
	ToName     string `json:"to_name,omitempty"`
	Body       string `json:"body"`
	EventType  string `json:"type"` // "direct.message", "message.request", "message.reply"
	RequestID  string `json:"request_id,omitempty"`
	ReplyToken string `json:"reply_token,omitempty"`
}

// SessionEvent is a typed event pushed to subscribers.
type SessionEvent struct {
	Timestamp string          `json:"timestamp"`
	EventType string          `json:"type"`
	Data      json.RawMessage `json:"data"`
}

// KVPair is a key-value entry for list responses.
type KVPair struct {
	Key       string  `json:"key"`
	Value     []byte  `json:"value"`
	ExpiresAt *string `json:"expires_at,omitempty"`
}
