package session

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"

	"github.com/codewiresh/codewire/internal/protocol"
	termutil "github.com/codewiresh/codewire/internal/terminal"
)

// namePattern validates session names: alphanumeric + hyphens, 1-32 chars.
var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,31}$`)

// ---------------------------------------------------------------------------
// Broadcaster — replaces tokio::sync::broadcast
// ---------------------------------------------------------------------------

// Broadcaster fans out byte slices to multiple subscribers. Slow consumers
// are dropped (non-blocking send) to avoid back-pressure on the PTY reader.
type Broadcaster struct {
	mu        sync.RWMutex
	listeners map[uint64]chan []byte
	nextID    uint64
}

// NewBroadcaster creates a ready-to-use Broadcaster.
func NewBroadcaster() *Broadcaster {
	return &Broadcaster{
		listeners: make(map[uint64]chan []byte),
	}
}

// Subscribe registers a new listener. Returns (id, channel). bufSize controls
// the channel buffer depth.
func (b *Broadcaster) Subscribe(bufSize int) (uint64, <-chan []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.nextID
	b.nextID++
	ch := make(chan []byte, bufSize)
	b.listeners[id] = ch
	return id, ch
}

// Unsubscribe removes and closes a listener by ID.
func (b *Broadcaster) Unsubscribe(id uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ch, ok := b.listeners[id]; ok {
		close(ch)
		delete(b.listeners, id)
	}
}

// Send broadcasts data to every listener. Non-blocking: if a listener's
// channel is full the message is silently dropped for that consumer.
func (b *Broadcaster) Send(data []byte) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.listeners {
		select {
		case ch <- data:
		default: // drop for slow consumers
		}
	}
}

// ---------------------------------------------------------------------------
// StatusWatcher — replaces tokio::sync::watch
// ---------------------------------------------------------------------------

// StatusWatcher holds a SessionStatus and notifies waiters on change.
type StatusWatcher struct {
	mu     sync.Mutex
	status SessionStatus
	waitCh chan struct{} // closed on change, then replaced
}

// NewStatusWatcher creates a watcher with the given initial status.
func NewStatusWatcher(initial SessionStatus) *StatusWatcher {
	return &StatusWatcher{
		status: initial,
		waitCh: make(chan struct{}),
	}
}

// Set updates the status and wakes all current waiters.
func (w *StatusWatcher) Set(s SessionStatus) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status = s
	close(w.waitCh)
	w.waitCh = make(chan struct{})
}

// Get returns the current status.
func (w *StatusWatcher) Get() SessionStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

// Changed returns a channel that is closed when the status next changes.
// After the channel fires, call Changed again for subsequent notifications.
func (w *StatusWatcher) Changed() <-chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.waitCh
}

// ---------------------------------------------------------------------------
// SessionStatus
// ---------------------------------------------------------------------------

// SessionStatus represents the lifecycle state of a session.
type SessionStatus struct {
	State    string // "running", "completed", "killed"
	ExitCode int    // only meaningful when State == "completed"
}

// String returns a human-readable representation matching the Rust Display impl.
func (s SessionStatus) String() string {
	switch s.State {
	case "completed":
		return fmt.Sprintf("completed (%d)", s.ExitCode)
	case "killed":
		return "killed"
	default:
		return "running"
	}
}

// StatusRunning returns the running status.
func StatusRunning() SessionStatus { return SessionStatus{State: "running"} }

// StatusCompleted returns a completed status with the given exit code.
func StatusCompleted(code int) SessionStatus {
	return SessionStatus{State: "completed", ExitCode: code}
}

// StatusKilled returns the killed status.
func StatusKilled() SessionStatus { return SessionStatus{State: "killed"} }

// ---------------------------------------------------------------------------
// SessionMeta — persisted to sessions.json
// ---------------------------------------------------------------------------

// SessionMeta holds the serialisable metadata for a session. It is written to
// dataDir/sessions.json so that session IDs survive restarts.
type SessionMeta struct {
	ID          uint32     `json:"id"`
	Name        string     `json:"name,omitempty"`
	Prompt      string     `json:"prompt"`
	WorkingDir  string     `json:"working_dir"`
	CreatedAt   time.Time  `json:"created_at"`
	Status      string     `json:"status"`
	PID         *uint32    `json:"pid,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	ExitCode    *int       `json:"exit_code,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Result      *string    `json:"result,omitempty"`
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

// Session represents a live PTY session with its communication channels.
type Session struct {
	Meta          SessionMeta
	master        *os.File // PTY master fd (from creack/pty)
	attachedCount atomic.Int32
	broadcaster   *Broadcaster
	inputCh       chan []byte // buffered channel for PTY input writes
	statusWatcher *StatusWatcher
	logPath       string
	mu            sync.Mutex // protects Meta.Status updates

	// Enriched tracking (new).
	outputBytes  atomic.Uint64
	outputLines  atomic.Uint64
	lastOutputAt atomic.Int64 // unix nano
	eventLog     *EventLog
	messageLog   *EventLog // JSONL at sessions/{id}/messages.jsonl
	exitHookSent bool
}

// ---------------------------------------------------------------------------
// AttachChannels
// ---------------------------------------------------------------------------

// AttachChannels groups the channels returned by SessionManager.Attach.
type AttachChannels struct {
	OutputCh <-chan []byte
	OutputID uint64 // for Broadcaster.Unsubscribe
	InputCh  chan<- []byte
	Status   *StatusWatcher
}

// ---------------------------------------------------------------------------
// SessionManager
// ---------------------------------------------------------------------------

// SessionManager owns all live sessions and persists their metadata to disk.
type SessionManager struct {
	mu            sync.RWMutex
	sessions      map[uint32]*Session
	nameIndex     map[string]uint32 // name → session ID (guarded by mu)
	nextID        atomic.Uint32
	dataDir       string
	PersistCh     chan struct{} // exported: the node package drains this to trigger writes
	Subscriptions *SubscriptionManager

	pendingRequestsMu sync.Mutex
	pendingRequests   map[string]pendingRequest // requestID → pending request state
	nameChangeHook    func(id uint32, oldName, newName string, tags []string) error
	sessionExitHook   func(id uint32, name string, tags []string)
	taskReportForward func(sessionID uint32, sessionName, eventID, summary, state string, ts time.Time)
}

const maxTaskSummaryLen = 280

type pendingRequest struct {
	replyCh                   chan ReplyData
	replyToken                string
	allowedReplierSessionID   uint32
	allowedReplierSessionName string
}

// NewSessionManager creates a SessionManager rooted at dataDir. It reads
// sessions.json (if present) to restore the next session ID counter. If the
// file is corrupt it is backed up and an empty session list is used.
func NewSessionManager(dataDir string) (*SessionManager, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating data dir: %w", err)
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("hardening data dir permissions: %w", err)
	}

	var startID uint32 = 1

	metaPath := filepath.Join(dataDir, "sessions.json")
	data, err := os.ReadFile(metaPath)
	if err == nil {
		var metas []SessionMeta
		if jsonErr := json.Unmarshal(data, &metas); jsonErr != nil {
			// Backup corrupt file
			ts := time.Now().UTC().Format("20060102_150405")
			backupPath := metaPath + ".corrupt." + ts
			if cpErr := copyFile(metaPath, backupPath); cpErr != nil {
				slog.Error("failed to backup corrupt sessions.json", "err", cpErr)
			} else {
				slog.Info("backed up corrupt sessions.json", "path", backupPath)
			}
			slog.Error("corrupt sessions.json — starting with empty session list", "err", jsonErr)
		} else {
			var maxID uint32
			for _, m := range metas {
				if m.ID > maxID {
					maxID = m.ID
				}
			}
			startID = maxID + 1
		}
	}
	// If the file does not exist we silently start from ID 1.

	sm := &SessionManager{
		sessions:        make(map[uint32]*Session),
		nameIndex:       make(map[string]uint32),
		dataDir:         dataDir,
		PersistCh:       make(chan struct{}, 1),
		Subscriptions:   NewSubscriptionManager(),
		pendingRequests: make(map[string]pendingRequest),
	}
	sm.nextID.Store(startID)
	return sm, nil
}

// SetNameChangeHook registers a callback invoked before a session name change is committed.
func (m *SessionManager) SetNameChangeHook(hook func(id uint32, oldName, newName string, tags []string) error) {
	m.nameChangeHook = hook
}

// SetSessionExitHook registers a callback invoked after a session exits or is killed.
func (m *SessionManager) SetSessionExitHook(hook func(id uint32, name string, tags []string)) {
	m.sessionExitHook = hook
}

// SetTaskReportForward registers a callback invoked after a task report has
// been recorded locally and published to subscribers.
func (m *SessionManager) SetTaskReportForward(hook func(sessionID uint32, sessionName, eventID, summary, state string, ts time.Time)) {
	m.taskReportForward = hook
}

// ReportTask records a task report event for one session, publishes it to
// local subscribers, and optionally forwards it to the relay transport.
func (m *SessionManager) ReportTask(sessionID uint32, summary, state string) error {
	m.mu.RLock()
	sess, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("session %d not found", sessionID)
	}

	normalizedSummary, err := normalizeTaskSummary(summary)
	if err != nil {
		return err
	}
	normalizedState, err := normalizeTaskState(state)
	if err != nil {
		return err
	}

	sess.mu.Lock()
	sessionName := sess.Meta.Name
	tags := append([]string(nil), sess.Meta.Tags...)
	sess.mu.Unlock()

	eventID := randomTaskEventID()
	event := NewTaskReportEvent(eventID, normalizedSummary, normalizedState)
	if sess.eventLog != nil {
		if err := sess.eventLog.Append(event); err != nil {
			return fmt.Errorf("append task report event: %w", err)
		}
	}
	m.Subscriptions.Publish(sessionID, tags, event)
	if m.taskReportForward != nil {
		m.taskReportForward(sessionID, sessionName, eventID, normalizedSummary, normalizedState, event.Timestamp)
	}
	return nil
}

// SetName assigns a unique name to a session. Returns an error if the name is
// invalid or already taken by another session.
func (m *SessionManager) SetName(id uint32, name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("invalid name %q: must be 1-32 alphanumeric characters or hyphens, starting with alphanumeric", name)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessions[id]
	if !ok {
		return fmt.Errorf("session %d not found", id)
	}

	if existing, taken := m.nameIndex[name]; taken && existing != id {
		return fmt.Errorf("name %q already in use by session %d", name, existing)
	}

	// Remove old name from index if renaming.
	sess.mu.Lock()
	oldName := sess.Meta.Name
	tags := append([]string(nil), sess.Meta.Tags...)
	if oldName != name && m.nameChangeHook != nil {
		if err := m.nameChangeHook(id, oldName, name, tags); err != nil {
			sess.mu.Unlock()
			return err
		}
	}
	sess.Meta.Name = name
	sess.mu.Unlock()

	if oldName != "" && oldName != name {
		delete(m.nameIndex, oldName)
	}
	m.nameIndex[name] = id
	m.triggerPersist()

	return nil
}

// releaseName removes a session's name from nameIndex if it owns it.
func (m *SessionManager) releaseName(id uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[id]
	if !ok {
		return
	}
	sess.mu.Lock()
	name := sess.Meta.Name
	sess.mu.Unlock()
	if name != "" {
		if existing, ok := m.nameIndex[name]; ok && existing == id {
			delete(m.nameIndex, name)
		}
	}
}

// ResolveByName looks up a session ID by name. Returns an error if no session
// has the given name.
func (m *SessionManager) ResolveByName(name string) (uint32, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	id, ok := m.nameIndex[name]
	if !ok {
		return 0, fmt.Errorf("no session named %q", name)
	}
	return id, nil
}

// GetName returns the name for a session, or empty string if unnamed.
func (m *SessionManager) GetName(id uint32) string {
	m.mu.RLock()
	sess, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return ""
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return sess.Meta.Name
}

// GroupNames returns the session's local group tags, normalized to group names.
func (m *SessionManager) GroupNames(id uint32) []string {
	m.mu.RLock()
	sess, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return nil
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	var groups []string
	for _, tag := range sess.Meta.Tags {
		tag = strings.TrimSpace(tag)
		if !strings.HasPrefix(tag, "group:") {
			continue
		}
		groupName := strings.TrimSpace(strings.TrimPrefix(tag, "group:"))
		if groupName == "" {
			continue
		}
		groups = append(groups, groupName)
	}
	return groups
}

// SendMessage sends a direct message from one session to another, recording it
// in both sessions' message logs and publishing it via the SubscriptionManager.
// fromID=0 is allowed (anonymous caller, e.g. CLI or gateway hook).
func (m *SessionManager) SendMessage(fromID, toID uint32, body string) (string, error) {
	return m.sendMessageWithMetadata(fromID, "", toID, body, true)
}

// SendRemoteMessage records a direct message from an authenticated remote sender.
func (m *SessionManager) SendRemoteMessage(fromName string, toID uint32, body string) (string, error) {
	return m.sendMessageWithMetadata(0, fromName, toID, body, false)
}

func (m *SessionManager) sendMessageWithMetadata(fromID uint32, fromNameOverride string, toID uint32, body string, mirrorSender bool) (string, error) {
	m.mu.RLock()
	fromSess, fromOK := m.sessions[fromID]
	toSess, toOK := m.sessions[toID]
	m.mu.RUnlock()

	if !fromOK && fromID != 0 {
		return "", fmt.Errorf("sender session %d not found", fromID)
	}
	if !toOK {
		return "", fmt.Errorf("recipient session %d not found", toID)
	}

	msgID := randomMessageID()

	var fromName string
	if fromNameOverride != "" {
		fromName = fromNameOverride
	} else if fromOK {
		fromSess.mu.Lock()
		fromName = fromSess.Meta.Name
		fromSess.mu.Unlock()
	}

	toSess.mu.Lock()
	toName := toSess.Meta.Name
	toSess.mu.Unlock()

	msgData := DirectMessageData{
		MessageID: msgID,
		From:      fromID,
		FromName:  fromName,
		To:        toID,
		ToName:    toName,
		Body:      body,
	}
	event := NewDirectMessageEvent(msgData)

	// Write to both sessions' message logs.
	if mirrorSender && fromOK && fromSess.messageLog != nil {
		fromSess.messageLog.Append(event)
	}
	if toSess.messageLog != nil {
		toSess.messageLog.Append(event)
	}

	// Publish to subscriptions (on the recipient's session ID).
	m.Subscriptions.Publish(toID, toSess.Meta.Tags, event)
	// Also publish on sender so listen can see sent messages.
	if mirrorSender && fromOK && fromID != toID {
		m.Subscriptions.Publish(fromID, fromSess.Meta.Tags, event)
	}

	return msgID, nil
}

// ReadMessages reads messages from a session's message log, returning the last
// `tail` events. If tail <= 0, all messages are returned.
func (m *SessionManager) ReadMessages(sessionID uint32, tail int) ([]Event, error) {
	m.mu.RLock()
	sess, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("session %d not found", sessionID)
	}
	if sess.messageLog == nil {
		return nil, nil
	}
	return sess.messageLog.ReadTail(tail)
}

// SendRequest sends a request from one session to another and returns a channel
// that will receive the reply. The caller should block on the channel with a timeout.
func (m *SessionManager) SendRequest(fromID, toID uint32, body string) (string, <-chan ReplyData, error) {
	return m.sendRequestWithMetadata(fromID, "", toID, body, true)
}

// SendRemoteRequest records a request from an authenticated remote sender.
func (m *SessionManager) SendRemoteRequest(fromName string, toID uint32, body string) (string, <-chan ReplyData, error) {
	return m.sendRequestWithMetadata(0, fromName, toID, body, false)
}

func (m *SessionManager) sendRequestWithMetadata(fromID uint32, fromNameOverride string, toID uint32, body string, mirrorSender bool) (string, <-chan ReplyData, error) {
	m.mu.RLock()
	fromSess, fromOK := m.sessions[fromID]
	toSess, toOK := m.sessions[toID]
	m.mu.RUnlock()

	// fromID=0 is allowed (anonymous caller, e.g. CLI or gateway hook).
	if !fromOK && fromID != 0 {
		return "", nil, fmt.Errorf("sender session %d not found", fromID)
	}
	if !toOK {
		return "", nil, fmt.Errorf("recipient session %d not found", toID)
	}

	requestID := randomRequestID()
	replyToken := randomReplyToken()

	var fromName string
	if fromNameOverride != "" {
		fromName = fromNameOverride
	} else if fromOK {
		fromSess.mu.Lock()
		fromName = fromSess.Meta.Name
		fromSess.mu.Unlock()
	}

	toSess.mu.Lock()
	toName := toSess.Meta.Name
	toSess.mu.Unlock()

	reqData := RequestData{
		RequestID:  requestID,
		ReplyToken: replyToken,
		From:       fromID,
		FromName:   fromName,
		To:         toID,
		ToName:     toName,
		Body:       body,
	}
	event := NewRequestEvent(reqData)

	// Write to recipient's message log and publish.
	if toSess.messageLog != nil {
		toSess.messageLog.Append(event)
	}
	m.Subscriptions.Publish(toID, toSess.Meta.Tags, event)
	// Also publish on sender (only if sender is a real session).
	if mirrorSender && fromOK && fromID != toID {
		if fromSess.messageLog != nil {
			fromSess.messageLog.Append(event)
		}
		m.Subscriptions.Publish(fromID, fromSess.Meta.Tags, event)
	}

	// Register reply channel and ownership.
	replyCh := make(chan ReplyData, 1)
	m.pendingRequestsMu.Lock()
	m.pendingRequests[requestID] = pendingRequest{
		replyCh:                   replyCh,
		replyToken:                replyToken,
		allowedReplierSessionID:   toID,
		allowedReplierSessionName: toName,
	}
	m.pendingRequestsMu.Unlock()

	return requestID, replyCh, nil
}

// SendReply sends a reply to a pending request. It looks up the reply channel,
// sends the reply, and records the reply event in both sessions' message logs.
func (m *SessionManager) SendReply(fromID uint32, requestID string, body string) error {
	return m.sendReplyWithMetadata(fromID, "", nil, requestID, "", body, true)
}

// SendRemoteReply sends a reply from an authenticated remote sender.
func (m *SessionManager) SendRemoteReply(fromName string, fromSessionID *uint32, requestID string, body string) error {
	return m.sendReplyWithMetadata(0, fromName, fromSessionID, requestID, "", body, false)
}

// SendReplyWithToken redeems a request-scoped reply token instead of trusting
// caller-supplied session identity on the wire.
func (m *SessionManager) SendReplyWithToken(requestID, replyToken, body string) error {
	return m.sendReplyWithMetadata(0, "", nil, requestID, replyToken, body, true)
}

func (m *SessionManager) sendReplyWithMetadata(fromID uint32, fromNameOverride string, fromSessionIDOverride *uint32, requestID, replyToken, body string, logSender bool) error {
	m.pendingRequestsMu.Lock()
	pending, ok := m.pendingRequests[requestID]
	m.pendingRequestsMu.Unlock()

	if !ok {
		return fmt.Errorf("no pending request with ID %q", requestID)
	}

	effectiveFromID := fromID
	if fromSessionIDOverride != nil {
		effectiveFromID = *fromSessionIDOverride
	}
	if replyToken != "" {
		if replyToken != pending.replyToken {
			return fmt.Errorf("invalid reply token for request %q", requestID)
		}
	}
	// Request-scoped reply tokens are the explicit capability for callers that
	// do not otherwise have an authenticated session identity on the wire.
	if effectiveFromID == 0 && fromNameOverride == "" && fromSessionIDOverride == nil && replyToken != "" {
		effectiveFromID = pending.allowedReplierSessionID
	}
	if effectiveFromID == 0 || effectiveFromID != pending.allowedReplierSessionID {
		return fmt.Errorf("request %q may only be replied to by session %d", requestID, pending.allowedReplierSessionID)
	}

	m.pendingRequestsMu.Lock()
	current, ok := m.pendingRequests[requestID]
	if !ok {
		m.pendingRequestsMu.Unlock()
		return fmt.Errorf("no pending request with ID %q", requestID)
	}
	delete(m.pendingRequests, requestID)
	m.pendingRequestsMu.Unlock()
	pending = current

	m.mu.RLock()
	fromSess, fromOK := m.sessions[effectiveFromID]
	m.mu.RUnlock()

	var fromName string
	if fromNameOverride != "" {
		fromName = fromNameOverride
	} else if fromOK {
		fromSess.mu.Lock()
		fromName = fromSess.Meta.Name
		fromSess.mu.Unlock()
	}

	replyData := ReplyData{
		RequestID: requestID,
		From:      effectiveFromID,
		FromName:  fromName,
		Body:      body,
	}
	event := NewReplyEvent(replyData)

	// Write to sender's message log.
	if logSender && fromOK && fromSess.messageLog != nil {
		fromSess.messageLog.Append(event)
	}
	if logSender && effectiveFromID != 0 {
		m.Subscriptions.Publish(effectiveFromID, nil, event)
	}

	// Send to the reply channel (non-blocking in case caller timed out).
	select {
	case pending.replyCh <- replyData:
	default:
	}

	return nil
}

// CleanupRequest removes a pending request entry (called on timeout).
func (m *SessionManager) CleanupRequest(requestID string) {
	m.pendingRequestsMu.Lock()
	delete(m.pendingRequests, requestID)
	m.pendingRequestsMu.Unlock()
}

// FormatDirectMessagePrompt formats a PTY-injectable prompt for a direct
// message. The body is emitted inside bracketed-paste markers and submitted
// with a carriage return so TUIs (codex, claude, etc.) treat it as one paste
// event rather than typed-then-submitted lines.
//
// We do NOT prepend a "[Codewire message from <sender>]" header for PTY
// delivery: codex's TUI panics on bracket-prefixed multi-line content
// (panic in tui/src/wrapping.rs:52, byte index near u64::MAX). The session
// identifier is preserved through other channels (inbox listing, log file,
// notifications); the PTY path delivers only the message body.
//
// Without bracketed-paste, embedded newlines in the body would pre-submit
// each line as its own prompt. Bracketed-paste-aware TUIs buffer the entire
// content, then the trailing CR submits the buffered paste as one input.
func FormatDirectMessagePrompt(fromName string, fromID uint32, body string) string {
	_ = fromName
	_ = fromID
	return "\x1b[200~" + body + "\x1b[201~\r"
}

// FormatRequestPrompt formats a PTY-injectable prompt for a request message.
// Uses bracketed-paste markers and omits the bracketed header for the same
// reason as FormatDirectMessagePrompt. The reply hint is appended inside the
// paste so the receiving session sees how to respond.
func FormatRequestPrompt(requestID string, fromName string, fromID uint32, body string) string {
	_ = fromName
	_ = fromID
	footer := fmt.Sprintf("\n\nReply with: cw reply %s <response>", requestID)
	return "\x1b[200~" + body + footer + "\x1b[201~\r"
}

func randomMessageID() string {
	return randomOpaqueID("msg_")
}

func randomRequestID() string {
	return randomOpaqueID("req_")
}

func randomReplyToken() string {
	return randomOpaqueID("rpl_")
}

func randomTaskEventID() string {
	return randomOpaqueID("task_")
}

func randomOpaqueID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b[:])
}

func normalizeTaskSummary(summary string) (string, error) {
	summary = strings.Join(strings.Fields(strings.TrimSpace(summary)), " ")
	if summary == "" {
		return "", fmt.Errorf("task summary is required")
	}
	if len(summary) > maxTaskSummaryLen {
		return "", fmt.Errorf("task summary exceeds %d characters", maxTaskSummaryLen)
	}
	return summary, nil
}

func normalizeTaskState(state string) (string, error) {
	state = strings.TrimSpace(strings.ToLower(state))
	switch state {
	case "working", "complete", "blocked", "failed":
		return state, nil
	default:
		return "", fmt.Errorf("invalid task state %q", state)
	}
}

// DeliverDirectMessagePrompt injects a formatted direct-message prompt into a
// session's PTY via SendInput.
func (m *SessionManager) DeliverDirectMessagePrompt(toID uint32, fromName string, fromID uint32, body string) error {
	prompt := FormatDirectMessagePrompt(fromName, fromID, body)
	_, err := m.SendInput(toID, []byte(prompt))
	return err
}

// DeliverRequestPrompt injects a formatted request prompt into a session's PTY
// via SendInput.
func (m *SessionManager) DeliverRequestPrompt(toID uint32, requestID string, fromName string, fromID uint32, body string) error {
	prompt := FormatRequestPrompt(requestID, fromName, fromID, body)
	_, err := m.SendInput(toID, []byte(prompt))
	return err
}

// triggerPersist sends a non-blocking signal on PersistCh.
func (m *SessionManager) triggerPersist() {
	select {
	case m.PersistCh <- struct{}{}:
	default:
	}
}

// Launch starts a new PTY session executing command in workingDir.
// name is the session name (used for env injection; naming is done by the caller).
// tags are optional labels for filtering/grouping.
func (m *SessionManager) Launch(command []string, workingDir string, env []string, stdinData []byte, name string, tags ...string) (uint32, error) {
	if len(command) == 0 {
		return 0, fmt.Errorf("command must not be empty")
	}

	// Validate command binary.
	cmdName := command[0]
	if filepath.IsAbs(cmdName) {
		if _, err := os.Stat(cmdName); err != nil {
			return 0, fmt.Errorf("command %q does not exist", cmdName)
		}
	} else {
		if _, err := exec.LookPath(cmdName); err != nil {
			return 0, fmt.Errorf("command %q not found in PATH", cmdName)
		}
	}

	// Validate working directory.
	info, err := os.Stat(workingDir)
	if err != nil {
		return 0, fmt.Errorf("working directory %q does not exist", workingDir)
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("working directory %q is not a directory", workingDir)
	}

	// Allocate ID (starts at 1).
	id := m.nextID.Add(1) - 1

	// Ensure log directory.
	logDir := filepath.Join(m.dataDir, "sessions", fmt.Sprintf("%d", id))
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return 0, fmt.Errorf("creating log dir: %w", err)
	}
	logPath := filepath.Join(logDir, "output.log")

	// Build exec.Cmd.
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Dir = workingDir
	extraEnv := []string{fmt.Sprintf("CW_SESSION_ID=%d", id)}
	if name != "" {
		extraEnv = append(extraEnv, "CW_SESSION_NAME="+name)
	}
	if len(tags) > 0 {
		extraEnv = append(extraEnv, "CW_COHORT_TAG="+tags[0])
	}
	cmd.Env = buildEnv(append(env, extraEnv...))

	// Start with a PTY.
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return 0, fmt.Errorf("opening PTY: %w", err)
	}

	// Process ID.
	var pid *uint32
	if cmd.Process != nil {
		p := uint32(cmd.Process.Pid)
		pid = &p
	}

	displayCommand := strings.Join(command, " ")

	broadcaster := NewBroadcaster()
	inputCh := make(chan []byte, 256)
	statusWatcher := NewStatusWatcher(StatusRunning())

	// Open event log.
	eventsPath := filepath.Join(logDir, "events.jsonl")
	eventLog, evErr := NewEventLog(eventsPath)
	if evErr != nil {
		slog.Error("failed to open event log", "id", id, "err", evErr)
	}

	// Open message log.
	messagesPath := filepath.Join(logDir, "messages.jsonl")
	messageLog, msgErr := NewEventLog(messagesPath)
	if msgErr != nil {
		slog.Error("failed to open message log", "id", id, "err", msgErr)
	}

	if tags == nil {
		tags = []string{}
	}

	sess := &Session{
		Meta: SessionMeta{
			ID:         id,
			Prompt:     displayCommand,
			WorkingDir: workingDir,
			CreatedAt:  time.Now().UTC(),
			Status:     StatusRunning().String(),
			PID:        pid,
			Tags:       tags,
		},
		master:        ptmx,
		broadcaster:   broadcaster,
		inputCh:       inputCh,
		statusWatcher: statusWatcher,
		logPath:       logPath,
		eventLog:      eventLog,
		messageLog:    messageLog,
	}

	m.mu.Lock()
	m.sessions[id] = sess
	m.mu.Unlock()

	// Emit session.created event.
	createdEvent := NewSessionCreatedEvent(command, workingDir, tags)
	if eventLog != nil {
		eventLog.Append(createdEvent)
	}
	m.Subscriptions.Publish(id, tags, createdEvent)

	// Open log file.
	logFile, logErr := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if logErr != nil {
		slog.Error("failed to open session log file", "id", id, "path", logPath, "err", logErr)
	}

	// Auto-respond to terminal capability queries (cursor position, device
	// attributes, OSC color queries) that TUIs emit at startup. Without a
	// real terminal emulator behind the PTY, the child would hang waiting
	// for replies. The responder is opt-out via CW_NO_TTY_QUERIES=1.
	var queryResponder *termutil.QueryAutoResponder
	if os.Getenv("CW_NO_TTY_QUERIES") != "1" {
		queryResponder = termutil.NewQueryAutoResponder()
	}

	// Goroutine 1: PTY reader → log file + broadcast + output tracking.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, readErr := ptmx.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				if queryResponder != nil {
					if resp := queryResponder.Feed(data); len(resp) > 0 {
						if _, wErr := ptmx.Write(resp); wErr != nil {
							slog.Error("PTY auto-respond write error", "id", id, "err", wErr)
						}
					}
				}
				if logFile != nil {
					if _, wErr := logFile.Write(data); wErr != nil {
						slog.Error("log write error", "id", id, "err", wErr)
					}
				}
				broadcaster.Send(data)

				// Track output stats.
				sess.outputBytes.Add(uint64(n))
				for _, b := range data {
					if b == '\n' {
						sess.outputLines.Add(1)
					}
				}
				sess.lastOutputAt.Store(time.Now().UTC().UnixNano())
			}
			if readErr != nil {
				if readErr == io.EOF || isEIO(readErr) {
					break
				}
				slog.Error("PTY read error", "id", id, "err", readErr)
				break
			}
		}
		if logFile != nil {
			logFile.Close()
		}
		if eventLog != nil {
			eventLog.Close()
		}
		slog.Info("output reader exited", "id", id)
	}()

	// Goroutine 2: input channel → PTY writer.
	go func() {
		for data := range inputCh {
			if _, wErr := ptmx.Write(data); wErr != nil {
				slog.Error("PTY write error", "id", id, "err", wErr)
				break
			}
		}
		slog.Info("input writer exited", "id", id)
	}()

	// Inject stdinData into the session after a short delay.
	if len(stdinData) > 0 {
		go func() {
			time.Sleep(200 * time.Millisecond)
			chunk := make([]byte, len(stdinData))
			copy(chunk, stdinData)
			select {
			case inputCh <- chunk:
			default:
				slog.Warn("input channel full when injecting stdin_data", "id", id)
			}
		}()
	}

	// Goroutine 3: wait for process exit → update status + emit events.
	go func() {
		var exitCode int
		waitErr := cmd.Wait()
		if waitErr != nil {
			var exitErr *exec.ExitError
			if errors.As(waitErr, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
			}
		}
		slog.Info("session process exited", "id", id, "code", exitCode)

		now := time.Now().UTC()
		durationMs := now.Sub(sess.Meta.CreatedAt).Milliseconds()

		sess.mu.Lock()
		sess.Meta.ExitCode = &exitCode
		sess.Meta.CompletedAt = &now
		sess.mu.Unlock()

		// Capture result from output log before status change.
		result := captureResult(sess.logPath, 200)
		sess.mu.Lock()
		sess.Meta.Result = result
		sess.mu.Unlock()

		statusWatcher.Set(StatusCompleted(exitCode))

		// Emit session.status event.
		statusEvent := NewSessionStatusEvent("running", "completed", &exitCode, &durationMs)
		if sess.eventLog != nil {
			sess.eventLog.Append(statusEvent)
		}
		m.Subscriptions.Publish(id, tags, statusEvent)

		sess.mu.Lock()
		name := sess.Meta.Name
		sendExitHook := !sess.exitHookSent
		sess.exitHookSent = true
		sess.mu.Unlock()
		m.releaseName(id)
		m.triggerPersist()
		if sendExitHook && m.sessionExitHook != nil {
			m.sessionExitHook(id, name, append([]string(nil), tags...))
		}
	}()

	slog.Info("session launched", "id", id)
	m.triggerPersist()
	return id, nil
}

// List returns a SessionInfo slice for every known session, sorted by ID.
func (m *SessionManager) List() []protocol.SessionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	infos := make([]protocol.SessionInfo, 0, len(m.sessions))
	for _, s := range m.sessions {
		infos = append(infos, m.buildSessionInfo(s))
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].ID < infos[j].ID })
	return infos
}

// Attach returns the channels needed to interact with a running session.
func (m *SessionManager) Attach(id uint32) (*AttachChannels, error) {
	m.mu.RLock()
	sess, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("session %d not found", id)
	}

	if sess.statusWatcher.Get().State != "running" {
		return nil, fmt.Errorf("session %d is not running", id)
	}

	sess.attachedCount.Add(1)
	subID, ch := sess.broadcaster.Subscribe(4096)

	return &AttachChannels{
		OutputCh: ch,
		OutputID: subID,
		InputCh:  sess.inputCh,
		Status:   sess.statusWatcher,
	}, nil
}

// Detach decrements the attached client count for a session.
func (m *SessionManager) Detach(id uint32) error {
	m.mu.RLock()
	sess, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("session %d not found", id)
	}
	sess.attachedCount.Add(-1)
	return nil
}

// Resize changes the PTY window size for a session.
func (m *SessionManager) Resize(id uint32, cols, rows uint16) error {
	m.mu.RLock()
	sess, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("session %d not found", id)
	}
	return pty.Setsize(sess.master, &pty.Winsize{Rows: rows, Cols: cols})
}

// Kill sends SIGTERM to the session's process and marks it killed.
func (m *SessionManager) Kill(id uint32) error {
	m.mu.RLock()
	sess, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("session %d not found", id)
	}

	sess.statusWatcher.Set(StatusKilled())

	if sess.Meta.PID != nil {
		_ = syscall.Kill(int(*sess.Meta.PID), syscall.SIGTERM)
	}

	sess.mu.Lock()
	sess.Meta.Status = StatusKilled().String()
	name := sess.Meta.Name
	tags := append([]string(nil), sess.Meta.Tags...)
	sendExitHook := !sess.exitHookSent
	sess.exitHookSent = true
	sess.mu.Unlock()

	m.triggerPersist()
	m.releaseName(id)
	if sendExitHook && m.sessionExitHook != nil {
		m.sessionExitHook(id, name, tags)
	}
	return nil
}

// KillAll kills every running session and returns the count killed.
func (m *SessionManager) KillAll() int {
	m.mu.RLock()
	ids := make([]uint32, 0)
	for id, s := range m.sessions {
		if s.statusWatcher.Get().State == "running" {
			ids = append(ids, id)
		}
	}
	m.mu.RUnlock()

	for _, id := range ids {
		_ = m.Kill(id)
	}
	return len(ids)
}

// LogPath returns the path to a session's output log file.
func (m *SessionManager) LogPath(id uint32) (string, error) {
	m.mu.RLock()
	_, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("session %d not found", id)
	}
	return filepath.Join(m.dataDir, "sessions", fmt.Sprintf("%d", id), "output.log"), nil
}

// SendInput writes data to a session's PTY. It is non-blocking: if the input
// channel is full the send fails with an error.
func (m *SessionManager) SendInput(id uint32, data []byte) (int, error) {
	m.mu.RLock()
	sess, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return 0, fmt.Errorf("session %d not found", id)
	}

	select {
	case sess.inputCh <- data:
		return len(data), nil
	default:
		return 0, fmt.Errorf("input channel full for session %d", id)
	}
}

// GetStatus returns detailed status information for a session, including log
// file size and the last few lines of output.
func (m *SessionManager) GetStatus(id uint32) (protocol.SessionInfo, uint64, error) {
	m.mu.RLock()
	sess, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return protocol.SessionInfo{}, 0, fmt.Errorf("session %d not found", id)
	}

	info := m.buildSessionInfo(sess)

	// Add snippet for GetStatus specifically.
	if content, err := os.ReadFile(sess.logPath); err == nil {
		lines := strings.Split(string(content), "\n")
		start := len(lines) - 5
		if start < 0 {
			start = 0
		}
		tail := lines[start:]
		joined := termutil.StripANSI(strings.Join(tail, "\n"))
		if joined != "" {
			info.LastOutputSnippet = &joined
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		slog.Warn("failed to read log file for snippet", "id", id, "err", err)
	}

	var outputSize uint64
	if info.OutputBytes != nil {
		outputSize = *info.OutputBytes
	}

	return info, outputSize, nil
}

// SubscribeOutput returns a broadcast subscription for a session's PTY output.
func (m *SessionManager) SubscribeOutput(id uint32) (uint64, <-chan []byte, error) {
	m.mu.RLock()
	sess, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return 0, nil, fmt.Errorf("session %d not found", id)
	}
	subID, ch := sess.broadcaster.Subscribe(4096)
	return subID, ch, nil
}

// UnsubscribeOutput removes a broadcast subscription for a session.
func (m *SessionManager) UnsubscribeOutput(id uint32, subID uint64) {
	m.mu.RLock()
	sess, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return
	}
	sess.broadcaster.Unsubscribe(subID)
}

// SubscribeStatus returns the StatusWatcher for a session.
func (m *SessionManager) SubscribeStatus(id uint32) (*StatusWatcher, error) {
	m.mu.RLock()
	sess, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("session %d not found", id)
	}
	return sess.statusWatcher, nil
}

// RefreshStatuses synchronises each session's Meta.Status with its
// StatusWatcher and triggers persistence if anything changed.
func (m *SessionManager) RefreshStatuses() {
	changed := false

	m.mu.RLock()
	for _, sess := range m.sessions {
		current := sess.statusWatcher.Get().String()
		sess.mu.Lock()
		if sess.Meta.Status != current {
			sess.Meta.Status = current
			changed = true
		}
		sess.mu.Unlock()
	}
	m.mu.RUnlock()

	if changed {
		m.triggerPersist()
	}
}

// PersistMeta writes all session metadata to dataDir/sessions.json.
func (m *SessionManager) PersistMeta() {
	m.mu.RLock()
	metas := make([]SessionMeta, 0, len(m.sessions))
	for _, sess := range m.sessions {
		sess.mu.Lock()
		metas = append(metas, sess.Meta)
		sess.mu.Unlock()
	}
	m.mu.RUnlock()

	path := filepath.Join(m.dataDir, "sessions.json")
	data, err := json.MarshalIndent(metas, "", "  ")
	if err != nil {
		slog.Error("failed to serialise session metadata", "err", err)
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		slog.Error("failed to persist session metadata", "path", path, "err", err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildSessionInfo constructs a fully enriched SessionInfo from a live Session.
func (m *SessionManager) buildSessionInfo(s *Session) protocol.SessionInfo {
	status := s.statusWatcher.Get()
	attached := s.attachedCount.Load() > 0
	attachedCount := s.attachedCount.Load()

	outputBytes := s.outputBytes.Load()
	outputLines := s.outputLines.Load()

	info := protocol.SessionInfo{
		ID:            s.Meta.ID,
		Name:          s.Meta.Name,
		Prompt:        s.Meta.Prompt,
		WorkingDir:    s.Meta.WorkingDir,
		CreatedAt:     s.Meta.CreatedAt.Format(time.RFC3339),
		Status:        status.String(),
		Attached:      attached,
		PID:           s.Meta.PID,
		Tags:          s.Meta.Tags,
		OutputBytes:   &outputBytes,
		OutputLines:   &outputLines,
		AttachedCount: attachedCount,
	}

	// File-based output size.
	if fi, err := os.Stat(s.logPath); err == nil {
		sz := uint64(fi.Size())
		info.OutputSizeBytes = &sz
	}

	// Exit code, completion info, and captured result.
	s.mu.Lock()
	if s.Meta.ExitCode != nil {
		info.ExitCode = s.Meta.ExitCode
	}
	if s.Meta.CompletedAt != nil {
		completedStr := s.Meta.CompletedAt.Format(time.RFC3339)
		info.CompletedAt = &completedStr
		durationMs := s.Meta.CompletedAt.Sub(s.Meta.CreatedAt).Milliseconds()
		info.DurationMs = &durationMs
	}
	if s.Meta.Result != nil {
		info.LastOutputSnippet = s.Meta.Result
	}
	s.mu.Unlock()

	// Last output timestamp.
	if lastNano := s.lastOutputAt.Load(); lastNano > 0 {
		lastStr := time.Unix(0, lastNano).UTC().Format(time.RFC3339)
		info.LastOutputAt = &lastStr
	}

	return info
}

// GetSessionTags returns the tags for a session (used by handler for event filtering).
func (m *SessionManager) GetSessionTags(id uint32) []string {
	m.mu.RLock()
	sess, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return nil
	}
	return sess.Meta.Tags
}

// ListByTags returns sessions matching any of the given tags.
func (m *SessionManager) ListByTags(tags []string) []protocol.SessionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var infos []protocol.SessionInfo
	for _, s := range m.sessions {
		if matchesTags(s.Meta.Tags, tags) {
			infos = append(infos, m.buildSessionInfo(s))
		}
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].ID < infos[j].ID })
	return infos
}

func matchesTags(sessionTags, filterTags []string) bool {
	for _, ft := range filterTags {
		for _, st := range sessionTags {
			if ft == st {
				return true
			}
		}
	}
	return false
}

// KillByTags kills all running sessions matching any of the given tags.
func (m *SessionManager) KillByTags(tags []string) int {
	m.mu.RLock()
	var ids []uint32
	for id, s := range m.sessions {
		if s.statusWatcher.Get().State == "running" && matchesTags(s.Meta.Tags, tags) {
			ids = append(ids, id)
		}
	}
	m.mu.RUnlock()

	for _, id := range ids {
		m.Kill(id)
	}
	return len(ids)
}

// buildEnv constructs child env from os.Environ() with Claude Code vars stripped
// and optional KEY=VALUE overrides applied.
func buildEnv(overrides []string) []string {
	base := os.Environ()
	filtered := make([]string, 0, len(base))
	for _, e := range base {
		if !strings.HasPrefix(e, "CLAUDECODE=") && !strings.HasPrefix(e, "CLAUDE_CODE_ENTRYPOINT=") {
			filtered = append(filtered, e)
		}
	}
	filtered = applyDefaultTerminalEnv(filtered)
	filtered = applyEnvOverrides(filtered, loadCodewireEnvOverrides())
	return applyEnvOverrides(filtered, overrides)
}

func applyDefaultTerminalEnv(base []string) []string {
	overrides := make([]string, 0, 2)

	term, ok := envValue(base, "TERM")
	if !ok || strings.TrimSpace(term) == "" || term == "dumb" {
		overrides = append(overrides, "TERM=xterm-256color")
	}

	colorTerm, ok := envValue(base, "COLORTERM")
	if !ok || strings.TrimSpace(colorTerm) == "" {
		overrides = append(overrides, "COLORTERM=truecolor")
	}

	return applyEnvOverrides(base, overrides)
}

func envValue(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return entry[len(prefix):], true
		}
	}
	return "", false
}

func loadCodewireEnvOverrides() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	path := filepath.Join(home, ".codewire", "environment.json")
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}
	var envVars map[string]string
	if err := json.Unmarshal(data, &envVars); err != nil {
		return nil
	}
	if len(envVars) == 0 {
		return nil
	}
	keys := make([]string, 0, len(envVars))
	for key := range envVars {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	overrides := make([]string, 0, len(keys))
	for _, key := range keys {
		overrides = append(overrides, key+"="+envVars[key])
	}
	return overrides
}

func applyEnvOverrides(base, overrides []string) []string {
	if len(overrides) == 0 {
		return base
	}
	keyIdx := make(map[string]int, len(base))
	for i, e := range base {
		if eq := strings.IndexByte(e, '='); eq >= 0 {
			keyIdx[e[:eq]] = i
		}
	}
	result := make([]string, len(base))
	copy(result, base)
	for _, ov := range overrides {
		eq := strings.IndexByte(ov, '=')
		if eq < 0 {
			continue
		}
		key := ov[:eq]
		if idx, exists := keyIdx[key]; exists {
			result[idx] = ov
		} else {
			result = append(result, ov)
			keyIdx[key] = len(result) - 1
		}
	}
	return result
}

// captureResult reads the tail of a log file, strips ANSI codes, and returns
// the last maxLines lines. It reads from the end of the file to avoid loading
// the entire file into memory.
func captureResult(logPath string, maxLines int) *string {
	f, err := os.Open(logPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return nil
	}

	// Read up to 64KB from the end — enough for 200 lines.
	readSize := int64(64 * 1024)
	if fi.Size() < readSize {
		readSize = fi.Size()
	}

	buf := make([]byte, readSize)
	_, err = f.ReadAt(buf, fi.Size()-readSize)
	if err != nil && err != io.EOF {
		return nil
	}

	// Strip ANSI escape codes.
	clean := termutil.StripANSI(string(buf))

	// Take last N lines.
	lines := strings.Split(clean, "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}

	// Trim trailing empty lines.
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}

	if len(lines) == 0 {
		return nil
	}

	result := strings.Join(lines, "\n")
	return &result
}

// isEIO returns true if err is an EIO (errno 5) wrapped in an *os.PathError.
func isEIO(err error) bool {
	var pe *os.PathError
	if errors.As(err, &pe) {
		if errno, ok := pe.Err.(syscall.Errno); ok {
			return errno == syscall.EIO
		}
	}
	return false
}

// copyFile copies src to dst using simple read + write.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}
