package session

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// launchSleepSession is a helper that launches a "sleep 30" session and returns
// its ID. It calls t.Fatal on failure and registers a cleanup to kill the
// session when the test finishes.
func launchSleepSession(t *testing.T, sm *SessionManager) uint32 {
	t.Helper()
	id, err := sm.Launch([]string{"sleep", "30"}, "/tmp", nil, nil, "")
	if err != nil {
		t.Fatalf("failed to launch session: %v", err)
	}
	t.Cleanup(func() { _ = sm.Kill(id) })
	return id
}

func TestSendMessage(t *testing.T) {
	sm, err := NewSessionManager(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	sender := launchSleepSession(t, sm)
	recipient := launchSleepSession(t, sm)

	msgID, err := sm.SendMessage(sender, recipient, "hello from sender")
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}
	if msgID == "" {
		t.Fatal("expected non-empty message ID")
	}
	if !strings.HasPrefix(msgID, "msg_") {
		t.Fatalf("expected opaque msg_ id, got %q", msgID)
	}

	// Verify the message appears in the recipient's message log.
	events, err := sm.ReadMessages(recipient, 0)
	if err != nil {
		t.Fatalf("ReadMessages failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 message in recipient log, got %d", len(events))
	}
	if events[0].Type != EventDirectMessage {
		t.Fatalf("expected event type %s, got %s", EventDirectMessage, events[0].Type)
	}

	var dm DirectMessageData
	if err := json.Unmarshal(events[0].Data, &dm); err != nil {
		t.Fatalf("failed to unmarshal message data: %v", err)
	}
	if dm.Body != "hello from sender" {
		t.Fatalf("expected body %q, got %q", "hello from sender", dm.Body)
	}
	if dm.From != sender {
		t.Fatalf("expected From=%d, got %d", sender, dm.From)
	}
	if dm.To != recipient {
		t.Fatalf("expected To=%d, got %d", recipient, dm.To)
	}
}

func TestSendMessageBothLogs(t *testing.T) {
	sm, err := NewSessionManager(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	sender := launchSleepSession(t, sm)
	recipient := launchSleepSession(t, sm)

	_, err = sm.SendMessage(sender, recipient, "bidirectional check")
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	// Verify the message appears in the sender's log.
	senderEvents, err := sm.ReadMessages(sender, 0)
	if err != nil {
		t.Fatalf("ReadMessages (sender) failed: %v", err)
	}
	if len(senderEvents) != 1 {
		t.Fatalf("expected 1 message in sender log, got %d", len(senderEvents))
	}
	if senderEvents[0].Type != EventDirectMessage {
		t.Fatalf("expected event type %s in sender log, got %s", EventDirectMessage, senderEvents[0].Type)
	}

	// Verify the message appears in the recipient's log.
	recipientEvents, err := sm.ReadMessages(recipient, 0)
	if err != nil {
		t.Fatalf("ReadMessages (recipient) failed: %v", err)
	}
	if len(recipientEvents) != 1 {
		t.Fatalf("expected 1 message in recipient log, got %d", len(recipientEvents))
	}
	if recipientEvents[0].Type != EventDirectMessage {
		t.Fatalf("expected event type %s in recipient log, got %s", EventDirectMessage, recipientEvents[0].Type)
	}

	// Both logs should contain the same message body.
	var senderDM, recipientDM DirectMessageData
	if err := json.Unmarshal(senderEvents[0].Data, &senderDM); err != nil {
		t.Fatalf("failed to unmarshal sender message data: %v", err)
	}
	if err := json.Unmarshal(recipientEvents[0].Data, &recipientDM); err != nil {
		t.Fatalf("failed to unmarshal recipient message data: %v", err)
	}
	if senderDM.Body != "bidirectional check" {
		t.Fatalf("sender log body: expected %q, got %q", "bidirectional check", senderDM.Body)
	}
	if recipientDM.Body != "bidirectional check" {
		t.Fatalf("recipient log body: expected %q, got %q", "bidirectional check", recipientDM.Body)
	}
	if senderDM.MessageID != recipientDM.MessageID {
		t.Fatalf("message IDs differ: sender=%q, recipient=%q", senderDM.MessageID, recipientDM.MessageID)
	}
}

func TestReadMessagesTail(t *testing.T) {
	sm, err := NewSessionManager(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	sender := launchSleepSession(t, sm)
	recipient := launchSleepSession(t, sm)

	// Send 5 messages.
	for i := 0; i < 5; i++ {
		_, err := sm.SendMessage(sender, recipient, "msg-"+string(rune('A'+i)))
		if err != nil {
			t.Fatalf("SendMessage %d failed: %v", i, err)
		}
	}

	// Read all messages to confirm count.
	all, err := sm.ReadMessages(recipient, 0)
	if err != nil {
		t.Fatalf("ReadMessages (all) failed: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("expected 5 messages, got %d", len(all))
	}

	// Read with tail=2 — should return only the last 2.
	tail, err := sm.ReadMessages(recipient, 2)
	if err != nil {
		t.Fatalf("ReadMessages (tail=2) failed: %v", err)
	}
	if len(tail) != 2 {
		t.Fatalf("expected 2 messages with tail=2, got %d", len(tail))
	}

	// Verify the tail messages are the last two sent.
	var dm3, dm4 DirectMessageData
	if err := json.Unmarshal(tail[0].Data, &dm3); err != nil {
		t.Fatalf("failed to unmarshal tail[0]: %v", err)
	}
	if err := json.Unmarshal(tail[1].Data, &dm4); err != nil {
		t.Fatalf("failed to unmarshal tail[1]: %v", err)
	}
	if dm3.Body != "msg-D" {
		t.Fatalf("expected tail[0] body %q, got %q", "msg-D", dm3.Body)
	}
	if dm4.Body != "msg-E" {
		t.Fatalf("expected tail[1] body %q, got %q", "msg-E", dm4.Body)
	}
}

func TestRequestReply(t *testing.T) {
	sm, err := NewSessionManager(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	sender := launchSleepSession(t, sm)
	if err := sm.SetName(sender, "requester"); err != nil {
		t.Fatalf("SetName failed: %v", err)
	}

	recipient := launchSleepSession(t, sm)
	if err := sm.SetName(recipient, "responder"); err != nil {
		t.Fatalf("SetName failed: %v", err)
	}

	requestID, replyCh, err := sm.SendRequest(sender, recipient, "what is 2+2?")
	if err != nil {
		t.Fatalf("SendRequest failed: %v", err)
	}
	if requestID == "" {
		t.Fatal("expected non-empty request ID")
	}
	if !strings.HasPrefix(requestID, "req_") {
		t.Fatalf("expected opaque req_ id, got %q", requestID)
	}

	// Reply from recipient.
	if err := sm.SendReply(recipient, requestID, "4"); err != nil {
		t.Fatalf("SendReply failed: %v", err)
	}

	// Verify the reply is received on the channel.
	select {
	case reply := <-replyCh:
		if reply.RequestID != requestID {
			t.Fatalf("reply RequestID: expected %q, got %q", requestID, reply.RequestID)
		}
		if reply.From != recipient {
			t.Fatalf("reply From: expected %d, got %d", recipient, reply.From)
		}
		if reply.FromName != "responder" {
			t.Fatalf("reply FromName: expected %q, got %q", "responder", reply.FromName)
		}
		if reply.Body != "4" {
			t.Fatalf("reply Body: expected %q, got %q", "4", reply.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for reply on channel")
	}
}

func TestMessageAndRequestIDsAreOpaque(t *testing.T) {
	sm, err := NewSessionManager(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	sender := launchSleepSession(t, sm)
	recipient := launchSleepSession(t, sm)

	msgID1, err := sm.SendMessage(sender, recipient, "one")
	if err != nil {
		t.Fatalf("SendMessage 1 failed: %v", err)
	}
	msgID2, err := sm.SendMessage(sender, recipient, "two")
	if err != nil {
		t.Fatalf("SendMessage 2 failed: %v", err)
	}
	if msgID1 == msgID2 {
		t.Fatalf("message ids should differ: %q", msgID1)
	}
	if strings.Contains(msgID1, fmt.Sprintf("_%d_%d_", sender, recipient)) {
		t.Fatalf("message id looks topology-derived: %q", msgID1)
	}

	reqID1, _, err := sm.SendRequest(sender, recipient, "req one")
	if err != nil {
		t.Fatalf("SendRequest 1 failed: %v", err)
	}
	reqID2, _, err := sm.SendRequest(sender, recipient, "req two")
	if err != nil {
		t.Fatalf("SendRequest 2 failed: %v", err)
	}
	if reqID1 == reqID2 {
		t.Fatalf("request ids should differ: %q", reqID1)
	}
	if strings.Contains(reqID1, fmt.Sprintf("_%d_%d_", sender, recipient)) {
		t.Fatalf("request id looks topology-derived: %q", reqID1)
	}
}

func TestRequestTimeout(t *testing.T) {
	sm, err := NewSessionManager(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	sender := launchSleepSession(t, sm)
	recipient := launchSleepSession(t, sm)

	requestID, replyCh, err := sm.SendRequest(sender, recipient, "this will timeout")
	if err != nil {
		t.Fatalf("SendRequest failed: %v", err)
	}

	// Do not reply. Instead, clean up the pending request (simulating timeout).
	sm.CleanupRequest(requestID)

	// The reply channel should not receive anything.
	select {
	case reply, ok := <-replyCh:
		if ok {
			t.Fatalf("expected no reply after cleanup, got: %+v", reply)
		}
	default:
		// No reply received — correct behavior.
	}

	// Attempting to reply after cleanup should fail.
	err = sm.SendReply(recipient, requestID, "too late")
	if err == nil {
		t.Fatal("expected error when replying to cleaned-up request")
	}
}

func TestRequestReplyRejectedForWrongSession(t *testing.T) {
	sm, err := NewSessionManager(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	sender := launchSleepSession(t, sm)
	recipient := launchSleepSession(t, sm)
	other := launchSleepSession(t, sm)

	requestID, _, err := sm.SendRequest(sender, recipient, "who may answer?")
	if err != nil {
		t.Fatalf("SendRequest failed: %v", err)
	}

	err = sm.SendReply(other, requestID, "not me")
	if err == nil {
		t.Fatal("expected error when wrong session replies")
	}
	if !strings.Contains(err.Error(), "may only be replied to by session") {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := sm.SendReply(recipient, requestID, "me"); err != nil {
		t.Fatalf("SendReply from recipient failed: %v", err)
	}
}

func TestRequestReplyTokenAllowsDetachedResponder(t *testing.T) {
	sm, err := NewSessionManager(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	recipient := launchSleepSession(t, sm)
	if err := sm.SetName(recipient, "gateway"); err != nil {
		t.Fatalf("SetName failed: %v", err)
	}

	requestID, replyCh, err := sm.SendRequest(0, recipient, "approve?")
	if err != nil {
		t.Fatalf("SendRequest failed: %v", err)
	}

	events, err := sm.ReadMessages(recipient, 0)
	if err != nil {
		t.Fatalf("ReadMessages failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 message in recipient log, got %d", len(events))
	}
	var req RequestData
	if err := json.Unmarshal(events[0].Data, &req); err != nil {
		t.Fatalf("failed to unmarshal request data: %v", err)
	}
	if req.RequestID != requestID {
		t.Fatalf("request RequestID: expected %q, got %q", requestID, req.RequestID)
	}
	if req.ReplyToken == "" {
		t.Fatal("expected non-empty reply token")
	}

	if err := sm.SendReplyWithToken(requestID, req.ReplyToken, "DENIED"); err != nil {
		t.Fatalf("SendReplyWithToken failed: %v", err)
	}

	select {
	case reply := <-replyCh:
		if reply.From != recipient {
			t.Fatalf("reply From: expected %d, got %d", recipient, reply.From)
		}
		if reply.FromName != "gateway" {
			t.Fatalf("reply FromName: expected %q, got %q", "gateway", reply.FromName)
		}
		if reply.Body != "DENIED" {
			t.Fatalf("reply Body: expected %q, got %q", "DENIED", reply.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for reply on channel")
	}
}

func TestRequestReplyInvalidTokenRejected(t *testing.T) {
	sm, err := NewSessionManager(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	recipient := launchSleepSession(t, sm)
	requestID, _, err := sm.SendRequest(0, recipient, "approve?")
	if err != nil {
		t.Fatalf("SendRequest failed: %v", err)
	}

	err = sm.SendReplyWithToken(requestID, "rpl_invalid", "DENIED")
	if err == nil {
		t.Fatal("expected invalid reply token to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid reply token") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequestReplyAfterCleanup(t *testing.T) {
	sm, err := NewSessionManager(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	sender := launchSleepSession(t, sm)
	recipient := launchSleepSession(t, sm)

	requestID, _, err := sm.SendRequest(sender, recipient, "will be cleaned up")
	if err != nil {
		t.Fatalf("SendRequest failed: %v", err)
	}

	// Cleanup the pending request first.
	sm.CleanupRequest(requestID)

	// Now try to reply — should error because no pending request exists.
	err = sm.SendReply(recipient, requestID, "late reply")
	if err == nil {
		t.Fatal("expected error when replying after cleanup, got nil")
	}

	// Verify the error message mentions the request ID.
	expectedSubstr := requestID
	if got := err.Error(); !containsSubstring(got, expectedSubstr) {
		t.Fatalf("expected error to contain %q, got %q", expectedSubstr, got)
	}
}

// containsSubstring checks if s contains substr.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestSendMessageAnonymousSender(t *testing.T) {
	sm, err := NewSessionManager(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	recipient := launchSleepSession(t, sm)

	// fromID=0 should succeed (anonymous sender).
	msgID, err := sm.SendMessage(0, recipient, "hello from anonymous")
	if err != nil {
		t.Fatalf("SendMessage with fromID=0 failed: %v", err)
	}
	if msgID == "" {
		t.Fatal("expected non-empty message ID")
	}

	// Verify the message appears in the recipient's message log.
	events, err := sm.ReadMessages(recipient, 0)
	if err != nil {
		t.Fatalf("ReadMessages failed: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 message in recipient log, got %d", len(events))
	}

	var dm DirectMessageData
	if err := json.Unmarshal(events[0].Data, &dm); err != nil {
		t.Fatalf("failed to unmarshal message data: %v", err)
	}
	if dm.Body != "hello from anonymous" {
		t.Fatalf("expected body %q, got %q", "hello from anonymous", dm.Body)
	}
	if dm.From != 0 {
		t.Fatalf("expected From=0, got %d", dm.From)
	}
}

// launchCatSession launches a "cat" session and returns its ID.
// cat echoes stdin to stdout, which gets captured in the PTY log.
func launchCatSession(t *testing.T, sm *SessionManager) uint32 {
	t.Helper()
	id, err := sm.Launch([]string{"cat"}, "/tmp", nil, nil, "")
	if err != nil {
		t.Fatalf("failed to launch cat session: %v", err)
	}
	t.Cleanup(func() { _ = sm.Kill(id) })
	time.Sleep(200 * time.Millisecond) // let PTY stabilize
	return id
}

func TestDeliverDirectMessagePrompt(t *testing.T) {
	sm, err := NewSessionManager(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	recipient := launchCatSession(t, sm)
	if err := sm.SetName(recipient, "worker"); err != nil {
		t.Fatalf("SetName failed: %v", err)
	}

	err = sm.DeliverDirectMessagePrompt(recipient, "planner", 1, "start with auth module")
	if err != nil {
		t.Fatalf("DeliverDirectMessagePrompt failed: %v", err)
	}

	// Wait for cat to echo the prompt back through the PTY.
	time.Sleep(500 * time.Millisecond)

	logPath, err := sm.LogPath(recipient)
	if err != nil {
		t.Fatalf("LogPath failed: %v", err)
	}
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}

	log := string(content)
	// The new PTY delivery format wraps the body in bracketed-paste markers
	// (\x1b[200~ ... \x1b[201~) followed by CR. The body itself must appear
	// verbatim; the header text is intentionally NOT prepended to the PTY
	// stream because some TUIs (codex) panic on bracket-prefixed multi-line
	// content. Sender identity is preserved through inbox + log layers.
	if !containsSubstring(log, "start with auth module") {
		t.Fatalf("PTY log should contain message body, got: %q", log)
	}
	if !containsSubstring(log, "\x1b[200~") || !containsSubstring(log, "\x1b[201~") {
		t.Fatalf("PTY log should contain bracketed-paste markers, got: %q", log)
	}
}

func TestDeliverRequestPrompt(t *testing.T) {
	sm, err := NewSessionManager(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	recipient := launchCatSession(t, sm)

	err = sm.DeliverRequestPrompt(recipient, "req_123", "planner", 1, "ready for review?")
	if err != nil {
		t.Fatalf("DeliverRequestPrompt failed: %v", err)
	}

	// Wait for cat to echo the prompt back through the PTY.
	time.Sleep(500 * time.Millisecond)

	logPath, err := sm.LogPath(recipient)
	if err != nil {
		t.Fatalf("LogPath failed: %v", err)
	}
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}

	log := string(content)
	// Same change as TestDeliverDirectMessagePrompt: PTY delivery is
	// body + reply-hint wrapped in bracketed-paste, no bracket-prefixed
	// header (which would crash codex's TUI). Request ID is still present
	// in the reply-hint footer.
	if !containsSubstring(log, "ready for review?") {
		t.Fatalf("PTY log should contain request body, got: %q", log)
	}
	if !containsSubstring(log, "cw reply req_123") {
		t.Fatalf("PTY log should contain reply hint with request id, got: %q", log)
	}
	if !containsSubstring(log, "\x1b[200~") || !containsSubstring(log, "\x1b[201~") {
		t.Fatalf("PTY log should contain bracketed-paste markers, got: %q", log)
	}
}
