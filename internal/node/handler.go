package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/codewiresh/codewire/internal/connection"
	"github.com/codewiresh/codewire/internal/networkauth"
	"github.com/codewiresh/codewire/internal/protocol"
	"github.com/codewiresh/codewire/internal/session"
)

// handleClient reads the first control frame from a client, dispatches the
// request by type, and returns. Each Unix/WebSocket connection is handled
// by exactly one goroutine calling this function.
func handleClient(reader connection.FrameReader, writer connection.FrameWriter, manager *session.SessionManager, kvStore *session.KVStore, authorizeLocalDelivery func(context.Context, uint32, uint32, string) error, issueSenderDelegation func(context.Context, uint32, string, string) (*networkauth.SenderDelegationResponse, error)) {
	defer reader.Close()
	defer writer.Close()

	f, err := reader.ReadFrame()
	if err != nil {
		slog.Error("failed to read initial frame", "err", err)
		return
	}
	if f == nil {
		return // clean disconnect
	}
	if f.Type != protocol.FrameControl {
		slog.Error("expected control frame, got data frame")
		return
	}

	var req protocol.Request
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		slog.Error("failed to parse request", "err", err)
		return
	}

	switch req.Type {
	case "ListSessions":
		sessions := manager.List()
		_ = writer.SendResponse(&protocol.Response{
			Type:     "SessionList",
			Sessions: &sessions,
		})

	case "Launch":
		id, launchErr := manager.Launch(req.Command, req.WorkingDir, req.Env, req.StdinData, req.Name, req.Tags...)
		if launchErr != nil {
			msg := launchErr.Error()
			_ = writer.SendResponse(&protocol.Response{
				Type:    "Error",
				Message: msg,
			})
			return
		}
		if req.Name != "" {
			if nameErr := manager.SetName(id, req.Name); nameErr != nil {
				_ = manager.Kill(id)
				_ = writer.SendResponse(&protocol.Response{
					Type:    "Error",
					Message: nameErr.Error(),
				})
				return
			}
		}
		_ = writer.SendResponse(&protocol.Response{
			Type: "Launched",
			ID:   &id,
		})

	case "Attach":
		if req.ID == nil {
			_ = writer.SendResponse(&protocol.Response{
				Type:    "Error",
				Message: "missing session id",
			})
			return
		}
		sessionID := *req.ID

		channels, attachErr := manager.Attach(sessionID)
		if attachErr != nil {
			_ = writer.SendResponse(&protocol.Response{
				Type:    "Error",
				Message: attachErr.Error(),
			})
			return
		}
		defer manager.Detach(sessionID)

		// Unsubscribe the output broadcast when we are done.
		defer manager.UnsubscribeOutput(sessionID, channels.OutputID)

		// Send Attached confirmation.
		_ = writer.SendResponse(&protocol.Response{
			Type: "Attached",
			ID:   &sessionID,
		})

		// Replay history if requested.
		includeHistory := req.IncludeHistory == nil || *req.IncludeHistory
		if includeHistory {
			logPath, logErr := manager.LogPath(sessionID)
			if logErr == nil {
				if histErr := replayHistory(writer, logPath, req.HistoryLines, true); histErr != nil {
					slog.Warn("failed to replay history", "id", sessionID, "err", histErr)
				}
			}
		}

		// Bridge PTY and client until detach or disconnect.
		if bridgeErr := handleAttachSession(reader, writer, channels, sessionID, manager); bridgeErr != nil {
			slog.Debug("attach session ended", "id", sessionID, "err", bridgeErr)
		}

	case "Kill":
		if req.ID == nil {
			_ = writer.SendResponse(&protocol.Response{
				Type:    "Error",
				Message: "missing session id",
			})
			return
		}
		if killErr := manager.Kill(*req.ID); killErr != nil {
			_ = writer.SendResponse(&protocol.Response{
				Type:    "Error",
				Message: killErr.Error(),
			})
			return
		}
		_ = writer.SendResponse(&protocol.Response{
			Type: "Killed",
			ID:   req.ID,
		})

	case "KillAll":
		count := manager.KillAll()
		c := uint(count)
		_ = writer.SendResponse(&protocol.Response{
			Type:  "KilledAll",
			Count: &c,
		})

	case "KillByTags":
		count := manager.KillByTags(req.Tags)
		c := uint(count)
		_ = writer.SendResponse(&protocol.Response{
			Type:  "KilledAll",
			Count: &c,
		})

	case "Resize":
		_ = writer.SendResponse(&protocol.Response{
			Type: "Resized",
		})

	case "Detach":
		_ = writer.SendResponse(&protocol.Response{
			Type: "Detached",
		})

	case "Logs":
		if req.ID == nil {
			_ = writer.SendResponse(&protocol.Response{
				Type:    "Error",
				Message: "missing session id",
			})
			return
		}
		logPath, logErr := manager.LogPath(*req.ID)
		if logErr != nil {
			_ = writer.SendResponse(&protocol.Response{
				Type:    "Error",
				Message: logErr.Error(),
			})
			return
		}
		follow := req.Follow != nil && *req.Follow
		strip := req.StripANSI == nil || *req.StripANSI // default: strip
		if logsErr := handleLogs(writer, logPath, follow, req.Tail, strip); logsErr != nil {
			slog.Debug("logs handler ended", "id", *req.ID, "err", logsErr)
		}

	case "SendInput":
		if req.ID == nil {
			_ = writer.SendResponse(&protocol.Response{
				Type:    "Error",
				Message: "missing session id",
			})
			return
		}
		n, inputErr := manager.SendInput(*req.ID, req.Data)
		if inputErr != nil {
			_ = writer.SendResponse(&protocol.Response{
				Type:    "Error",
				Message: inputErr.Error(),
			})
			return
		}
		bytes := uint(n)
		_ = writer.SendResponse(&protocol.Response{
			Type:  "InputSent",
			Bytes: &bytes,
		})

	case "GetStatus":
		if req.ID == nil {
			_ = writer.SendResponse(&protocol.Response{
				Type:    "Error",
				Message: "missing session id",
			})
			return
		}
		full := req.Full != nil && *req.Full
		info, outputSize, statusErr := manager.GetStatus(*req.ID, full)
		if statusErr != nil {
			_ = writer.SendResponse(&protocol.Response{
				Type:    "Error",
				Message: statusErr.Error(),
			})
			return
		}
		_ = writer.SendResponse(&protocol.Response{
			Type:       "SessionStatus",
			Info:       &info,
			OutputSize: &outputSize,
		})

	case "WatchSession":
		if req.ID == nil {
			_ = writer.SendResponse(&protocol.Response{
				Type:    "Error",
				Message: "missing session id",
			})
			return
		}
		includeHistory := req.IncludeHistory == nil || *req.IncludeHistory
		if watchErr := handleWatchSession(reader, writer, manager, *req.ID, includeHistory, req.HistoryLines); watchErr != nil {
			slog.Debug("watch session ended", "id", *req.ID, "err", watchErr)
		}

	case "Subscribe":
		var eventTypes []session.EventType
		for _, et := range req.EventTypes {
			eventTypes = append(eventTypes, session.EventType(et))
		}
		sub := manager.Subscriptions.Subscribe(req.ID, req.Tags, eventTypes)
		subID := sub.ID
		_ = writer.SendResponse(&protocol.Response{
			Type:           "SubscribeAck",
			SubscriptionID: &subID,
		})

		// Stream events until client disconnects.
		disconnectCh := make(chan struct{}, 1)
		go func() {
			for {
				f, err := reader.ReadFrame()
				if err != nil || f == nil {
					close(disconnectCh)
					return
				}
				// Check for Unsubscribe.
				if f.Type == protocol.FrameControl {
					var unsubReq protocol.Request
					if json.Unmarshal(f.Payload, &unsubReq) == nil && unsubReq.Type == "Unsubscribe" {
						close(disconnectCh)
						return
					}
				}
			}
		}()

		for {
			select {
			case se, ok := <-sub.Ch:
				if !ok {
					return
				}
				sessionID := se.SessionID
				_ = writer.SendResponse(&protocol.Response{
					Type:           "Event",
					SubscriptionID: &subID,
					SessionID:      &sessionID,
					Event: &protocol.SessionEvent{
						Timestamp: se.Event.Timestamp.Format(time.RFC3339Nano),
						EventType: string(se.Event.Type),
						Data:      se.Event.Data,
					},
				})
			case <-disconnectCh:
				manager.Subscriptions.Unsubscribe(sub.ID)
				_ = writer.SendResponse(&protocol.Response{
					Type: "Unsubscribed",
				})
				return
			}
		}

	case "Wait":
		handleWait(reader, writer, manager, req)

	case "MsgSend":
		handleMsgSend(writer, manager, authorizeLocalDelivery, req)

	case "MsgRead":
		handleMsgRead(writer, manager, req)

	case "MsgRequest":
		handleMsgRequest(reader, writer, manager, authorizeLocalDelivery, req)

	case "MsgReply":
		handleMsgReply(writer, manager, req)

	case "MsgListen":
		handleMsgListen(reader, writer, manager, req)

	case "KVSet":
		handleKVSet(writer, kvStore, req)

	case "KVGet":
		handleKVGet(writer, kvStore, req)

	case "KVDelete":
		handleKVDelete(writer, kvStore, req)

	case "KVList":
		handleKVList(writer, kvStore, req)

	case "IssueSenderDelegation":
		sessionID, resolveErr := resolveMessageSession(manager, req.ID, req.Name)
		if resolveErr != nil {
			_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: resolveErr.Error()})
			return
		}
		if issueSenderDelegation == nil {
			_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: "sender delegation issuance is not configured"})
			return
		}
		issued, err := issueSenderDelegation(context.Background(), sessionID, req.Verb, req.AudienceNode)
		if err != nil {
			_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: err.Error()})
			return
		}
		fromName := manager.GetName(sessionID)
		_ = writer.SendResponse(&protocol.Response{
			Type:      "SenderDelegationIssued",
			FromID:    &sessionID,
			FromName:  fromName,
			SenderCap: issued.Delegation,
		})

	case "ReportTask":
		sessionID, resolveErr := resolveMessageSession(manager, req.ID, req.Name)
		if resolveErr != nil {
			_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: resolveErr.Error()})
			return
		}
		if err := manager.ReportTask(sessionID, req.Summary, req.State); err != nil {
			_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: err.Error()})
			return
		}
		_ = writer.SendResponse(&protocol.Response{
			Type: "TaskReported",
			ID:   &sessionID,
		})

	default:
		_ = writer.SendResponse(&protocol.Response{
			Type:    "Error",
			Message: fmt.Sprintf("unknown request type: %s", req.Type),
		})
	}
}

func resolveMessageSession(manager *session.SessionManager, id *uint32, name string) (uint32, error) {
	if manager == nil {
		return 0, fmt.Errorf("session manager is nil")
	}
	if id != nil {
		return *id, nil
	}
	name = strings.TrimSpace(strings.TrimPrefix(name, "@"))
	if name == "" {
		return 0, fmt.Errorf("session id or name required")
	}
	return manager.ResolveByName(name)
}

// frameOrError bundles a frame read result for channel-based communication.
type frameOrError struct {
	frame *protocol.Frame
	err   error
}

// handleAttachSession bridges PTY output and client input until the session
// ends, the client disconnects, or the client sends a Detach command.
func handleAttachSession(
	reader connection.FrameReader,
	writer connection.FrameWriter,
	channels *session.AttachChannels,
	sessionID uint32,
	manager *session.SessionManager,
) error {
	// Spawn a goroutine to read frames from the client, since ReadFrame blocks.
	frameCh := make(chan frameOrError, 1)
	go func() {
		for {
			f, err := reader.ReadFrame()
			frameCh <- frameOrError{frame: f, err: err}
			if err != nil || f == nil {
				return
			}
		}
	}()

	for {
		select {
		case data := <-channels.OutputCh:
			// PTY output to client.
			if err := writer.SendData(data); err != nil {
				return fmt.Errorf("sending output data: %w", err)
			}

		case fe := <-frameCh:
			if fe.err != nil {
				return fmt.Errorf("reading client frame: %w", fe.err)
			}
			if fe.frame == nil {
				// Client disconnected.
				return nil
			}

			if fe.frame.Type == protocol.FrameData {
				// Client sending PTY input.
				select {
				case channels.InputCh <- fe.frame.Payload:
				default:
					slog.Warn("input channel full, dropping data", "id", sessionID)
				}
				continue
			}

			// Control frame — parse the request.
			var req protocol.Request
			if err := json.Unmarshal(fe.frame.Payload, &req); err != nil {
				slog.Error("failed to parse attach control frame", "err", err)
				continue
			}

			switch req.Type {
			case "Detach":
				_ = writer.SendResponse(&protocol.Response{
					Type: "Detached",
					ID:   &sessionID,
				})
				return nil

			case "Resize":
				if req.Cols != nil && req.Rows != nil {
					if err := manager.Resize(sessionID, *req.Cols, *req.Rows); err != nil {
						slog.Error("resize failed", "id", sessionID, "err", err)
					}
				}

			default:
				slog.Warn("unexpected control frame during attach", "type", req.Type)
			}

		case <-channels.Status.Changed():
			status := channels.Status.Get()
			if status.State != "running" {
				msg := fmt.Sprintf("session %s", status.String())
				_ = writer.SendResponse(&protocol.Response{
					Type:    "Error",
					Message: msg,
				})
				return nil
			}
		}
	}
}

// replayHistory reads the session log file and sends its contents as a data
// frame. If historyLines is non-nil, only the last N lines are sent.
func replayHistory(writer connection.FrameWriter, logPath string, historyLines *uint, clearScreen bool) error {
	content, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no history yet
		}
		return fmt.Errorf("reading log file: %w", err)
	}

	if len(content) == 0 {
		return nil
	}

	data := string(content)
	if historyLines != nil {
		lines := strings.Split(data, "\n")
		n := int(*historyLines)
		if n < len(lines) {
			lines = lines[len(lines)-n:]
		}
		data = strings.Join(lines, "\n")
	}
	data = sanitizeReplayOutput(data)
	if clearScreen && historyLines == nil && len(data) > 0 {
		data = "[H[2J" + data
	}

	if len(data) > 0 {
		return writer.SendData([]byte(data))
	}
	return nil
}

// handleWatchSession subscribes to a session's output and status, streaming
// updates to the client until the session ends or the client disconnects.
func handleWatchSession(
	reader connection.FrameReader,
	writer connection.FrameWriter,
	manager *session.SessionManager,
	id uint32,
	includeHistory bool,
	historyLines *uint,
) error {
	subID, outputCh, err := manager.SubscribeOutput(id)
	if err != nil {
		return writer.SendResponse(&protocol.Response{
			Type:    "Error",
			Message: err.Error(),
		})
	}
	defer manager.UnsubscribeOutput(id, subID)

	statusWatcher, err := manager.SubscribeStatus(id)
	if err != nil {
		return writer.SendResponse(&protocol.Response{
			Type:    "Error",
			Message: err.Error(),
		})
	}

	// Send history if requested.
	if includeHistory {
		logPath, logErr := manager.LogPath(id)
		if logErr == nil {
			content, readErr := os.ReadFile(logPath)
			if readErr == nil && len(content) > 0 {
				data := string(content)
				if historyLines != nil {
					lines := strings.Split(data, "\n")
					n := int(*historyLines)
					if n < len(lines) {
						lines = lines[len(lines)-n:]
					}
					data = strings.Join(lines, "\n")
				}
				data = sanitizeReplayOutput(data)
				if len(data) > 0 {
					output := data
					f := false
					_ = writer.SendResponse(&protocol.Response{
						Type:   "WatchUpdate",
						Status: "running",
						Output: &output,
						Done:   &f,
					})
				}
			}
		}
	}

	// Spawn a goroutine to detect client disconnect.
	disconnectCh := make(chan struct{}, 1)
	go func() {
		for {
			f, err := reader.ReadFrame()
			if err != nil || f == nil {
				select {
				case disconnectCh <- struct{}{}:
				default:
				}
				return
			}
			// Ignore any frames from the client during watch.
		}
	}()

	for {
		select {
		case data := <-outputCh:
			output := string(data)
			f := false
			if sendErr := writer.SendResponse(&protocol.Response{
				Type:   "WatchUpdate",
				Status: "running",
				Output: &output,
				Done:   &f,
			}); sendErr != nil {
				return sendErr
			}

		case <-statusWatcher.Changed():
			s := statusWatcher.Get()
			done := s.State != "running"
			_ = writer.SendResponse(&protocol.Response{
				Type:   "WatchUpdate",
				Status: s.String(),
				Output: nil,
				Done:   &done,
			})
			if done {
				return nil
			}

		case <-disconnectCh:
			return nil
		}
	}
}

// handleWait blocks until the target session(s) complete or timeout.
func handleWait(
	reader connection.FrameReader,
	writer connection.FrameWriter,
	manager *session.SessionManager,
	req protocol.Request,
) {
	var timeout time.Duration
	if req.TimeoutSeconds != nil && *req.TimeoutSeconds > 0 {
		timeout = time.Duration(*req.TimeoutSeconds) * time.Second
	} else {
		timeout = 24 * time.Hour // default: very long
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	condition := req.Condition
	if condition == "" {
		condition = "all"
	}

	// Subscribe to status events.
	var eventTypes []session.EventType
	eventTypes = append(eventTypes, session.EventSessionStatus)

	sub := manager.Subscriptions.Subscribe(req.ID, req.Tags, eventTypes)
	defer manager.Subscriptions.Unsubscribe(sub.ID)

	// Check if already completed.
	if req.ID != nil {
		info, _, err := manager.GetStatus(*req.ID, false)
		if err == nil && (strings.Contains(info.Status, "completed") || strings.Contains(info.Status, "killed")) {
			sessions := []protocol.SessionInfo{info}
			_ = writer.SendResponse(&protocol.Response{
				Type:     "WaitResult",
				Sessions: &sessions,
			})
			return
		}
	}

	// If waiting by tags, check if matching sessions are already done.
	if len(req.Tags) > 0 {
		matching := manager.ListByTags(req.Tags)
		allDone := true
		anyDone := false
		for _, s := range matching {
			if strings.Contains(s.Status, "completed") || strings.Contains(s.Status, "killed") {
				anyDone = true
			} else {
				allDone = false
			}
		}
		if (condition == "all" && allDone && len(matching) > 0) || (condition == "any" && anyDone) {
			_ = writer.SendResponse(&protocol.Response{
				Type:     "WaitResult",
				Sessions: &matching,
			})
			return
		}
	}

	for {
		select {
		case _, ok := <-sub.Ch:
			if !ok {
				return
			}

			// Re-check condition.
			if req.ID != nil {
				info, _, err := manager.GetStatus(*req.ID, false)
				if err == nil && (strings.Contains(info.Status, "completed") || strings.Contains(info.Status, "killed")) {
					sessions := []protocol.SessionInfo{info}
					_ = writer.SendResponse(&protocol.Response{
						Type:     "WaitResult",
						Sessions: &sessions,
					})
					return
				}
			}

			if len(req.Tags) > 0 {
				matching := manager.ListByTags(req.Tags)
				allDone := true
				anyDone := false
				for _, s := range matching {
					if strings.Contains(s.Status, "completed") || strings.Contains(s.Status, "killed") {
						anyDone = true
					} else {
						allDone = false
					}
				}
				if (condition == "all" && allDone && len(matching) > 0) || (condition == "any" && anyDone) {
					_ = writer.SendResponse(&protocol.Response{
						Type:     "WaitResult",
						Sessions: &matching,
					})
					return
				}
			}

		case <-timer.C:
			_ = writer.SendResponse(&protocol.Response{
				Type:    "Error",
				Message: "wait timed out",
			})
			return
		}
	}
}

// handleLogs reads a session's log file and sends it to the client. If follow
// is true, it polls for new data every 500ms until the connection is closed.
func handleLogs(writer connection.FrameWriter, logPath string, follow bool, tail *uint, strip bool) error {
	content, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			content = nil
		} else {
			return writer.SendResponse(&protocol.Response{
				Type:    "Error",
				Message: "failed to read session log",
			})
		}
	}

	data := string(content)
	if strip {
		data = stripANSI(data)
	}

	// Apply tail.
	if tail != nil && len(content) > 0 {
		lines := strings.Split(data, "\n")
		n := int(*tail)
		if n < len(lines) {
			lines = lines[len(lines)-n:]
		}
		data = strings.Join(lines, "\n")
	}

	done := !follow
	if sendErr := writer.SendResponse(&protocol.Response{
		Type: "LogData",
		Data: data,
		Done: &done,
	}); sendErr != nil {
		return sendErr
	}

	if !follow {
		return nil
	}

	// Follow mode: poll for new data.
	offset := int64(len(content))
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		fi, statErr := os.Stat(logPath)
		if statErr != nil {
			continue
		}
		newSize := fi.Size()
		if newSize <= offset {
			continue
		}

		f, openErr := os.Open(logPath)
		if openErr != nil {
			continue
		}

		buf := make([]byte, newSize-offset)
		if _, seekErr := f.Seek(offset, 0); seekErr != nil {
			f.Close()
			continue
		}
		n, readErr := f.Read(buf)
		f.Close()

		if readErr != nil && n == 0 {
			continue
		}

		offset += int64(n)
		chunk := string(buf[:n])
		if strip {
			chunk = stripANSI(chunk)
		}
		notDone := false
		if sendErr := writer.SendResponse(&protocol.Response{
			Type: "LogData",
			Data: chunk,
			Done: &notDone,
		}); sendErr != nil {
			return sendErr
		}
	}

	return nil
}

// resolveRecipient resolves a message target to a session ID. If toID is set it
// is used directly; otherwise toName is resolved via the session manager.
func resolveRecipient(manager *session.SessionManager, toID *uint32, toName string) (uint32, error) {
	if toID != nil {
		return *toID, nil
	}
	if toName != "" {
		name := strings.TrimPrefix(toName, "@")
		return manager.ResolveByName(name)
	}
	return 0, fmt.Errorf("either to_id or to_name required")
}

// deliveryIncludesPTY returns true if the delivery mode includes PTY injection.
func deliveryIncludesPTY(delivery string) bool {
	return delivery == "pty" || delivery == "both"
}

// deliveryIncludesInbox returns true if the delivery mode includes inbox logging.
func deliveryIncludesInbox(delivery string) bool {
	return delivery == "" || delivery == "inbox" || delivery == "both"
}

// handleMsgSend processes a MsgSend request.
func handleMsgSend(writer connection.FrameWriter, manager *session.SessionManager, authorizeLocalDelivery func(context.Context, uint32, uint32, string) error, req protocol.Request) {
	toID, err := resolveRecipient(manager, req.ToID, req.ToName)
	if err != nil {
		_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: err.Error()})
		return
	}

	// Sender: use req.ID if set, otherwise default to 0 (CLI sender).
	var fromID uint32
	if req.ID != nil {
		fromID = *req.ID
	}
	if authorizeLocalDelivery != nil {
		if err := authorizeLocalDelivery(context.Background(), fromID, toID, "msg"); err != nil {
			_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: err.Error()})
			return
		}
	}

	var msgID string
	if deliveryIncludesInbox(req.Delivery) {
		msgID, err = manager.SendMessage(fromID, toID, req.Body)
		if err != nil {
			_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: err.Error()})
			return
		}
	} else {
		msgID = fmt.Sprintf("msg_%d_%d_%d", fromID, toID, time.Now().UnixNano())
	}

	// Inject PTY prompt if delivery includes pty.
	if deliveryIncludesPTY(req.Delivery) {
		fromName := manager.GetName(fromID)
		if ptyErr := manager.DeliverDirectMessagePrompt(toID, fromName, fromID, req.Body); ptyErr != nil {
			slog.Warn("PTY injection failed for MsgSend", "to", toID, "err", ptyErr)
		}
	}

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	_ = writer.SendResponse(&protocol.Response{
		Type:      "MsgSent",
		MessageID: msgID,
		Status:    ts,
	})
}

// handleMsgRead processes a MsgRead request.
func handleMsgRead(writer connection.FrameWriter, manager *session.SessionManager, req protocol.Request) {
	var sessionID uint32
	if req.ID != nil {
		sessionID = *req.ID
	} else if req.ToName != "" {
		resolved, err := manager.ResolveByName(strings.TrimPrefix(req.ToName, "@"))
		if err != nil {
			_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: err.Error()})
			return
		}
		sessionID = resolved
	} else {
		_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: "session id or name required"})
		return
	}

	tail := 50
	if req.Tail != nil {
		tail = int(*req.Tail)
	}

	events, err := manager.ReadMessages(sessionID, tail)
	if err != nil {
		_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: err.Error()})
		return
	}

	messages := make([]protocol.MessageResponse, 0, len(events))
	for _, e := range events {
		mr := eventToMessageResponse(e)
		if mr != nil {
			messages = append(messages, *mr)
		}
	}

	_ = writer.SendResponse(&protocol.Response{
		Type:     "MsgReadResult",
		Messages: &messages,
	})
}

// eventToMessageResponse converts an Event to a MessageResponse, or nil if not a message event.
func eventToMessageResponse(e session.Event) *protocol.MessageResponse {
	switch e.Type {
	case session.EventDirectMessage:
		var d session.DirectMessageData
		if json.Unmarshal(e.Data, &d) != nil {
			return nil
		}
		return &protocol.MessageResponse{
			MessageID: d.MessageID,
			Timestamp: e.Timestamp.Format(time.RFC3339Nano),
			From:      d.From,
			FromName:  d.FromName,
			To:        d.To,
			ToName:    d.ToName,
			Body:      d.Body,
			EventType: string(e.Type),
		}
	case session.EventRequest:
		var d session.RequestData
		if json.Unmarshal(e.Data, &d) != nil {
			return nil
		}
		return &protocol.MessageResponse{
			MessageID:  d.RequestID,
			Timestamp:  e.Timestamp.Format(time.RFC3339Nano),
			From:       d.From,
			FromName:   d.FromName,
			To:         d.To,
			ToName:     d.ToName,
			Body:       d.Body,
			EventType:  string(e.Type),
			RequestID:  d.RequestID,
			ReplyToken: d.ReplyToken,
		}
	case session.EventReply:
		var d session.ReplyData
		if json.Unmarshal(e.Data, &d) != nil {
			return nil
		}
		return &protocol.MessageResponse{
			MessageID: d.RequestID,
			Timestamp: e.Timestamp.Format(time.RFC3339Nano),
			From:      d.From,
			FromName:  d.FromName,
			Body:      d.Body,
			EventType: string(e.Type),
			RequestID: d.RequestID,
		}
	default:
		return nil
	}
}

// handleMsgRequest processes a MsgRequest: sends a request to a session and
// blocks until a reply is received or the timeout expires.
func handleMsgRequest(
	reader connection.FrameReader,
	writer connection.FrameWriter,
	manager *session.SessionManager,
	authorizeLocalDelivery func(context.Context, uint32, uint32, string) error,
	req protocol.Request,
) {
	toID, err := resolveRecipient(manager, req.ToID, req.ToName)
	if err != nil {
		_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: err.Error()})
		return
	}

	var fromID uint32
	if req.ID != nil {
		fromID = *req.ID
	}
	if authorizeLocalDelivery != nil {
		if err := authorizeLocalDelivery(context.Background(), fromID, toID, "request"); err != nil {
			_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: err.Error()})
			return
		}
	}

	delivery := req.Delivery

	requestID, replyCh, reqErr := manager.SendRequest(fromID, toID, req.Body)
	if reqErr != nil {
		_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: reqErr.Error()})
		return
	}

	// Inject PTY prompt if delivery includes pty.
	if deliveryIncludesPTY(delivery) {
		fromName := manager.GetName(fromID)
		if ptyErr := manager.DeliverRequestPrompt(toID, requestID, fromName, fromID, req.Body); ptyErr != nil {
			slog.Warn("PTY injection failed for MsgRequest", "to", toID, "err", ptyErr)
			// Clean up pending request on PTY failure.
			manager.CleanupRequest(requestID)
			_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: fmt.Sprintf("PTY injection failed: %v", ptyErr)})
			return
		}
	}

	timeoutSecs := 60
	if req.TimeoutSeconds != nil && *req.TimeoutSeconds > 0 {
		timeoutSecs = int(*req.TimeoutSeconds)
	}
	timer := time.NewTimer(time.Duration(timeoutSecs) * time.Second)
	defer timer.Stop()

	// Also detect client disconnect.
	disconnectCh := make(chan struct{}, 1)
	go func() {
		for {
			f, err := reader.ReadFrame()
			if err != nil || f == nil {
				close(disconnectCh)
				return
			}
		}
	}()

	select {
	case reply := <-replyCh:
		fromReplyID := reply.From
		_ = writer.SendResponse(&protocol.Response{
			Type:      "MsgRequestResult",
			RequestID: requestID,
			ReplyBody: reply.Body,
			FromID:    &fromReplyID,
			FromName:  reply.FromName,
		})
	case <-timer.C:
		manager.CleanupRequest(requestID)
		_ = writer.SendResponse(&protocol.Response{
			Type:    "Error",
			Message: fmt.Sprintf("request %s timed out after %ds", requestID, timeoutSecs),
		})
	case <-disconnectCh:
		manager.CleanupRequest(requestID)
	}
}

// handleMsgListen subscribes to message events and streams them to the client.
func handleMsgListen(
	reader connection.FrameReader,
	writer connection.FrameWriter,
	manager *session.SessionManager,
	req protocol.Request,
) {
	eventTypes := []session.EventType{
		session.EventDirectMessage,
		session.EventRequest,
		session.EventReply,
	}
	sub := manager.Subscriptions.Subscribe(req.ID, nil, eventTypes)
	defer manager.Subscriptions.Unsubscribe(sub.ID)

	// Send ack.
	_ = writer.SendResponse(&protocol.Response{
		Type: "MsgListenAck",
	})

	// Detect client disconnect.
	disconnectCh := make(chan struct{}, 1)
	go func() {
		for {
			f, err := reader.ReadFrame()
			if err != nil || f == nil {
				close(disconnectCh)
				return
			}
		}
	}()

	for {
		select {
		case se, ok := <-sub.Ch:
			if !ok {
				return
			}
			sessionID := se.SessionID
			_ = writer.SendResponse(&protocol.Response{
				Type:      "Event",
				SessionID: &sessionID,
				Event: &protocol.SessionEvent{
					Timestamp: se.Event.Timestamp.Format(time.RFC3339Nano),
					EventType: string(se.Event.Type),
					Data:      se.Event.Data,
				},
			})
		case <-disconnectCh:
			return
		}
	}
}

// handleMsgReply processes a MsgReply: sends a reply to a pending request.
func handleMsgReply(writer connection.FrameWriter, manager *session.SessionManager, req protocol.Request) {
	if req.RequestID == "" {
		_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: "missing request_id"})
		return
	}

	var fromID uint32
	if req.ID != nil {
		fromID = *req.ID
	}
	if fromID == 0 && strings.TrimSpace(req.ReplyToken) == "" {
		_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: "missing sender identity or reply_token"})
		return
	}

	var err error
	if strings.TrimSpace(req.ReplyToken) != "" {
		err = manager.SendReplyWithToken(req.RequestID, strings.TrimSpace(req.ReplyToken), req.Body)
	} else {
		err = manager.SendReply(fromID, req.RequestID, req.Body)
	}
	if err != nil {
		_ = writer.SendResponse(&protocol.Response{Type: "Error", Message: err.Error()})
		return
	}

	_ = writer.SendResponse(&protocol.Response{
		Type:      "MsgReplySent",
		RequestID: req.RequestID,
	})
}

// ---------------------------------------------------------------------------
// KV handlers
// ---------------------------------------------------------------------------

func handleKVSet(writer connection.FrameWriter, kvStore *session.KVStore, req protocol.Request) {
	ns := req.Namespace
	if ns == "" {
		ns = "default"
	}

	var ttl time.Duration
	if req.TTL != "" {
		var err error
		ttl, err = time.ParseDuration(req.TTL)
		if err != nil {
			_ = writer.SendResponse(&protocol.Response{
				Type:    "Error",
				Message: fmt.Sprintf("invalid TTL %q: %v", req.TTL, err),
			})
			return
		}
	}

	kvStore.Set(ns, req.Key, req.Value, ttl)
	_ = writer.SendResponse(&protocol.Response{
		Type: "KVSetOK",
	})
}

func handleKVGet(writer connection.FrameWriter, kvStore *session.KVStore, req protocol.Request) {
	ns := req.Namespace
	if ns == "" {
		ns = "default"
	}

	value := kvStore.Get(ns, req.Key)
	_ = writer.SendResponse(&protocol.Response{
		Type:  "KVGetResult",
		Value: value,
	})
}

func handleKVDelete(writer connection.FrameWriter, kvStore *session.KVStore, req protocol.Request) {
	ns := req.Namespace
	if ns == "" {
		ns = "default"
	}

	kvStore.Delete(ns, req.Key)
	_ = writer.SendResponse(&protocol.Response{
		Type: "KVDeleteOK",
	})
}

func handleKVList(writer connection.FrameWriter, kvStore *session.KVStore, req protocol.Request) {
	ns := req.Namespace
	if ns == "" {
		ns = "default"
	}

	entries := kvStore.List(ns, req.Key)
	pairs := make([]protocol.KVPair, 0, len(entries))
	for _, e := range entries {
		pair := protocol.KVPair{
			Key:   e.Key,
			Value: e.Value,
		}
		if e.ExpiresAt != nil {
			ts := e.ExpiresAt.Format(time.RFC3339)
			pair.ExpiresAt = &ts
		}
		pairs = append(pairs, pair)
	}

	_ = writer.SendResponse(&protocol.Response{
		Type:    "KVListResult",
		Entries: &pairs,
	})
}
