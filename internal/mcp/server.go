package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/codewiresh/codewire/internal/config"
	"github.com/codewiresh/codewire/internal/connection"
	"github.com/codewiresh/codewire/internal/protocol"
)

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 types
// ---------------------------------------------------------------------------

type jsonRpcRequest struct {
	Jsonrpc string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params,omitempty"`
}

type jsonRpcResponse struct {
	Jsonrpc string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Result  interface{}      `json:"result,omitempty"`
	Error   *jsonRpcError    `json:"error,omitempty"`
}

type jsonRpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

// RunMCPServer reads JSON-RPC requests from stdin, dispatches them, and writes
// responses to stdout. It communicates with the codewire node over a Unix
// socket at dataDir/codewire.sock.
func RunMCPServer(dataDir string) error {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1 MB buffer

	version := "0.1.0"

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var req jsonRpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			fmt.Fprintf(os.Stderr, "[mcp] invalid JSON-RPC: %v\n", err)
			continue
		}

		var resp jsonRpcResponse
		resp.Jsonrpc = "2.0"
		resp.ID = req.ID

		switch req.Method {
		case "initialize":
			resp.Result = map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{},
				},
				"serverInfo": map[string]interface{}{
					"name":    "codewire",
					"version": version,
				},
			}

		case "tools/list":
			resp.Result = map[string]interface{}{
				"tools": getTools(),
			}

		case "tools/call":
			result, err := handleToolCall(dataDir, req.Params)
			if err != nil {
				resp.Error = &jsonRpcError{Code: -32603, Message: err.Error()}
			} else {
				resp.Result = map[string]interface{}{
					"content": []map[string]interface{}{
						{"type": "text", "text": result},
					},
				}
			}

		default:
			resp.Error = &jsonRpcError{
				Code:    -32601,
				Message: fmt.Sprintf("method not found: %s", req.Method),
			}
		}

		out, _ := json.Marshal(resp)
		fmt.Fprintf(os.Stdout, "%s\n", out)
	}
	return scanner.Err()
}

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

// getTools returns all MCP tools (local node + platform environment tools).
func getTools() []tool {
	tools := getNodeTools()
	tools = append(tools, environmentTools()...)
	return tools
}

func getNodeTools() []tool {
	return []tool{
		{
			Name:        "codewire_list_sessions",
			Description: "List all CodeWire sessions with their status",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"status_filter": map[string]interface{}{
						"type":        "string",
						"description": "Filter by status: 'all', 'running', or 'completed'",
						"enum":        []string{"all", "running", "completed"},
					},
				},
			},
		},
		{
			Name:        "codewire_read_session_output",
			Description: "Read output from a session (snapshot, not live)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{
						"type":        "integer",
						"description": "The session ID to read from",
					},
					"tail": map[string]interface{}{
						"type":        "integer",
						"description": "Number of lines to show from end (optional)",
					},
					"max_chars": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum characters to return (default: 500000)",
					},
				},
				"required": []string{"session_id"},
			},
		},
		{
			Name:        "codewire_send_input",
			Description: "Send input to a session without attaching",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{
						"type":        "integer",
						"description": "The session ID to send input to",
					},
					"input": map[string]interface{}{
						"type":        "string",
						"description": "The input text to send",
					},
					"auto_newline": map[string]interface{}{
						"type":        "boolean",
						"description": "Automatically add newline (default: true)",
					},
				},
				"required": []string{"session_id", "input"},
			},
		},
		{
			Name:        "codewire_watch_session",
			Description: "Monitor a session in real-time (time-bounded)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{
						"type":        "integer",
						"description": "The session ID to watch",
					},
					"include_history": map[string]interface{}{
						"type":        "boolean",
						"description": "Include recent history (default: true)",
					},
					"history_lines": map[string]interface{}{
						"type":        "integer",
						"description": "Number of history lines to include (default: 50)",
					},
					"max_duration_seconds": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum watch duration in seconds (default: 30)",
					},
				},
				"required": []string{"session_id"},
			},
		},
		{
			Name:        "codewire_get_session_status",
			Description: "Get detailed status information for a session",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{
						"type":        "integer",
						"description": "The session ID to query",
					},
				},
				"required": []string{"session_id"},
			},
		},
		{
			Name:        "codewire_launch_session",
			Description: "Launch a new CodeWire session with optional name and tags for grouping and filtering",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"command": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Command and arguments to run",
					},
					"working_dir": map[string]interface{}{
						"type":        "string",
						"description": "Working directory (defaults to current dir)",
					},
					"name": map[string]interface{}{
						"type":        "string",
						"description": "Unique name for the session (alphanumeric + hyphens, 1-32 chars)",
					},
					"tags": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Tags for grouping/filtering (e.g. ['worker', 'build'])",
					},
				},
				"required": []string{"command"},
			},
		},
		{
			Name:        "codewire_kill_session",
			Description: "Terminate a running session by ID or by tag filter",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{
						"type":        "integer",
						"description": "The session ID to kill (optional if tags provided)",
					},
					"tags": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Kill all sessions matching these tags",
					},
				},
			},
		},
		{
			Name:        "codewire_subscribe",
			Description: "Subscribe to session events (returns events as they arrive, time-bounded)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{
						"type":        "integer",
						"description": "Filter by session ID",
					},
					"tags": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Filter by tags",
					},
					"event_types": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Filter by event type (session.created, session.status, etc.)",
					},
					"max_duration_seconds": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum subscription duration in seconds (default: 30)",
					},
				},
			},
		},
		{
			Name:        "codewire_wait_for",
			Description: "Block until session(s) complete. Returns enriched session info when done.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{
						"type":        "integer",
						"description": "Wait for this session ID to complete",
					},
					"tags": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Wait for sessions matching these tags",
					},
					"condition": map[string]interface{}{
						"type":        "string",
						"description": "Wait condition: 'all' (default) or 'any'",
						"enum":        []string{"all", "any"},
					},
					"timeout_seconds": map[string]interface{}{
						"type":        "integer",
						"description": "Timeout in seconds (default: 300)",
					},
				},
			},
		},
		{
			Name:        "codewire_msg",
			Description: "Send a direct message to a session",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"to_session_id": map[string]interface{}{
						"type":        "integer",
						"description": "Recipient session ID",
					},
					"to_name": map[string]interface{}{
						"type":        "string",
						"description": "Recipient session name",
					},
					"from_session_id": map[string]interface{}{
						"type":        "integer",
						"description": "Sender session ID (optional)",
					},
					"body": map[string]interface{}{
						"type":        "string",
						"description": "Message body",
					},
				},
				"required": []string{"body"},
			},
		},
		{
			Name:        "codewire_read_messages",
			Description: "Read messages from a session's inbox. Includes pending requests at the top.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"session_id": map[string]interface{}{
						"type":        "integer",
						"description": "Session ID to read inbox of",
					},
					"tail": map[string]interface{}{
						"type":        "integer",
						"description": "Number of messages to return (default: 20)",
					},
				},
			},
		},
		{
			Name:        "codewire_request",
			Description: "Send a request to a session and block until a reply is received",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"to_session_id": map[string]interface{}{
						"type":        "integer",
						"description": "Recipient session ID",
					},
					"to_name": map[string]interface{}{
						"type":        "string",
						"description": "Recipient session name",
					},
					"from_session_id": map[string]interface{}{
						"type":        "integer",
						"description": "Sender session ID (optional)",
					},
					"body": map[string]interface{}{
						"type":        "string",
						"description": "Request body",
					},
					"timeout_seconds": map[string]interface{}{
						"type":        "integer",
						"description": "Timeout in seconds (default: 60)",
					},
				},
				"required": []string{"body"},
			},
		},
		{
			Name:        "codewire_reply",
			Description: "Reply to a pending request",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"request_id": map[string]interface{}{
						"type":        "string",
						"description": "The request ID to reply to",
					},
					"body": map[string]interface{}{
						"type":        "string",
						"description": "Reply body",
					},
					"from_session_id": map[string]interface{}{
						"type":        "integer",
						"description": "Session ID sending the reply (optional)",
					},
				},
				"required": []string{"request_id", "body"},
			},
		},
		{
			Name:        "codewire_list_nodes",
			Description: "List all registered nodes from the relay",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Tool dispatch
// ---------------------------------------------------------------------------

// handleToolCall dispatches to the appropriate tool handler.
func handleToolCall(dataDir string, params json.RawMessage) (string, error) {
	var p struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return "", fmt.Errorf("invalid params: %w", err)
	}

	args := p.Arguments

	switch p.Name {
	case "codewire_list_sessions":
		return toolListSessions(dataDir, args)
	case "codewire_read_session_output":
		return toolReadSessionOutput(dataDir, args)
	case "codewire_send_input":
		return toolSendInput(dataDir, args)
	case "codewire_watch_session":
		return toolWatchSession(dataDir, args)
	case "codewire_get_session_status":
		return toolGetSessionStatus(dataDir, args)
	case "codewire_launch_session":
		return toolLaunchSession(dataDir, args)
	case "codewire_kill_session":
		return toolKillSession(dataDir, args)
	case "codewire_subscribe":
		return toolSubscribe(dataDir, args)
	case "codewire_wait_for":
		return toolWaitFor(dataDir, args)
	case "codewire_msg":
		return toolMsg(dataDir, args)
	case "codewire_read_messages":
		return toolReadMessages(dataDir, args)
	case "codewire_request":
		return toolRequest(dataDir, args)
	case "codewire_reply":
		return toolReply(dataDir, args)
	case "codewire_list_nodes":
		return toolListNodes(dataDir, args)
	// Platform environment tools (use API, not local node)
	case "codewire_list_environments":
		return toolListEnvironments(args)
	case "codewire_create_environment":
		return toolCreateEnvironment(args)
	case "codewire_get_environment":
		return toolGetEnvironment(args)
	case "codewire_stop_environment":
		return toolStopEnvironment(args)
	case "codewire_start_environment":
		return toolStartEnvironment(args)
	case "codewire_delete_environment":
		return toolDeleteEnvironment(args)
	case "codewire_list_presets":
		return toolListPresets(args)
	case "codewire_exec_in_environment":
		return toolExecInEnvironment(args)
	case "codewire_list_files":
		return toolListFiles(args)
	default:
		return "", fmt.Errorf("unknown tool: %s", p.Name)
	}
}

// ---------------------------------------------------------------------------
// Tool handlers
// ---------------------------------------------------------------------------

func toolListSessions(dataDir string, args map[string]interface{}) (string, error) {
	resp, err := nodeRequest(dataDir, &protocol.Request{Type: "ListSessions"})
	if err != nil {
		return "", err
	}
	if resp.Type == "Error" {
		return fmt.Sprintf("Error: %s", resp.Message), nil
	}
	if resp.Sessions == nil {
		return "Unexpected response", nil
	}

	sessions := *resp.Sessions

	filter, _ := args["status_filter"].(string)
	if filter == "" {
		filter = "all"
	}

	var filtered []protocol.SessionInfo
	for _, s := range sessions {
		switch filter {
		case "running":
			if strings.Contains(s.Status, "running") {
				filtered = append(filtered, s)
			}
		case "completed":
			if strings.Contains(s.Status, "completed") {
				filtered = append(filtered, s)
			}
		default:
			filtered = append(filtered, s)
		}
	}

	out, err := json.MarshalIndent(filtered, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func toolReadSessionOutput(dataDir string, args map[string]interface{}) (string, error) {
	sessionID, err := argUint32(args, "session_id")
	if err != nil {
		return "", err
	}

	var tail *uint
	if v, ok := args["tail"].(float64); ok {
		t := uint(v)
		tail = &t
	}

	maxChars := uint64(500000)
	if v, ok := args["max_chars"].(float64); ok {
		maxChars = uint64(v)
	}

	f := false
	resp, err := nodeRequest(dataDir, &protocol.Request{
		Type:   "Logs",
		ID:     &sessionID,
		Follow: &f,
		Tail:   tail,
	})
	if err != nil {
		return "", err
	}

	if resp.Type == "Error" {
		return fmt.Sprintf("Error: %s", resp.Message), nil
	}
	if resp.Type != "LogData" {
		return "Unexpected response", nil
	}

	data := resp.Data
	if uint64(len(data)) > maxChars {
		data = data[:maxChars] + "... [truncated]"
	}
	return data, nil
}

func toolSendInput(dataDir string, args map[string]interface{}) (string, error) {
	sessionID, err := argUint32(args, "session_id")
	if err != nil {
		return "", err
	}

	input, ok := args["input"].(string)
	if !ok {
		return "", fmt.Errorf("missing input")
	}

	autoNewline := true
	if v, ok := args["auto_newline"].(bool); ok {
		autoNewline = v
	}

	data := []byte(input)
	if autoNewline && !endsWithNewline(data) {
		data = append(data, '\n')
	}

	resp, err := nodeRequest(dataDir, &protocol.Request{
		Type: "SendInput",
		ID:   &sessionID,
		Data: data,
	})
	if err != nil {
		return "", err
	}

	if resp.Type == "Error" {
		return fmt.Sprintf("Error: %s", resp.Message), nil
	}
	if resp.Type == "InputSent" {
		bytes := uint(0)
		if resp.Bytes != nil {
			bytes = *resp.Bytes
		}
		return fmt.Sprintf("Sent %d bytes to session %d", bytes, sessionID), nil
	}
	return "Unexpected response", nil
}

func toolWatchSession(dataDir string, args map[string]interface{}) (string, error) {
	sessionID, err := argUint32(args, "session_id")
	if err != nil {
		return "", err
	}

	includeHistory := true
	if v, ok := args["include_history"].(bool); ok {
		includeHistory = v
	}

	var historyLines *uint
	if v, ok := args["history_lines"].(float64); ok {
		h := uint(v)
		historyLines = &h
	}

	maxDuration := uint64(30)
	if v, ok := args["max_duration_seconds"].(float64); ok {
		maxDuration = uint64(v)
	}

	return watchSessionTimed(dataDir, sessionID, includeHistory, historyLines, maxDuration)
}

func toolGetSessionStatus(dataDir string, args map[string]interface{}) (string, error) {
	sessionID, err := argUint32(args, "session_id")
	if err != nil {
		return "", err
	}

	resp, err := nodeRequest(dataDir, &protocol.Request{
		Type: "GetStatus",
		ID:   &sessionID,
	})
	if err != nil {
		return "", err
	}

	if resp.Type == "Error" {
		return fmt.Sprintf("Error: %s", resp.Message), nil
	}
	if resp.Type != "SessionStatus" || resp.Info == nil {
		return "Unexpected response", nil
	}

	// Marshal the session info and inject output_size.
	raw, err := json.Marshal(resp.Info)
	if err != nil {
		return "", err
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "", err
	}
	if resp.OutputSize != nil {
		obj["output_size"] = *resp.OutputSize
	}

	out, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func toolLaunchSession(dataDir string, args map[string]interface{}) (string, error) {
	cmdRaw, ok := args["command"]
	if !ok {
		return "", fmt.Errorf("missing command")
	}
	cmdArr, ok := cmdRaw.([]interface{})
	if !ok {
		return "", fmt.Errorf("command must be an array")
	}
	var command []string
	for _, v := range cmdArr {
		s, ok := v.(string)
		if ok {
			command = append(command, s)
		}
	}

	workingDir, _ := args["working_dir"].(string)
	if workingDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			workingDir = "."
		} else {
			workingDir = wd
		}
	}

	name, _ := args["name"].(string)

	var tags []string
	if tagsRaw, ok := args["tags"].([]interface{}); ok {
		for _, v := range tagsRaw {
			if s, ok := v.(string); ok {
				tags = append(tags, s)
			}
		}
	}

	resp, err := nodeRequest(dataDir, &protocol.Request{
		Type:       "Launch",
		Command:    command,
		WorkingDir: workingDir,
		Name:       name,
		Tags:       tags,
	})
	if err != nil {
		return "", err
	}

	if resp.Type == "Error" {
		return fmt.Sprintf("Error: %s", resp.Message), nil
	}
	if resp.Type == "Launched" && resp.ID != nil {
		return fmt.Sprintf("Launched session %d", *resp.ID), nil
	}
	return "Unexpected response", nil
}

func toolKillSession(dataDir string, args map[string]interface{}) (string, error) {
	// Check if killing by tags.
	var tags []string
	if tagsRaw, ok := args["tags"].([]interface{}); ok {
		for _, v := range tagsRaw {
			if s, ok := v.(string); ok {
				tags = append(tags, s)
			}
		}
	}

	if len(tags) > 0 {
		resp, err := nodeRequest(dataDir, &protocol.Request{
			Type: "KillByTags",
			Tags: tags,
		})
		if err != nil {
			return "", err
		}
		if resp.Type == "Error" {
			return fmt.Sprintf("Error: %s", resp.Message), nil
		}
		count := uint(0)
		if resp.Count != nil {
			count = *resp.Count
		}
		return fmt.Sprintf("Killed %d session(s) matching tags %v", count, tags), nil
	}

	sessionID, err := argUint32(args, "session_id")
	if err != nil {
		return "", fmt.Errorf("either session_id or tags required")
	}

	resp, err := nodeRequest(dataDir, &protocol.Request{
		Type: "Kill",
		ID:   &sessionID,
	})
	if err != nil {
		return "", err
	}

	if resp.Type == "Error" {
		return fmt.Sprintf("Error: %s", resp.Message), nil
	}
	if resp.Type == "Killed" && resp.ID != nil {
		return fmt.Sprintf("Killed session %d", *resp.ID), nil
	}
	return "Unexpected response", nil
}

func toolSubscribe(dataDir string, args map[string]interface{}) (string, error) {
	maxDuration := uint64(30)
	if v, ok := args["max_duration_seconds"].(float64); ok {
		maxDuration = uint64(v)
	}

	var sessionID *uint32
	if v, ok := args["session_id"].(float64); ok {
		id := uint32(v)
		sessionID = &id
	}

	var tags []string
	if tagsRaw, ok := args["tags"].([]interface{}); ok {
		for _, v := range tagsRaw {
			if s, ok := v.(string); ok {
				tags = append(tags, s)
			}
		}
	}

	var eventTypes []string
	if etRaw, ok := args["event_types"].([]interface{}); ok {
		for _, v := range etRaw {
			if s, ok := v.(string); ok {
				eventTypes = append(eventTypes, s)
			}
		}
	}

	return subscribeTimed(dataDir, sessionID, tags, eventTypes, maxDuration)
}

func toolWaitFor(dataDir string, args map[string]interface{}) (string, error) {
	var sessionID *uint32
	if v, ok := args["session_id"].(float64); ok {
		id := uint32(v)
		sessionID = &id
	}

	var tags []string
	if tagsRaw, ok := args["tags"].([]interface{}); ok {
		for _, v := range tagsRaw {
			if s, ok := v.(string); ok {
				tags = append(tags, s)
			}
		}
	}

	condition, _ := args["condition"].(string)
	if condition == "" {
		condition = "all"
	}

	timeoutSecs := uint64(300)
	if v, ok := args["timeout_seconds"].(float64); ok {
		timeoutSecs = uint64(v)
	}

	return waitForTimed(dataDir, sessionID, tags, condition, timeoutSecs)
}

func toolMsg(dataDir string, args map[string]interface{}) (string, error) {
	body, _ := args["body"].(string)
	if body == "" {
		return "", fmt.Errorf("missing body")
	}

	req := &protocol.Request{
		Type: "MsgSend",
		Body: body,
	}

	if v, ok := args["to_session_id"].(float64); ok {
		id := uint32(v)
		req.ToID = &id
	}
	if v, ok := args["to_name"].(string); ok && v != "" {
		req.ToName = v
	}
	if v, ok := args["from_session_id"].(float64); ok {
		id := uint32(v)
		req.ID = &id
	}

	resp, err := nodeRequest(dataDir, req)
	if err != nil {
		return "", err
	}
	if resp.Type == "Error" {
		return fmt.Sprintf("Error: %s", resp.Message), nil
	}
	return fmt.Sprintf("Message sent: %s", resp.MessageID), nil
}

func toolReadMessages(dataDir string, args map[string]interface{}) (string, error) {
	var sessionID *uint32
	if v, ok := args["session_id"].(float64); ok {
		id := uint32(v)
		sessionID = &id
	}

	tail := uint(20)
	if v, ok := args["tail"].(float64); ok {
		tail = uint(v)
	}

	req := &protocol.Request{
		Type: "MsgRead",
		ID:   sessionID,
		Tail: &tail,
	}

	resp, err := nodeRequest(dataDir, req)
	if err != nil {
		return "", err
	}
	if resp.Type == "Error" {
		return fmt.Sprintf("Error: %s", resp.Message), nil
	}
	if resp.Messages == nil {
		return "[]", nil
	}
	out, err := json.MarshalIndent(resp.Messages, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func toolRequest(dataDir string, args map[string]interface{}) (string, error) {
	body, _ := args["body"].(string)
	if body == "" {
		return "", fmt.Errorf("missing body")
	}

	timeoutSecs := uint64(60)
	if v, ok := args["timeout_seconds"].(float64); ok {
		timeoutSecs = uint64(v)
	}

	req := &protocol.Request{
		Type:           "MsgRequest",
		Body:           body,
		TimeoutSeconds: &timeoutSecs,
	}
	if v, ok := args["to_session_id"].(float64); ok {
		id := uint32(v)
		req.ToID = &id
	}
	if v, ok := args["to_name"].(string); ok && v != "" {
		req.ToName = v
	}
	if v, ok := args["from_session_id"].(float64); ok {
		id := uint32(v)
		req.ID = &id
	}

	// This blocks until reply or timeout — use a long-lived connection.
	sockPath := filepath.Join(dataDir, "codewire.sock")
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return "", fmt.Errorf("no node running — start one with: cw node -d\n(socket: %s)", sockPath)
	}
	defer conn.Close()

	reader := connection.NewUnixReader(conn)
	writer := connection.NewUnixWriter(conn)

	if err := writer.SendRequest(req); err != nil {
		return "", err
	}

	// Read response (blocks until reply or timeout).
	f, err := reader.ReadFrame()
	if err != nil {
		return "", err
	}
	if f == nil {
		return "", fmt.Errorf("connection closed before response")
	}
	if f.Type != protocol.FrameControl {
		return "", fmt.Errorf("unexpected data frame")
	}

	var resp protocol.Response
	if err := json.Unmarshal(f.Payload, &resp); err != nil {
		return "", err
	}

	switch resp.Type {
	case "MsgRequestResult":
		fromLabel := "unknown"
		if resp.FromName != "" {
			fromLabel = resp.FromName
		} else if resp.FromID != nil {
			fromLabel = fmt.Sprintf("session %d", *resp.FromID)
		}
		return fmt.Sprintf("Reply from %s: %s", fromLabel, resp.ReplyBody), nil
	case "Error":
		return fmt.Sprintf("Error: %s", resp.Message), nil
	default:
		return fmt.Sprintf("Unexpected response: %s", resp.Type), nil
	}
}

func toolReply(dataDir string, args map[string]interface{}) (string, error) {
	requestID, _ := args["request_id"].(string)
	if requestID == "" {
		return "", fmt.Errorf("missing request_id")
	}
	body, _ := args["body"].(string)

	req := &protocol.Request{
		Type:      "MsgReply",
		RequestID: requestID,
		Body:      body,
	}
	if v, ok := args["from_session_id"].(float64); ok {
		id := uint32(v)
		req.ID = &id
	}

	resp, err := nodeRequest(dataDir, req)
	if err != nil {
		return "", err
	}
	if resp.Type == "Error" {
		return fmt.Sprintf("Error: %s", resp.Message), nil
	}
	return fmt.Sprintf("Reply sent for request %s", requestID), nil
}

func toolListNodes(dataDir string, _ map[string]interface{}) (string, error) {
	cfg, err := loadRelayConfig(dataDir)
	if err != nil {
		return "", err
	}

	resp, fetchErr := fetchRelayJSON(cfg + "/api/v1/nodes")
	if fetchErr != nil {
		return "", fetchErr
	}
	return string(resp), nil
}

// ---------------------------------------------------------------------------
// Node communication
// ---------------------------------------------------------------------------

// nodeRequest connects to the Unix socket and sends a single request,
// returning the response.
func nodeRequest(dataDir string, req *protocol.Request) (*protocol.Response, error) {
	sockPath := filepath.Join(dataDir, "codewire.sock")
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("no node running — start one with: cw node -d\n(socket: %s)", sockPath)
	}
	defer conn.Close()

	reader := connection.NewUnixReader(conn)
	writer := connection.NewUnixWriter(conn)

	if err := writer.SendRequest(req); err != nil {
		return nil, err
	}

	f, err := reader.ReadFrame()
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, fmt.Errorf("unexpected EOF")
	}
	if f.Type != protocol.FrameControl {
		return nil, fmt.Errorf("unexpected data frame")
	}

	var resp protocol.Response
	if err := json.Unmarshal(f.Payload, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// watchSessionTimed connects and watches a session with a maximum duration,
// collecting all output.
func watchSessionTimed(dataDir string, sessionID uint32, includeHistory bool, historyLines *uint, maxDurationSecs uint64) (string, error) {
	sockPath := filepath.Join(dataDir, "codewire.sock")
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return "", fmt.Errorf("no node running — start one with: cw node -d\n(socket: %s)", sockPath)
	}
	defer conn.Close()

	reader := connection.NewUnixReader(conn)
	writer := connection.NewUnixWriter(conn)

	req := &protocol.Request{
		Type:           "WatchSession",
		ID:             &sessionID,
		IncludeHistory: &includeHistory,
		HistoryLines:   historyLines,
	}
	if err := writer.SendRequest(req); err != nil {
		return "", err
	}

	var output string
	deadline := time.After(time.Duration(maxDurationSecs) * time.Second)

	type frameResult struct {
		frame *protocol.Frame
		err   error
	}
	frameCh := make(chan frameResult, 1)
	go func() {
		for {
			f, err := reader.ReadFrame()
			frameCh <- frameResult{f, err}
			if err != nil || f == nil {
				return
			}
		}
	}()

	for {
		select {
		case fr := <-frameCh:
			if fr.err != nil {
				return output, fr.err
			}
			if fr.frame == nil {
				return output, nil
			}
			if fr.frame.Type == protocol.FrameControl {
				var resp protocol.Response
				if err := json.Unmarshal(fr.frame.Payload, &resp); err != nil {
					continue
				}
				switch resp.Type {
				case "WatchUpdate":
					if resp.Output != nil {
						output += *resp.Output
					}
					if resp.Done != nil && *resp.Done {
						output += fmt.Sprintf("\n[Session %s]\n", resp.Status)
						return output, nil
					}
				case "Error":
					return "", fmt.Errorf("watch error: %s", resp.Message)
				}
			}

		case <-deadline:
			output += "\n[Watch timeout]\n"
			if len(output) > 500000 {
				output = output[:500000] + "\n... [output truncated to 500KB]"
			}
			return output, nil
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// argUint32 extracts a uint32 argument from the JSON-decoded arguments map.
// JSON numbers arrive as float64.
func argUint32(args map[string]interface{}, key string) (uint32, error) {
	v, ok := args[key].(float64)
	if !ok {
		return 0, fmt.Errorf("missing %s", key)
	}
	return uint32(v), nil
}

// endsWithNewline returns true if data ends with a newline byte.
func endsWithNewline(data []byte) bool {
	return len(data) > 0 && data[len(data)-1] == '\n'
}

// subscribeTimed subscribes to events and collects them for up to maxDurationSecs.
func subscribeTimed(dataDir string, sessionID *uint32, tags, eventTypes []string, maxDurationSecs uint64) (string, error) {
	sockPath := filepath.Join(dataDir, "codewire.sock")
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return "", fmt.Errorf("no node running — start one with: cw node -d\n(socket: %s)", sockPath)
	}
	defer conn.Close()

	reader := connection.NewUnixReader(conn)
	writer := connection.NewUnixWriter(conn)

	req := &protocol.Request{
		Type:       "Subscribe",
		ID:         sessionID,
		Tags:       tags,
		EventTypes: eventTypes,
	}
	if err := writer.SendRequest(req); err != nil {
		return "", err
	}

	deadline := time.After(time.Duration(maxDurationSecs) * time.Second)

	type frameResult struct {
		frame *protocol.Frame
		err   error
	}
	frameCh := make(chan frameResult, 1)
	go func() {
		for {
			f, err := reader.ReadFrame()
			frameCh <- frameResult{f, err}
			if err != nil || f == nil {
				return
			}
		}
	}()

	var events []map[string]interface{}

	for {
		select {
		case fr := <-frameCh:
			if fr.err != nil {
				out, _ := json.MarshalIndent(events, "", "  ")
				return string(out), nil
			}
			if fr.frame == nil {
				out, _ := json.MarshalIndent(events, "", "  ")
				return string(out), nil
			}
			if fr.frame.Type != protocol.FrameControl {
				continue
			}
			var resp protocol.Response
			if err := json.Unmarshal(fr.frame.Payload, &resp); err != nil {
				continue
			}
			switch resp.Type {
			case "SubscribeAck":
				// Subscribed OK.
			case "Event":
				event := map[string]interface{}{}
				if resp.SessionID != nil {
					event["session_id"] = *resp.SessionID
				}
				if resp.Event != nil {
					event["timestamp"] = resp.Event.Timestamp
					event["type"] = resp.Event.EventType
					var data interface{}
					if json.Unmarshal(resp.Event.Data, &data) == nil {
						event["data"] = data
					}
				}
				events = append(events, event)
			case "Error":
				return fmt.Sprintf("Error: %s", resp.Message), nil
			}

		case <-deadline:
			out, _ := json.MarshalIndent(events, "", "  ")
			return string(out), nil
		}
	}
}

// waitForTimed sends a Wait request and blocks for the result.
func waitForTimed(dataDir string, sessionID *uint32, tags []string, condition string, timeoutSecs uint64) (string, error) {
	sockPath := filepath.Join(dataDir, "codewire.sock")
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	reader := connection.NewUnixReader(conn)
	writer := connection.NewUnixWriter(conn)

	req := &protocol.Request{
		Type:           "Wait",
		ID:             sessionID,
		Tags:           tags,
		Condition:      condition,
		TimeoutSeconds: &timeoutSecs,
	}
	if err := writer.SendRequest(req); err != nil {
		return "", err
	}

	// Read frames until we get the WaitResult.
	for {
		f, err := reader.ReadFrame()
		if err != nil {
			return "", err
		}
		if f == nil {
			return "", fmt.Errorf("connection closed before wait result")
		}
		if f.Type != protocol.FrameControl {
			continue
		}
		var resp protocol.Response
		if err := json.Unmarshal(f.Payload, &resp); err != nil {
			continue
		}
		switch resp.Type {
		case "WaitResult":
			if resp.Sessions != nil {
				out, _ := json.MarshalIndent(resp.Sessions, "", "  ")
				return string(out), nil
			}
			return "[]", nil
		case "Error":
			return fmt.Sprintf("Error: %s", resp.Message), nil
		}
	}
}

// loadRelayConfig returns the relay URL from config.
func loadRelayConfig(dataDir string) (string, error) {
	cfg, err := config.LoadConfig(dataDir)
	if err != nil {
		return "", fmt.Errorf("loading config: %w", err)
	}
	if cfg.RelayURL == nil || *cfg.RelayURL == "" {
		return "", fmt.Errorf("relay not configured (run 'cw relay setup <relay-url> [token]' or set CODEWIRE_RELAY_URL)")
	}
	return *cfg.RelayURL, nil
}

// fetchRelayJSON performs a GET request to a relay URL and returns the body.
func fetchRelayJSON(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	body := make([]byte, 0)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return body, nil
}
