package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Frame round-trip tests
// ---------------------------------------------------------------------------

func TestFrameRoundTripControl(t *testing.T) {
	original := &Frame{Type: FrameControl, Payload: []byte(`{"type":"ListSessions"}`)}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, original); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	decoded, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if decoded == nil {
		t.Fatal("ReadFrame returned nil frame")
	}
	if decoded.Type != FrameControl {
		t.Errorf("Type = 0x%02x, want 0x%02x", decoded.Type, FrameControl)
	}
	if !bytes.Equal(decoded.Payload, original.Payload) {
		t.Errorf("Payload = %q, want %q", decoded.Payload, original.Payload)
	}
}

func TestFrameRoundTripData(t *testing.T) {
	original := &Frame{Type: FrameData, Payload: []byte("hello world")}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, original); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	decoded, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if decoded == nil {
		t.Fatal("ReadFrame returned nil frame")
	}
	if decoded.Type != FrameData {
		t.Errorf("Type = 0x%02x, want 0x%02x", decoded.Type, FrameData)
	}
	if !bytes.Equal(decoded.Payload, original.Payload) {
		t.Errorf("Payload = %q, want %q", decoded.Payload, original.Payload)
	}
}

func TestFrameEmptyPayload(t *testing.T) {
	original := &Frame{Type: FrameControl, Payload: []byte{}}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, original); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	decoded, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if decoded == nil {
		t.Fatal("ReadFrame returned nil frame")
	}
	if len(decoded.Payload) != 0 {
		t.Errorf("Payload length = %d, want 0", len(decoded.Payload))
	}
}

func TestFrameWireFormat(t *testing.T) {
	payload := []byte("test")
	f := &Frame{Type: FrameData, Payload: payload}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	wire := buf.Bytes()
	// Header: 1 byte type + 4 bytes length
	if len(wire) != 5+len(payload) {
		t.Fatalf("wire length = %d, want %d", len(wire), 5+len(payload))
	}
	if wire[0] != FrameData {
		t.Errorf("wire[0] = 0x%02x, want 0x%02x", wire[0], FrameData)
	}
	length := binary.BigEndian.Uint32(wire[1:5])
	if length != uint32(len(payload)) {
		t.Errorf("wire length field = %d, want %d", length, len(payload))
	}
	if !bytes.Equal(wire[5:], payload) {
		t.Errorf("wire payload = %q, want %q", wire[5:], payload)
	}
}

// ---------------------------------------------------------------------------
// MaxPayload check
// ---------------------------------------------------------------------------

func TestMaxPayloadReject(t *testing.T) {
	// Construct a frame header with a payload size exceeding MaxPayload.
	var header [5]byte
	header[0] = FrameControl
	binary.BigEndian.PutUint32(header[1:5], MaxPayload+1)

	r := bytes.NewReader(header[:])
	_, err := ReadFrame(r)
	if err == nil {
		t.Fatal("expected error for oversized payload, got nil")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error = %q, want it to contain 'too large'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// EOF handling
// ---------------------------------------------------------------------------

func TestEOFReturnsNilNil(t *testing.T) {
	r := bytes.NewReader([]byte{})
	frame, err := ReadFrame(r)
	if frame != nil {
		t.Errorf("frame = %v, want nil", frame)
	}
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

func TestPartialHeaderEOFReturnsNilNil(t *testing.T) {
	// Partial header (only 3 bytes, need 5).
	r := bytes.NewReader([]byte{0x00, 0x00, 0x00})
	frame, err := ReadFrame(r)
	if frame != nil {
		t.Errorf("frame = %v, want nil", frame)
	}
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

func TestUnknownFrameType(t *testing.T) {
	var header [5]byte
	header[0] = 0xFF
	binary.BigEndian.PutUint32(header[1:5], 0)

	r := bytes.NewReader(header[:])
	_, err := ReadFrame(r)
	if err == nil {
		t.Fatal("expected error for unknown frame type")
	}
	if !strings.Contains(err.Error(), "unknown frame type") {
		t.Errorf("error = %q, want it to contain 'unknown frame type'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Multiple frames in sequence
// ---------------------------------------------------------------------------

func TestMultipleFrames(t *testing.T) {
	frames := []*Frame{
		{Type: FrameControl, Payload: []byte(`{"type":"ListSessions"}`)},
		{Type: FrameData, Payload: []byte("terminal output")},
		{Type: FrameControl, Payload: []byte(`{"type":"Ok"}`)},
	}

	var buf bytes.Buffer
	for _, f := range frames {
		if err := WriteFrame(&buf, f); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
	}

	for i, want := range frames {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame[%d]: %v", i, err)
		}
		if got.Type != want.Type {
			t.Errorf("frame[%d] Type = 0x%02x, want 0x%02x", i, got.Type, want.Type)
		}
		if !bytes.Equal(got.Payload, want.Payload) {
			t.Errorf("frame[%d] Payload = %q, want %q", i, got.Payload, want.Payload)
		}
	}

	// Should get nil after all frames consumed.
	got, err := ReadFrame(&buf)
	if got != nil || err != nil {
		t.Errorf("expected (nil, nil) after all frames, got (%v, %v)", got, err)
	}
}

// ---------------------------------------------------------------------------
// Request JSON serialization (must match Rust serde output)
// ---------------------------------------------------------------------------

func uint32Ptr(v uint32) *uint32 { return &v }
func uint16Ptr(v uint16) *uint16 { return &v }
func boolPtr(v bool) *bool       { return &v }
func uintPtr(v uint) *uint       { return &v }

func TestRequestJSON_ListSessions(t *testing.T) {
	req := Request{Type: "ListSessions"}
	assertJSON(t, req, `{"type":"ListSessions"}`)
}

func TestRequestJSON_Launch(t *testing.T) {
	req := Request{
		Type:       "Launch",
		Command:    []string{"bash"},
		WorkingDir: "/tmp",
	}
	assertJSON(t, req, `{"type":"Launch","command":["bash"],"working_dir":"/tmp"}`)
}

func TestRequestJSON_Attach(t *testing.T) {
	req := Request{
		Type:           "Attach",
		ID:             uint32Ptr(1),
		IncludeHistory: boolPtr(true),
	}
	assertJSON(t, req, `{"type":"Attach","id":1,"include_history":true}`)
}

func TestRequestJSON_Kill(t *testing.T) {
	req := Request{Type: "Kill", ID: uint32Ptr(1)}
	assertJSON(t, req, `{"type":"Kill","id":1}`)
}

func TestRequestJSON_Resize(t *testing.T) {
	req := Request{
		Type: "Resize",
		Cols: uint16Ptr(80),
		Rows: uint16Ptr(24),
	}
	assertJSON(t, req, `{"type":"Resize","cols":80,"rows":24}`)
}

func TestRequestJSON_Logs(t *testing.T) {
	req := Request{
		Type:   "Logs",
		ID:     uint32Ptr(1),
		Follow: boolPtr(false),
	}
	assertJSON(t, req, `{"type":"Logs","id":1,"follow":false}`)
}

func TestRequestJSON_SendInput(t *testing.T) {
	req := Request{
		Type: "SendInput",
		ID:   uint32Ptr(1),
		Data: []byte{104, 101, 108, 108, 111},
	}
	// Go encodes []byte as base64 by default. Rust uses array of ints.
	// Verify it marshals (the format difference is handled at the transport layer).
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	if m["type"] != "SendInput" {
		t.Errorf("type = %v, want SendInput", m["type"])
	}
	if m["id"].(float64) != 1 {
		t.Errorf("id = %v, want 1", m["id"])
	}
	// data field should be present (base64 encoded).
	if _, ok := m["data"]; !ok {
		t.Error("data field missing")
	}
}

func TestRequestJSON_GetStatus(t *testing.T) {
	req := Request{Type: "GetStatus", ID: uint32Ptr(1)}
	assertJSON(t, req, `{"type":"GetStatus","id":1}`)
}

func TestRequestJSON_WatchSession(t *testing.T) {
	req := Request{
		Type:           "WatchSession",
		ID:             uint32Ptr(1),
		IncludeHistory: boolPtr(true),
	}
	assertJSON(t, req, `{"type":"WatchSession","id":1,"include_history":true}`)
}

func TestRequestJSON_Detach(t *testing.T) {
	req := Request{Type: "Detach"}
	assertJSON(t, req, `{"type":"Detach"}`)
}

func TestRequestJSON_KillAll(t *testing.T) {
	req := Request{Type: "KillAll"}
	assertJSON(t, req, `{"type":"KillAll"}`)
}

// ---------------------------------------------------------------------------
// Response JSON serialization (must match Rust serde output)
// ---------------------------------------------------------------------------

func TestResponseJSON_SessionList(t *testing.T) {
	sessions := []SessionInfo{}
	resp := Response{
		Type:     "SessionList",
		Sessions: &sessions,
	}
	assertJSON(t, resp, `{"type":"SessionList","sessions":[]}`)
}

func TestResponseJSON_Launched(t *testing.T) {
	resp := Response{Type: "Launched", ID: uint32Ptr(1)}
	assertJSON(t, resp, `{"type":"Launched","id":1}`)
}

func TestResponseJSON_Attached(t *testing.T) {
	resp := Response{Type: "Attached", ID: uint32Ptr(1)}
	assertJSON(t, resp, `{"type":"Attached","id":1}`)
}

func TestResponseJSON_Detached(t *testing.T) {
	resp := Response{Type: "Detached"}
	assertJSON(t, resp, `{"type":"Detached"}`)
}

func TestResponseJSON_Killed(t *testing.T) {
	resp := Response{Type: "Killed", ID: uint32Ptr(1)}
	assertJSON(t, resp, `{"type":"Killed","id":1}`)
}

func TestResponseJSON_KilledAll(t *testing.T) {
	resp := Response{Type: "KilledAll", Count: uintPtr(3)}
	assertJSON(t, resp, `{"type":"KilledAll","count":3}`)
}

func TestResponseJSON_Resized(t *testing.T) {
	resp := Response{Type: "Resized"}
	assertJSON(t, resp, `{"type":"Resized"}`)
}

func TestResponseJSON_LogData(t *testing.T) {
	done := true
	resp := Response{Type: "LogData", Data: "hello", Done: &done}
	assertJSON(t, resp, `{"type":"LogData","data":"hello","done":true}`)
}

func TestResponseJSON_InputSent(t *testing.T) {
	resp := Response{Type: "InputSent", ID: uint32Ptr(1), Bytes: uintPtr(5)}
	assertJSON(t, resp, `{"type":"InputSent","id":1,"bytes":5}`)
}

func TestResponseJSON_SessionStatus(t *testing.T) {
	info := SessionInfo{
		ID:         1,
		Prompt:     "$ ",
		WorkingDir: "/home/user",
		CreatedAt:  "2025-01-01T00:00:00Z",
		Status:     "running",
		Attached:   false,
	}
	outputSize := uint64(1234)
	resp := Response{
		Type:       "SessionStatus",
		Info:       &info,
		OutputSize: &outputSize,
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	if m["type"] != "SessionStatus" {
		t.Errorf("type = %v, want SessionStatus", m["type"])
	}
	if m["output_size"].(float64) != 1234 {
		t.Errorf("output_size = %v, want 1234", m["output_size"])
	}
	infoMap := m["info"].(map[string]any)
	if infoMap["id"].(float64) != 1 {
		t.Errorf("info.id = %v, want 1", infoMap["id"])
	}
}

func TestResponseJSON_WatchUpdate(t *testing.T) {
	output := "hello"
	done := false
	resp := Response{
		Type:   "WatchUpdate",
		ID:     uint32Ptr(1),
		Status: "running",
		Output: &output,
		Done:   &done,
	}
	assertJSON(t, resp, `{"type":"WatchUpdate","id":1,"done":false,"status":"running","output":"hello"}`)
}

func TestResponseJSON_Error(t *testing.T) {
	resp := Response{Type: "Error", Message: "not found"}
	assertJSON(t, resp, `{"type":"Error","message":"not found"}`)
}

func TestResponseJSON_Ok(t *testing.T) {
	resp := Response{Type: "Ok"}
	assertJSON(t, resp, `{"type":"Ok"}`)
}

// ---------------------------------------------------------------------------
// Request UnmarshalJSON: include_history defaults
// ---------------------------------------------------------------------------

func TestRequestUnmarshal_AttachMissingIncludeHistory(t *testing.T) {
	input := `{"type":"Attach","id":1}`
	var req Request
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if req.Type != "Attach" {
		t.Errorf("Type = %q, want Attach", req.Type)
	}
	if req.IncludeHistory == nil {
		t.Fatal("IncludeHistory should not be nil (should default to true)")
	}
	if *req.IncludeHistory != true {
		t.Errorf("IncludeHistory = %v, want true", *req.IncludeHistory)
	}
}

func TestRequestUnmarshal_AttachExplicitFalse(t *testing.T) {
	input := `{"type":"Attach","id":1,"include_history":false}`
	var req Request
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if req.IncludeHistory == nil {
		t.Fatal("IncludeHistory should not be nil")
	}
	if *req.IncludeHistory != false {
		t.Errorf("IncludeHistory = %v, want false", *req.IncludeHistory)
	}
}

func TestRequestUnmarshal_AttachExplicitTrue(t *testing.T) {
	input := `{"type":"Attach","id":1,"include_history":true}`
	var req Request
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if req.IncludeHistory == nil {
		t.Fatal("IncludeHistory should not be nil")
	}
	if *req.IncludeHistory != true {
		t.Errorf("IncludeHistory = %v, want true", *req.IncludeHistory)
	}
}

func TestRequestUnmarshal_NonAttachDoesNotDefault(t *testing.T) {
	input := `{"type":"ListSessions"}`
	var req Request
	if err := json.Unmarshal([]byte(input), &req); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if req.IncludeHistory != nil {
		t.Errorf("IncludeHistory = %v, want nil for non-Attach", *req.IncludeHistory)
	}
}

// ---------------------------------------------------------------------------
// SessionInfo serialization with optional fields
// ---------------------------------------------------------------------------

func TestSessionInfoJSON_WithOptionalFields(t *testing.T) {
	pid := uint32(12345)
	size := uint64(4096)
	snippet := "$ ls\n"
	lastEventAt := "2026-05-03T15:24:11Z"
	idleSeconds := int64(47)
	lastEventPreview := "turn/completed"
	lastEvent := "{\"jsonrpc\":\"2.0\"}"
	info := SessionInfo{
		ID:                1,
		Prompt:            "$ ",
		WorkingDir:        "/home/user",
		CreatedAt:         "2025-01-01T00:00:00Z",
		Status:            "running",
		Attached:          true,
		PID:               &pid,
		OutputSizeBytes:   &size,
		LastOutputSnippet: &snippet,
		LastEventAt:       &lastEventAt,
		IdleSeconds:       &idleSeconds,
		LastEventPreview:  &lastEventPreview,
		LastEvent:         &lastEvent,
	}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)

	if m["pid"].(float64) != 12345 {
		t.Errorf("pid = %v, want 12345", m["pid"])
	}
	if m["output_size_bytes"].(float64) != 4096 {
		t.Errorf("output_size_bytes = %v, want 4096", m["output_size_bytes"])
	}
	if m["last_output_snippet"] != "$ ls\n" {
		t.Errorf("last_output_snippet = %v, want '$ ls\\n'", m["last_output_snippet"])
	}
	if m["last_event_at"] != "2026-05-03T15:24:11Z" {
		t.Errorf("last_event_at = %v, want 2026-05-03T15:24:11Z", m["last_event_at"])
	}
	if m["idle_seconds"].(float64) != 47 {
		t.Errorf("idle_seconds = %v, want 47", m["idle_seconds"])
	}
	if m["last_event_preview"] != "turn/completed" {
		t.Errorf("last_event_preview = %v, want turn/completed", m["last_event_preview"])
	}
	if m["last_event"] != "{\"jsonrpc\":\"2.0\"}" {
		t.Errorf("last_event = %v, want JSON blob", m["last_event"])
	}
}

func TestSessionInfoJSON_WithoutOptionalFields(t *testing.T) {
	info := SessionInfo{
		ID:         2,
		Prompt:     "% ",
		WorkingDir: "/tmp",
		CreatedAt:  "2025-06-01T12:00:00Z",
		Status:     "exited",
		Attached:   false,
	}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)

	// Optional fields should be absent.
	if _, ok := m["pid"]; ok {
		t.Error("pid should be omitted when nil")
	}
	if _, ok := m["output_size_bytes"]; ok {
		t.Error("output_size_bytes should be omitted when nil")
	}
	if _, ok := m["last_output_snippet"]; ok {
		t.Error("last_output_snippet should be omitted when nil")
	}
	if _, ok := m["last_event_at"]; ok {
		t.Error("last_event_at should be omitted when nil")
	}
	if _, ok := m["idle_seconds"]; ok {
		t.Error("idle_seconds should be omitted when nil")
	}
	if _, ok := m["last_event_preview"]; ok {
		t.Error("last_event_preview should be omitted when nil")
	}
	if _, ok := m["last_event"]; ok {
		t.Error("last_event should be omitted when nil")
	}
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

// assertJSON marshals v and checks that the resulting JSON object has exactly
// the same keys and values as the expected JSON string. This comparison is
// order-independent (uses map comparison).
func assertJSON(t *testing.T, v any, expected string) {
	t.Helper()
	got, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var gotMap, wantMap map[string]any
	if err := json.Unmarshal(got, &gotMap); err != nil {
		t.Fatalf("Unmarshal got: %v", err)
	}
	if err := json.Unmarshal([]byte(expected), &wantMap); err != nil {
		t.Fatalf("Unmarshal expected: %v", err)
	}

	// Compare key-by-key for clearer error messages.
	for k, wv := range wantMap {
		gv, ok := gotMap[k]
		if !ok {
			t.Errorf("missing key %q in output; got: %s", k, string(got))
			continue
		}
		wj, _ := json.Marshal(wv)
		gj, _ := json.Marshal(gv)
		if string(wj) != string(gj) {
			t.Errorf("key %q: got %s, want %s; full output: %s", k, gj, wj, string(got))
		}
	}
	for k := range gotMap {
		if _, ok := wantMap[k]; !ok {
			t.Errorf("unexpected key %q in output; got: %s", k, string(got))
		}
	}
}
