package guestagent

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// Request types sent from host to guest agent.
type Request struct {
	Type    string   `json:"type"`              // "Exec", "PortForward", "Ping"
	Command []string `json:"command,omitempty"`  // for Exec
	Workdir string   `json:"workdir,omitempty"`  // for Exec
	Port    int      `json:"port,omitempty"`     // for PortForward
}

// Response types sent from guest agent to host.
type Response struct {
	Type     string `json:"type"`               // "Output", "Exit", "Pong", "Error"
	Data     []byte `json:"data,omitempty"`      // stdout/stderr bytes for Output
	Stream   string `json:"stream,omitempty"`    // "stdout" or "stderr"
	ExitCode int    `json:"exit_code,omitempty"` // for Exit
	Message  string `json:"message,omitempty"`   // for Error
}

const maxMessageSize = 4 * 1024 * 1024 // 4 MB

// WriteMessage writes a length-prefixed JSON message to the writer.
func WriteMessage(w io.Writer, msg any) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// ReadMessage reads a length-prefixed JSON message from the reader.
func ReadMessage(r io.Reader, msg any) error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(lenBuf[:])
	if size > maxMessageSize {
		return fmt.Errorf("message too large: %d bytes", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	return json.Unmarshal(data, msg)
}
