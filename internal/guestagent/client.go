package guestagent

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

const (
	AgentPort  uint32 = 10000
	DefaultCID uint32 = 3
)

// Client connects to the guest agent over Firecracker's vsock UDS.
type Client struct {
	conn net.Conn
}

// DialVsockUDS connects to the guest agent via Firecracker's vsock Unix socket.
// Firecracker exposes guest vsock ports through a UDS with a CONNECT handshake:
// 1. Connect to the Unix socket at udsPath
// 2. Send "CONNECT <port>\n"
// 3. Receive "OK <port>\n"
func DialVsockUDS(udsPath string) (*Client, error) {
	conn, err := net.Dial("unix", udsPath)
	if err != nil {
		return nil, fmt.Errorf("connect to vsock UDS %s: %w", udsPath, err)
	}

	// Firecracker vsock handshake
	connectMsg := fmt.Sprintf("CONNECT %d\n", AgentPort)
	if _, err := conn.Write([]byte(connectMsg)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("vsock CONNECT: %w", err)
	}

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("vsock CONNECT response: %w", err)
	}

	response = strings.TrimSpace(response)
	if !strings.HasPrefix(response, "OK") {
		conn.Close()
		return nil, fmt.Errorf("vsock CONNECT failed: %q", response)
	}

	// The connection is now a transparent pipe to the guest's vsock port.
	// Wrap with the buffered reader since we already consumed from it.
	return &Client{conn: &bufferedConn{Conn: conn, reader: reader}}, nil
}

// bufferedConn wraps a net.Conn with a bufio.Reader for reads
// (since we already consumed the handshake response from the reader).
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Ping checks if the guest agent is alive.
func (c *Client) Ping() error {
	if err := WriteMessage(c.conn, &Request{Type: "Ping"}); err != nil {
		return err
	}
	var resp Response
	if err := ReadMessage(c.conn, &resp); err != nil {
		return err
	}
	if resp.Type != "Pong" {
		return fmt.Errorf("unexpected response: %s", resp.Type)
	}
	return nil
}

// Exec runs a command in the guest and streams output to stdout/stderr.
// Returns the exit code.
func (c *Client) Exec(command []string, workdir string) (int, error) {
	req := Request{
		Type:    "Exec",
		Command: command,
		Workdir: workdir,
	}
	if err := WriteMessage(c.conn, &req); err != nil {
		return 1, fmt.Errorf("send exec request: %w", err)
	}

	for {
		var resp Response
		if err := ReadMessage(c.conn, &resp); err != nil {
			if err == io.EOF {
				return 1, fmt.Errorf("agent connection closed unexpectedly")
			}
			return 1, fmt.Errorf("read response: %w", err)
		}

		switch resp.Type {
		case "Output":
			switch resp.Stream {
			case "stderr":
				os.Stderr.Write(resp.Data)
			default:
				os.Stdout.Write(resp.Data)
			}
		case "Exit":
			return resp.ExitCode, nil
		case "Error":
			return 1, fmt.Errorf("agent error: %s", resp.Message)
		}
	}
}
