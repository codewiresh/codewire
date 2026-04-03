package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/codewiresh/codewire/internal/guestagent"
	"github.com/mdlayher/vsock"
)

const agentPort = 10000

func main() {
	ln, err := vsock.Listen(agentPort, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cw-guest-agent: listen vsock port %d: %v\n", agentPort, err)
		os.Exit(1)
	}
	defer ln.Close()

	fmt.Fprintf(os.Stderr, "cw-guest-agent: listening on vsock port %d\n", agentPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cw-guest-agent: accept: %v\n", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn io.ReadWriteCloser) {
	defer conn.Close()

	for {
		var req guestagent.Request
		if err := guestagent.ReadMessage(conn, &req); err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "cw-guest-agent: read: %v\n", err)
			}
			return
		}

		switch req.Type {
		case "Ping":
			guestagent.WriteMessage(conn, &guestagent.Response{Type: "Pong"})
		case "Exec":
			handleExec(conn, &req)
		default:
			guestagent.WriteMessage(conn, &guestagent.Response{
				Type:    "Error",
				Message: fmt.Sprintf("unknown request type: %s", req.Type),
			})
		}
	}
}

func handleExec(conn io.Writer, req *guestagent.Request) {
	if len(req.Command) == 0 {
		guestagent.WriteMessage(conn, &guestagent.Response{
			Type: "Error", Message: "empty command",
		})
		return
	}

	cmd := exec.Command(req.Command[0], req.Command[1:]...)
	if req.Workdir != "" {
		cmd.Dir = req.Workdir
	}
	env := os.Environ()
	hasPath := false
	for _, e := range env {
		if len(e) > 5 && e[:5] == "PATH=" {
			hasPath = true
			break
		}
	}
	if !hasPath {
		env = append(env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}
	cmd.Env = env

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		guestagent.WriteMessage(conn, &guestagent.Response{
			Type: "Error", Message: fmt.Sprintf("start: %v", err),
		})
		return
	}

	done := make(chan struct{}, 2)
	stream := func(r io.Reader, name string) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				guestagent.WriteMessage(conn, &guestagent.Response{
					Type:   "Output",
					Data:   buf[:n],
					Stream: name,
				})
			}
			if err != nil {
				return
			}
		}
	}

	go stream(stdout, "stdout")
	go stream(stderr, "stderr")

	<-done
	<-done

	exitCode := 0
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	guestagent.WriteMessage(conn, &guestagent.Response{
		Type:     "Exit",
		ExitCode: exitCode,
	})
}
