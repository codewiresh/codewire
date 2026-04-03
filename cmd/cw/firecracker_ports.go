package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

// forwardPort opens a TCP listener on the host and proxies connections to a guest port
// via Firecracker's vsock UDS.
func forwardPort(hostPort, guestPort int, vsockUDSPath string) (net.Listener, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", hostPort))
	if err != nil {
		return nil, fmt.Errorf("listen on host port %d: %w", hostPort, err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxyConnection(conn, guestPort, vsockUDSPath)
		}
	}()

	return ln, nil
}

func proxyConnection(hostConn net.Conn, guestPort int, vsockUDSPath string) {
	defer hostConn.Close()

	// Connect to guest via Firecracker's vsock UDS + CONNECT handshake
	guestConn, err := net.Dial("unix", vsockUDSPath)
	if err != nil {
		return
	}
	defer guestConn.Close()

	// Firecracker vsock handshake
	connectMsg := fmt.Sprintf("CONNECT %d\n", guestPort)
	if _, err := guestConn.Write([]byte(connectMsg)); err != nil {
		return
	}

	reader := bufio.NewReader(guestConn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	if !strings.HasPrefix(strings.TrimSpace(response), "OK") {
		return
	}

	// Bidirectional proxy
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(guestConn, hostConn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(hostConn, reader) // use reader since we buffered from it
	}()
	wg.Wait()
}
