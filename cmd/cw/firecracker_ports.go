package main

import (
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/mdlayher/vsock"
)

// forwardPort opens a TCP listener on the host and proxies connections to a vsock port in the guest.
func forwardPort(hostPort, guestPort int, guestCID uint32) (net.Listener, error) {
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
			go proxyConnection(conn, guestPort, guestCID)
		}
	}()

	return ln, nil
}

func proxyConnection(hostConn net.Conn, guestPort int, guestCID uint32) {
	defer hostConn.Close()

	guestConn, err := vsock.Dial(guestCID, uint32(guestPort), nil)
	if err != nil {
		return
	}
	defer guestConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(guestConn, hostConn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(hostConn, guestConn)
	}()
	wg.Wait()
}
