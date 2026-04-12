//go:build ios || cgotest

package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"time"
	"unsafe"

	"github.com/codewiresh/codewire/internal/envshell"
	"github.com/codewiresh/codewire/internal/platform"
)

// DialConfig is the JSON payload for CwShellDial.
type DialConfig struct {
	ServerURL      string `json:"server_url"`
	Token          string `json:"token"`
	OrgID          string `json:"org_id"`
	EnvID          string `json:"env_id"`
	Cols           uint16 `json:"cols"`
	Rows           uint16 `json:"rows"`
	KnownHostsPath string `json:"known_hosts_path,omitempty"`
}

func main() {} // required for -buildmode=c-archive

// --- C exports ---

//export CwShellDial
func CwShellDial(configJSON *C.char, errOut **C.char) C.int {
	defer recoverPanic(errOut)
	id, err := doDial(C.GoString(configJSON))
	if err != nil {
		setErr(errOut, err.Error())
		return -1
	}
	return C.int(id)
}

//export CwShellRead
func CwShellRead(handle C.int, buf *C.char, n C.int, errOut **C.char) C.int {
	defer recoverPanic(errOut)
	result, err := doRead(int32(handle), unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(n)))
	if err != nil {
		setErr(errOut, err.Error())
		return -1
	}
	return C.int(result)
}

//export CwShellWrite
func CwShellWrite(handle C.int, buf *C.char, n C.int, errOut **C.char) C.int {
	defer recoverPanic(errOut)
	result, err := doWrite(int32(handle), unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(n)))
	if err != nil {
		setErr(errOut, err.Error())
		return -1
	}
	return C.int(result)
}

//export CwShellResize
func CwShellResize(handle C.int, cols, rows C.int, errOut **C.char) C.int {
	defer recoverPanic(errOut)
	if err := doResize(int32(handle), uint16(cols), uint16(rows)); err != nil {
		setErr(errOut, err.Error())
		return -1
	}
	return 0
}

//export CwShellClose
func CwShellClose(handle C.int) {
	defer recoverPanic(nil)
	doClose(int32(handle))
}

//export CwFreeString
func CwFreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

// --- Go-level functions (testable without CGO boundary) ---

// dialForTest is swappable for tests.
var dialForTest = func(ctx context.Context, opts envshell.DialOptions) (envshell.Shell, error) {
	return envshell.Dial(ctx, opts)
}

func doDial(configJSON string) (int32, error) {
	var cfg DialConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return 0, fmt.Errorf("config parse: %w", err)
	}
	client := &platform.Client{
		ServerURL:    cfg.ServerURL,
		SessionToken: cfg.Token,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	shell, err := dialForTest(ctx, envshell.DialOptions{
		Client:         client,
		OrgID:          cfg.OrgID,
		EnvID:          cfg.EnvID,
		InitialCols:    cfg.Cols,
		InitialRows:    cfg.Rows,
		KnownHostsPath: cfg.KnownHostsPath,
	})
	if err != nil {
		cancel()
		return 0, err
	}
	// Replace the timeout context with a cancellable one for the shell's lifetime.
	_, shellCancel := context.WithCancel(context.Background())
	cancel() // release the dial timeout context
	return registerHandle(shell, shellCancel), nil
}

func doRead(id int32, buf []byte) (int, error) {
	h := lookupHandle(id)
	if h == nil {
		return -1, fmt.Errorf("invalid handle")
	}
	return h.shell.Read(buf)
}

func doWrite(id int32, buf []byte) (int, error) {
	h := lookupHandle(id)
	if h == nil {
		return -1, fmt.Errorf("invalid handle")
	}
	return h.shell.Write(buf)
}

func doResize(id int32, cols, rows uint16) error {
	h := lookupHandle(id)
	if h == nil {
		return fmt.Errorf("invalid handle")
	}
	return h.shell.Resize(cols, rows)
}

func doClose(id int32) {
	h := removeHandle(id)
	if h == nil {
		return
	}
	h.cancel()
	_ = h.shell.Close()
}

func setErr(errOut **C.char, msg string) {
	if errOut != nil {
		*errOut = C.CString(msg)
	}
}

func recoverPanic(errOut **C.char) {
	if r := recover(); r != nil {
		setErr(errOut, fmt.Sprintf("go panic: %v\n%s", r, debug.Stack()))
	}
}
