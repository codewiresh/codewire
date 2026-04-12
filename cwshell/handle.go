//go:build ios || cgotest

package main

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/codewiresh/codewire/internal/envshell"
)

var (
	handles sync.Map
	nextID  int32
)

type shellHandle struct {
	shell  envshell.Shell
	cancel context.CancelFunc
}

func registerHandle(shell envshell.Shell, cancel context.CancelFunc) int32 {
	id := atomic.AddInt32(&nextID, 1)
	handles.Store(id, &shellHandle{shell: shell, cancel: cancel})
	return id
}

func lookupHandle(id int32) *shellHandle {
	v, ok := handles.Load(id)
	if !ok {
		return nil
	}
	return v.(*shellHandle)
}

func removeHandle(id int32) *shellHandle {
	v, ok := handles.LoadAndDelete(id)
	if !ok {
		return nil
	}
	return v.(*shellHandle)
}
