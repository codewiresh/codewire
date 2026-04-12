//go:build cgotest

package main

import (
	"context"
	"io"
	"sync"
	"testing"
)

type stubShell struct {
	closed bool
	readCh chan []byte
	mu     sync.Mutex
}

func (s *stubShell) Read(p []byte) (int, error) {
	data, ok := <-s.readCh
	if !ok {
		return 0, io.EOF
	}
	return copy(p, data), nil
}
func (s *stubShell) Write(p []byte) (int, error) { return len(p), nil }
func (s *stubShell) Resize(c, r uint16) error    { return nil }
func (s *stubShell) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.readCh != nil {
		select {
		case <-s.readCh:
		default:
			close(s.readCh)
		}
	}
	return nil
}

func TestHandleTable_RegisterAndLookup(t *testing.T) {
	shell := &stubShell{readCh: make(chan []byte, 1)}
	_, cancel := context.WithCancel(context.Background())
	id := registerHandle(shell, cancel)
	if id <= 0 {
		t.Fatalf("expected positive id, got %d", id)
	}
	h := lookupHandle(id)
	if h == nil || h.shell != shell {
		t.Error("lookup mismatch")
	}
	removeHandle(id)
	cancel()
}

func TestHandleTable_Remove(t *testing.T) {
	shell := &stubShell{readCh: make(chan []byte, 1)}
	_, cancel := context.WithCancel(context.Background())
	id := registerHandle(shell, cancel)
	removed := removeHandle(id)
	if removed == nil {
		t.Fatal("remove returned nil")
	}
	if lookupHandle(id) != nil {
		t.Error("handle still present after remove")
	}
	cancel()
}

func TestHandleTable_ConcurrentRegister(t *testing.T) {
	var wg sync.WaitGroup
	ids := make([]int32, 100)
	for i := range ids {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s := &stubShell{readCh: make(chan []byte, 1)}
			_, cancel := context.WithCancel(context.Background())
			ids[idx] = registerHandle(s, cancel)
		}(i)
	}
	wg.Wait()
	seen := make(map[int32]bool)
	for _, id := range ids {
		if seen[id] {
			t.Errorf("duplicate id %d", id)
		}
		seen[id] = true
		removeHandle(id)
	}
}
