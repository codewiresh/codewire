package guestagent

import (
	"bytes"
	"testing"
)

func TestWriteReadMessage(t *testing.T) {
	var buf bytes.Buffer
	req := Request{Type: "Exec", Command: []string{"ls", "-la"}, Workdir: "/workspace"}
	if err := WriteMessage(&buf, &req); err != nil {
		t.Fatal(err)
	}

	var got Request
	if err := ReadMessage(&buf, &got); err != nil {
		t.Fatal(err)
	}
	if got.Type != "Exec" || len(got.Command) != 2 || got.Workdir != "/workspace" {
		t.Fatalf("round-trip failed: %+v", got)
	}
}

func TestWriteReadResponse(t *testing.T) {
	var buf bytes.Buffer
	resp := Response{Type: "Output", Data: []byte("hello\n"), Stream: "stdout"}
	if err := WriteMessage(&buf, &resp); err != nil {
		t.Fatal(err)
	}

	var got Response
	if err := ReadMessage(&buf, &got); err != nil {
		t.Fatal(err)
	}
	if got.Type != "Output" || string(got.Data) != "hello\n" || got.Stream != "stdout" {
		t.Fatalf("round-trip failed: %+v", got)
	}
}
