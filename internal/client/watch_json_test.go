package client

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWatchJSONWriterWrapsRawTextLines(t *testing.T) {
	var out bytes.Buffer
	writer, err := newWatchJSONWriter(&out, "")
	if err != nil {
		t.Fatalf("newWatchJSONWriter: %v", err)
	}

	if err := writer.WriteChunk("hello\nworld\n"); err != nil {
		t.Fatalf("WriteChunk: %v", err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}

	for i, want := range []string{"hello", "world"} {
		var got map[string]any
		if err := json.Unmarshal([]byte(lines[i]), &got); err != nil {
			t.Fatalf("Unmarshal[%d]: %v", i, err)
		}
		if got["stream"] != "stdout" {
			t.Fatalf("stream[%d] = %v, want stdout", i, got["stream"])
		}
		if got["text"] != want {
			t.Fatalf("text[%d] = %v, want %q", i, got["text"], want)
		}
		if _, ok := got["timestamp"].(string); !ok {
			t.Fatalf("timestamp[%d] missing from %#v", i, got)
		}
	}
}

func TestWatchJSONWriterPassesThroughJSONAndAppliesFilter(t *testing.T) {
	var out bytes.Buffer
	writer, err := newWatchJSONWriter(&out, ".method")
	if err != nil {
		t.Fatalf("newWatchJSONWriter: %v", err)
	}

	if err := writer.WriteChunk("{\"jsonrpc\":\"2.0\",\"method\":\"turn/started\""); err != nil {
		t.Fatalf("WriteChunk[0]: %v", err)
	}
	if err := writer.WriteChunk("}\nplain text\n"); err != nil {
		t.Fatalf("WriteChunk[1]: %v", err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	got := strings.TrimSpace(out.String())
	if got != `"turn/started"` {
		t.Fatalf("output = %q, want %q", got, `"turn/started"`)
	}
}

func TestParseWatchFilterSupportsNestedPathsAndIndexes(t *testing.T) {
	tokens, err := parseWatchFilter(".items[1].id")
	if err != nil {
		t.Fatalf("parseWatchFilter: %v", err)
	}

	value, ok := applyWatchFilter(map[string]any{
		"items": []any{
			map[string]any{"id": "first"},
			map[string]any{"id": "second"},
		},
	}, tokens)
	if !ok {
		t.Fatal("applyWatchFilter returned false")
	}
	if value != "second" {
		t.Fatalf("value = %#v, want second", value)
	}
}
