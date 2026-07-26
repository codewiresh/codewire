package interop_test

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"
	testingv1 "github.com/codewiresh/codewire/libs/gen-go/codewire/testing/v1"
	"github.com/codewiresh/codewire/libs/gen-go/codewire/testing/v1/testingv1connect"
)

// TestGeneratedClientConsumesRustConnect is the bounded supported-consumer
// smoke. The Rust harness supplies a real listener; an unset URL keeps an
// ordinary standalone module test hermetic and makes the selected harness the
// only place this cross-language proof executes.
func TestGeneratedClientConsumesRustConnect(t *testing.T) {
	baseURL := os.Getenv("CODEWIRE_GO_INTEROP_BASE_URL")
	if baseURL == "" {
		t.Skip("CODEWIRE_GO_INTEROP_BASE_URL is set by the Rust interop harness")
	}

	// Keep this supported-consumer probe isolated from the process-global
	// http.DefaultTransport pool. It remains the normal Go transport (including
	// connection reuse), but another test cannot leave a stale idle connection
	// for this stream to inherit.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(transport.CloseIdleConnections)
	client := testingv1connect.NewPingServiceClient(&http.Client{Transport: transport}, baseURL)

	newContext := func(t *testing.T) context.Context {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		return ctx
	}

	t.Run("unary", func(t *testing.T) {
		response, err := client.PublicPing(
			newContext(t),
			connect.NewRequest(&testingv1.PublicPingRequest{}),
		)
		if err != nil {
			t.Fatalf("PublicPing: %v", err)
		}
		if got, want := response.Msg.GetMessage(), "public pong"; got != want {
			t.Fatalf("PublicPing message = %q, want %q", got, want)
		}
	})

	t.Run("canonical_error", func(t *testing.T) {
		_, err := client.Ping(
			newContext(t),
			connect.NewRequest(&testingv1.PingRequest{Message: "whoami"}),
		)
		if got, want := connect.CodeOf(err), connect.CodeUnauthenticated; got != want {
			t.Fatalf("Ping code = %v, want %v (error: %v)", got, want, err)
		}
	})

	t.Run("server_stream", func(t *testing.T) {
		stream, err := client.StreamPing(
			newContext(t),
			connect.NewRequest(&testingv1.StreamPingRequest{}),
		)
		if err != nil {
			t.Fatalf("StreamPing: %v", err)
		}

		var sequences []uint32
		for stream.Receive() {
			message := stream.Msg()
			if got, want := message.GetTotal(), uint32(5); got != want {
				t.Fatalf("StreamPing total = %d, want %d", got, want)
			}
			sequences = append(sequences, message.GetSequence())
		}
		if err := stream.Err(); err != nil {
			t.Fatalf("StreamPing receive after sequences %v: %v", sequences, err)
		}
		want := []uint32{0, 1, 2, 3, 4}
		if len(sequences) != len(want) {
			t.Fatalf("StreamPing sequences = %v, want %v", sequences, want)
		}
		for index := range want {
			if sequences[index] != want[index] {
				t.Fatalf("StreamPing sequences = %v, want %v", sequences, want)
			}
		}
	})
}
