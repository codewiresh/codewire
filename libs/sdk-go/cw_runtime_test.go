package codewire

import (
	"bytes"
	"connectrpc.com/connect"
	"context"
	"errors"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	codewirev1connect "github.com/codewiresh/codewire/libs/gen-go/codewire/v1/codewirev1connect"
	"google.golang.org/protobuf/proto"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

type boundedCwReader struct {
	reader io.Reader
	calls  []int
}

type lostCwRuntimeAckTransport struct {
	calls int
	t     *testing.T
}

func (transport *lostCwRuntimeAckTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.calls++
	if request.URL.Path != "/codewire.v1.EnvironmentCwRuntimeService/UpdateEnvironmentCwRuntime" {
		transport.t.Fatal("unexpected route")
	}
	if request.Header.Get("Content-Type") != "application/connect+proto" {
		transport.t.Fatal("runtime must use bounded binary frames")
	}
	deadline, ok := request.Context().Deadline()
	if !ok || time.Until(deadline) > cwRuntimeMutationTimeout {
		transport.t.Fatal("missing bounded mutation deadline")
	}
	size, err := io.Copy(io.Discard, io.LimitReader(request.Body, 200*1024))
	request.Body.Close()
	if err != nil || size == 0 || size >= 200*1024 {
		transport.t.Fatalf("invalid synthetic stream: %d %v", size, err)
	}
	return nil, errors.New("synthetic lost ACK after request EOF")
}

func TestCwRuntimeGeneratedLostAckRetainsOriginalRequestWithoutRetry(t *testing.T) {
	transport := &lostCwRuntimeAckTransport{t: t}
	runtime := &CwRuntime{orgID: "org", envID: "env", client: codewirev1connect.NewEnvironmentCwRuntimeServiceClient(&http.Client{Transport: transport}, "http://in-memory.invalid", connect.WithReadMaxBytes(32*1024))}
	source := &boundedCwReader{reader: bytes.NewReader(make([]byte, 64))}
	_, err := runtime.Update(context.Background(), &codewirev1.UpdateEnvironmentCwRuntimeHeader{OrgId: "org", EnvironmentId: "env", RequestId: "original-request", Identity: &codewirev1.EnvironmentCwRuntimeIdentity{Size: 64}}, source)
	var unknown *CwRuntimeOutcomeUnknownError
	if !errors.As(err, &unknown) || unknown.RequestID != "original-request" || transport.calls != 1 {
		t.Fatalf("lost original request or retried: %d %v", transport.calls, err)
	}
}

func (r *boundedCwReader) Read(p []byte) (int, error) {
	if len(p) > cwRuntimeChunkBytes {
		panic("unbounded read")
	}
	r.calls = append(r.calls, len(p))
	return r.reader.Read(p)
}

type stalledCwReader struct{}

func (stalledCwReader) Read([]byte) (int, error) { return 0, nil }

func TestCwRuntimeCandidateStreamsBoundedExactBytes(t *testing.T) {
	source := &boundedCwReader{reader: bytes.NewReader(bytes.Repeat([]byte{9}, 3*cwRuntimeChunkBytes+7))}
	var chunks []int
	err := streamCwCandidate(source, 3*cwRuntimeChunkBytes+7, func(chunk []byte) error { chunks = append(chunks, len(chunk)); return nil })
	if err != nil || len(chunks) != 4 || chunks[0] != cwRuntimeChunkBytes || chunks[3] != 7 {
		t.Fatalf("bounded chunks: %v %v", chunks, err)
	}
	if source.calls[len(source.calls)-1] != 1 {
		t.Fatal("missing exact EOF probe")
	}
}

func TestCwRuntimeCandidateRejectsShortExtraBoundsAndNoProgress(t *testing.T) {
	for _, src := range []io.Reader{bytes.NewReader(make([]byte, 63)), bytes.NewReader(make([]byte, 65)), stalledCwReader{}} {
		if streamCwCandidate(src, 64, func([]byte) error { return nil }) == nil {
			t.Fatal("invalid reader was accepted")
		}
	}
	for _, size := range []uint64{0, 63, cwRuntimeMaximumBytes + 1} {
		if streamCwCandidate(stalledCwReader{}, size, func([]byte) error { return nil }) == nil {
			t.Fatal("invalid size accepted")
		}
	}
}

func TestCwRuntimeCancelledSendIsNotRetried(t *testing.T) {
	called := 0
	lost := errors.New("synthetic lost transport")
	err := streamCwCandidate(bytes.NewReader(make([]byte, 3*cwRuntimeChunkBytes)), 3*cwRuntimeChunkBytes, func([]byte) error { called++; return lost })
	if !errors.Is(err, lost) || called != 1 {
		t.Fatalf("reissued or hid send: %d %v", called, err)
	}
}

func TestCwRuntimeGeneratedContractPreservesFullUint64AndUnknown(t *testing.T) {
	value := &codewirev1.EnvironmentCwRuntimeOperation{RequestId: "original", Phase: "unknown", ExpectedSelection: &codewirev1.EnvironmentCwRuntimeExpectation{Generation: math.MaxUint64}}
	encoded, err := proto.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded codewirev1.EnvironmentCwRuntimeOperation
	if err := proto.Unmarshal(encoded, &decoded); err != nil || decoded.ExpectedSelection.Generation != math.MaxUint64 || decoded.Phase != "unknown" {
		t.Fatalf("precision or phase: %v", err)
	}
}

func TestCwRuntimeOversizedRollbackRefusesBeforeTransport(t *testing.T) {
	// A nil generated client would panic if the preflight called transport.
	runtime := &CwRuntime{orgID: "org", envID: "env"}
	_, err := runtime.Rollback(context.Background(), &codewirev1.RollbackEnvironmentCwRuntimeRequest{
		OrgId: "org", EnvironmentId: "env", RequestId: "original-request",
		Identity: &codewirev1.EnvironmentCwRuntimeIdentity{PackageVersion: strings.Repeat("x", 32*1024+1)},
	})
	var unknown *CwRuntimeOutcomeUnknownError
	if err == nil || errors.As(err, &unknown) {
		t.Fatalf("invalid local rollback became a transport effect: %v", err)
	}
}
