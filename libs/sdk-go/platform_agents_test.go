package codewire

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"net/http"
	"testing"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	codewirev1connect "github.com/codewiresh/codewire/libs/gen-go/codewire/v1/codewirev1connect"
	"google.golang.org/protobuf/proto"
)

const syntheticAgentRequest = "6a162b2b-a758-4c8c-bccb-794502c82f09"

func syntheticAgentScope() *codewirev1.EnvironmentAgentScope {
	return &codewirev1.EnvironmentAgentScope{Incarnation: &codewirev1.EnvironmentCwRuntimeIncarnation{
		OrgId: "org", EnvironmentId: "env", PodUid: "original-pod", BindingGeneration: math.MaxUint64},
		SupportImageSha256: bytes.Repeat([]byte{7}, 32), SupportImageSize: 123}
}

func syntheticAgentMutation() *codewirev1.MutateEnvironmentAgentRequest {
	return &codewirev1.MutateEnvironmentAgentRequest{OrgId: "org", EnvironmentId: "env", RequestId: syntheticAgentRequest,
		ExpectedScope: syntheticAgentScope(), Operation: &codewirev1.MutateEnvironmentAgentRequest_Control{Control: &codewirev1.EnvironmentAgentControl{
			Action: codewirev1.EnvironmentAgentAction_ENVIRONMENT_AGENT_ACTION_STOP, SessionId: "session", DriverId: "driver", ExpectedLaunchGeneration: math.MaxUint64}}}
}

type syntheticAgentTransport struct {
	t     *testing.T
	mode  string
	calls []string
}

func (s *syntheticAgentTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	s.calls = append(s.calls, request.URL.Path)
	raw, err := io.ReadAll(io.LimitReader(request.Body, 256*1024+1))
	request.Body.Close()
	if err != nil || len(raw) > 256*1024 {
		s.t.Fatalf("request bound: %v", err)
	}
	var result proto.Message
	switch request.URL.Path {
	case "/codewire.v1.EnvironmentAgentService/MutateEnvironmentAgent":
		var value codewirev1.MutateEnvironmentAgentRequest
		if err := proto.Unmarshal(raw, &value); err != nil {
			s.t.Fatal(err)
		}
		if value.GetControl().ExpectedLaunchGeneration != math.MaxUint64 || value.ExpectedScope.Incarnation.BindingGeneration != math.MaxUint64 {
			s.t.Fatal("uint64 changed in generated wire")
		}
		if s.mode == "lost" {
			return nil, errors.New("synthetic lost response after dispatch")
		}
		op := &codewirev1.EnvironmentAgentOperation{RequestId: value.RequestId, Scope: value.ExpectedScope, Phase: codewirev1.EnvironmentAgentPhase_ENVIRONMENT_AGENT_PHASE_UNKNOWN}
		if s.mode == "wrong-id" {
			op.RequestId = "6d370dab-3d67-4d76-93c3-3bd31581fbe9"
		}
		if s.mode == "wrong-scope" {
			op.Scope.Incarnation.PodUid = "replacement-pod"
		}
		result = &codewirev1.MutateEnvironmentAgentResponse{Operation: op}
	case "/codewire.v1.EnvironmentAgentService/ObserveEnvironmentAgent":
		var value codewirev1.ObserveEnvironmentAgentRequest
		if err := proto.Unmarshal(raw, &value); err != nil {
			s.t.Fatal(err)
		}
		result = &codewirev1.ObserveEnvironmentAgentResponse{Operation: &codewirev1.EnvironmentAgentOperation{
			RequestId: value.RequestId, Scope: syntheticAgentScope(), Phase: codewirev1.EnvironmentAgentPhase_ENVIRONMENT_AGENT_PHASE_UNKNOWN}}
	case "/codewire.v1.EnvironmentAgentService/ReadEnvironmentAgent":
		var value codewirev1.ReadEnvironmentAgentRequest
		if err := proto.Unmarshal(raw, &value); err != nil {
			s.t.Fatal(err)
		}
		data := []byte(`{"record":"synthetic"}`)
		digest := sha256.Sum256(data)
		r := &codewirev1.ReadEnvironmentAgentResponse{Scope: value.ExpectedScope, SessionId: value.SessionId, DriverId: value.DriverId,
			LaunchGeneration: value.ExpectedLaunchGeneration, Kind: value.Kind, MessageId: value.MessageId, RecordJson: data, RecordSha256: digest[:]}
		if s.mode == "wrong-generation" {
			r.LaunchGeneration--
		}
		if s.mode == "wrong-digest" {
			r.RecordJson = append(r.RecordJson, ' ')
		}
		result = r
	default:
		s.t.Fatal("unexpected agent route")
	}
	encoded, err := proto.Marshal(result)
	if err != nil {
		s.t.Fatal(err)
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/proto"}}, Body: io.NopCloser(bytes.NewReader(encoded))}, nil
}

func syntheticAgents(t *testing.T, mode string) (*PlatformAgents, *syntheticAgentTransport) {
	transport := &syntheticAgentTransport{t: t, mode: mode}
	return &PlatformAgents{orgID: "org", envID: "env", client: codewirev1connect.NewEnvironmentAgentServiceClient(
		&http.Client{Transport: transport}, "http://in-memory.invalid", connect.WithReadMaxBytes(platformAgentRecordBytes+32*1024))}, transport
}

func TestPlatformAgentsLostReplyKeepsOriginalUUIDForObserveWithoutRetry(t *testing.T) {
	a, transport := syntheticAgents(t, "lost")
	_, err := a.Mutate(context.Background(), syntheticAgentMutation())
	var unknown *PlatformAgentOutcomeUnknownError
	if !errors.As(err, &unknown) || unknown.RequestID != syntheticAgentRequest {
		t.Fatalf("lost original request: %v", err)
	}
	op, err := a.Observe(context.Background(), unknown.RequestID)
	if err != nil || op.Phase != codewirev1.EnvironmentAgentPhase_ENVIRONMENT_AGENT_PHASE_UNKNOWN || len(transport.calls) != 2 {
		t.Fatalf("observe or retry: %v %v", transport.calls, err)
	}
}

func TestPlatformAgentsWrongOriginalUUIDOrPodDoesNotRetry(t *testing.T) {
	for _, mode := range []string{"wrong-id", "wrong-scope"} {
		t.Run(mode, func(t *testing.T) {
			a, transport := syntheticAgents(t, mode)
			_, err := a.Mutate(context.Background(), syntheticAgentMutation())
			var unknown *PlatformAgentOutcomeUnknownError
			if !errors.As(err, &unknown) || unknown.RequestID != syntheticAgentRequest || len(transport.calls) != 1 {
				t.Fatalf("wrong response accepted or retried: %v", err)
			}
		})
	}
}

func TestPlatformAgentsScopeAndSizeRefusalPrecedesTransport(t *testing.T) {
	for _, mode := range []string{"scope", "id", "bound"} {
		t.Run(mode, func(t *testing.T) {
			a, transport := syntheticAgents(t, "")
			r := syntheticAgentMutation()
			if mode == "scope" {
				r.ExpectedScope.Incarnation.EnvironmentId = "other"
			}
			if mode == "id" {
				r.RequestId = "invalid"
			}
			if mode == "bound" {
				r.GetControl().Text = string(bytes.Repeat([]byte{'x'}, 256*1024))
			}
			_, err := a.Mutate(context.Background(), r)
			if err == nil || len(transport.calls) != 0 {
				t.Fatalf("preflight had effects: %v", err)
			}
		})
	}
}

func TestPlatformAgentsReadRejectsGenerationAndDigestChanges(t *testing.T) {
	for _, mode := range []string{"ok", "wrong-generation", "wrong-digest"} {
		t.Run(mode, func(t *testing.T) {
			a, _ := syntheticAgents(t, mode)
			r, err := a.Read(context.Background(), &codewirev1.ReadEnvironmentAgentRequest{
				OrgId: "org", EnvironmentId: "env", ExpectedScope: syntheticAgentScope(), SessionId: "session", DriverId: "driver",
				ExpectedLaunchGeneration: math.MaxUint64, Kind: codewirev1.EnvironmentAgentRecordKind_ENVIRONMENT_AGENT_RECORD_KIND_MESSAGE, MessageId: syntheticAgentRequest})
			if mode != "ok" {
				if err == nil {
					t.Fatal("changed generation or digest accepted")
				}
				return
			}
			if err != nil || r.LaunchGeneration != math.MaxUint64 || r.Scope.Incarnation.BindingGeneration != math.MaxUint64 {
				t.Fatalf("lossless read: %v", err)
			}
		})
	}
}
