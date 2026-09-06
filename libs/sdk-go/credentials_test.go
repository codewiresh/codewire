package codewire_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	codewire "codewire.sh/sdk-go"
	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	codewirev1connect "github.com/codewiresh/codewire/libs/gen-go/codewire/v1/codewirev1connect"
	"google.golang.org/protobuf/proto"
)

const credentialExact uint64 = 9_007_199_254_741_009

type credentialFixture struct {
	codewirev1connect.UnimplementedCredentialServiceHandler
	codewirev1connect.UnimplementedCredentialMutationServiceHandler
	t         *testing.T
	mu        sync.Mutex
	requests  []proto.Message
	methods   []string
	commit    chan struct{}
	cancelled chan struct{}
}

func credentialProto() *codewirev1.Credential {
	maximum := ^uint64(0)
	return &codewirev1.Credential{Id: "credential-one", Name: "personal", Provider: "openai",
		AuthenticationKind: codewirev1.CredentialAuthenticationKind_CREDENTIAL_AUTHENTICATION_KIND_OAUTH,
		Status:             codewirev1.CredentialStatus_CREDENTIAL_STATUS_ACTIVE,
		ExpiresAtUnix:      &maximum, RevocationGeneration: credentialExact}
}

func (f *credentialFixture) record(method string, message proto.Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if message.ProtoReflect().Descriptor().Fields().ByName("org_id") != nil {
		f.t.Error("personal credentials must not inherit organization scope")
	}
	f.requests = append(f.requests, proto.Clone(message))
	f.methods = append(f.methods, method)
}

func (f *credentialFixture) last() proto.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return proto.Clone(f.requests[len(f.requests)-1])
}

func (f *credentialFixture) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *credentialFixture) ListCredentials(_ context.Context, req *connect.Request[codewirev1.ListCredentialsRequest]) (*connect.Response[codewirev1.ListCredentialsResponse], error) {
	f.record("ListCredentials", req.Msg)
	next := ""
	if req.Msg.PageToken == "" {
		next = "page-two"
	}
	return connect.NewResponse(&codewirev1.ListCredentialsResponse{Credentials: []*codewirev1.Credential{credentialProto()}, NextPageToken: next}), nil
}

func (f *credentialFixture) GetCredential(_ context.Context, req *connect.Request[codewirev1.GetCredentialRequest]) (*connect.Response[codewirev1.GetCredentialResponse], error) {
	f.record("GetCredential", req.Msg)
	if req.Msg.GetCredentialId() == "missing" {
		return connect.NewResponse(&codewirev1.GetCredentialResponse{}), nil
	}
	value := credentialProto()
	statuses := map[string]codewirev1.CredentialStatus{
		"revoked":        codewirev1.CredentialStatus_CREDENTIAL_STATUS_REVOKED,
		"expired":        codewirev1.CredentialStatus_CREDENTIAL_STATUS_EXPIRED,
		"refresh_failed": codewirev1.CredentialStatus_CREDENTIAL_STATUS_REFRESH_FAILED,
	}
	if status, ok := statuses[req.Msg.GetName()]; ok {
		value.Status = status
	}
	return connect.NewResponse(&codewirev1.GetCredentialResponse{Credential: value}), nil
}

func (f *credentialFixture) RevokeCredential(_ context.Context, req *connect.Request[codewirev1.RevokeCredentialRequest]) (*connect.Response[codewirev1.RevokeCredentialResponse], error) {
	f.record("RevokeCredential", req.Msg)
	if req.Msg.CredentialId == "stale" {
		return nil, connect.NewError(connect.CodeAborted, errors.New("stale revision"))
	}
	value := credentialProto()
	value.Status = codewirev1.CredentialStatus_CREDENTIAL_STATUS_REVOKED
	return connect.NewResponse(&codewirev1.RevokeCredentialResponse{Credential: value}), nil
}

func (f *credentialFixture) DeleteCredential(_ context.Context, req *connect.Request[codewirev1.DeleteCredentialRequest]) (*connect.Response[codewirev1.DeleteCredentialResponse], error) {
	f.record("DeleteCredential", req.Msg)
	return connect.NewResponse(&codewirev1.DeleteCredentialResponse{}), nil
}

func (f *credentialFixture) EnrollCodex(ctx context.Context, req *connect.Request[codewirev1.EnrollCodexRequest], stream *connect.ServerStream[codewirev1.EnrollCodexResponse]) error {
	f.record("EnrollCodex", req.Msg)
	if req.Msg.ProtoReflect().Descriptor().Fields().Len() != 1 {
		f.t.Error("enrollment must send only its name")
	}
	deadline, err := strconv.ParseInt(req.Header().Get("Connect-Timeout-Ms"), 10, 64)
	if err != nil || deadline <= 900_000 || deadline > 960_000 {
		f.t.Errorf("unexpected enrollment timeout: %d (%v)", deadline, err)
	}
	challenge := &codewirev1.EnrollCodexResponse{Event: &codewirev1.EnrollCodexResponse_Challenge{
		Challenge: &codewirev1.CodexDeviceChallenge{VerificationUrl: "https://auth.openai.com/codex/device", UserCode: "SYNTHETIC-CODE", ExpiresAtUnix: ^uint64(0)},
	}}
	if err := stream.Send(challenge); err != nil {
		return err
	}
	switch req.Msg.Name {
	case "success":
		select {
		case <-f.commit:
		case <-ctx.Done():
			return ctx.Err()
		}
		return stream.Send(&codewirev1.EnrollCodexResponse{Event: &codewirev1.EnrollCodexResponse_Credential{Credential: credentialProto()}})
	case "error":
		return connect.NewError(connect.CodeUnavailable, errors.New("synthetic unavailable"))
	case "duplicate":
		return stream.Send(challenge)
	case "cancel", "callback-error":
		<-ctx.Done()
		select {
		case f.cancelled <- struct{}{}:
		default:
		}
		return ctx.Err()
	default:
		return nil
	}
}

func newCredentialFixture(t *testing.T) (*credentialFixture, *httptest.Server) {
	t.Helper()
	f := &credentialFixture{t: t, commit: make(chan struct{}), cancelled: make(chan struct{}, 1)}
	mux := http.NewServeMux()
	metadataPath, metadata := codewirev1connect.NewCredentialServiceHandler(f)
	mutationPath, mutations := codewirev1connect.NewCredentialMutationServiceHandler(f)
	mux.Handle(metadataPath, metadata)
	mux.Handle(mutationPath, mutations)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-opaque-oauth" {
			t.Error("missing original account bearer")
		}
		if !strings.HasPrefix(r.URL.Path, "/codewire.v1.Credential") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return f, server
}

func TestCredentialsMetadataAndExactLifecycle(t *testing.T) {
	f, server := newCredentialFixture(t)
	c := codewire.New("synthetic-opaque-oauth", codewire.WithBaseURL(server.URL), codewire.WithHTTPClient(server.Client()))
	ctx := context.Background()
	values, err := c.Credentials.List(ctx)
	if err != nil || len(values) != 2 {
		t.Fatalf("list: %v %v", values, err)
	}
	if values[0].RevocationGeneration != credentialExact || values[0].ExpiresAtUnix == nil || *values[0].ExpiresAtUnix != ^uint64(0) || values[0].AccountHint != nil {
		t.Fatal("lossy or incorrect optional metadata")
	}
	if _, err = c.Credentials.Get(ctx, "credential-one"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.last().(*codewirev1.GetCredentialRequest).Selector.(*codewirev1.GetCredentialRequest_CredentialId); !ok {
		t.Fatal("ID selector was guessed")
	}
	for _, status := range []string{"expired", "refresh_failed", "revoked"} {
		value, err := c.Credentials.GetByName(ctx, status)
		if err != nil || value.Status != status {
			t.Fatalf("status %s: %v %v", status, value, err)
		}
		if _, ok := f.last().(*codewirev1.GetCredentialRequest).Selector.(*codewirev1.GetCredentialRequest_Name); !ok {
			t.Fatal("name selector was guessed")
		}
	}
	value, err := c.Credentials.Revoke(ctx, "credential-one", credentialExact)
	if err != nil || value.Status != "revoked" || f.last().(*codewirev1.RevokeCredentialRequest).ExpectedRevocationGeneration != credentialExact {
		t.Fatalf("revoke: %v %v", value, err)
	}
	if err := c.Credentials.Delete(ctx, "credential-one", ^uint64(0)); err != nil {
		t.Fatal(err)
	}
	if f.last().(*codewirev1.DeleteCredentialRequest).ExpectedRevocationGeneration != ^uint64(0) {
		t.Fatal("lossy revision")
	}
	before := f.count()
	if _, err := c.Credentials.Revoke(ctx, "stale", credentialExact); err == nil {
		t.Fatal("accepted stale revision")
	}
	if f.count() != before+1 {
		t.Fatal("stale mutation retried")
	}
	before = f.count()
	if err := c.Credentials.Delete(ctx, "credential-one", 0); err == nil {
		t.Fatal("accepted zero revision")
	}
	if _, err := c.Credentials.EnrollCodex(ctx, "unused", nil); err == nil {
		t.Fatal("accepted missing challenge callback")
	}
	if f.count() != before {
		t.Fatal("invalid input reached transport")
	}
	if _, err := c.Credentials.Get(ctx, "missing"); err == nil {
		t.Fatal("accepted missing metadata")
	}
}

func TestCredentialsEnrollmentIsIncrementalAndHasPerCallDeadline(t *testing.T) {
	f, server := newCredentialFixture(t)
	httpClient := server.Client()
	httpClient.Timeout = time.Nanosecond
	c := codewire.New("synthetic-opaque-oauth", codewire.WithBaseURL(server.URL), codewire.WithHTTPClient(httpClient))
	challengeSeen := make(chan codewire.CodexDeviceChallenge, 1)
	type outcome struct {
		value *codewire.Credential
		err   error
	}
	result := make(chan outcome, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		value, err := c.Credentials.EnrollCodex(ctx, "success", func(challenge codewire.CodexDeviceChallenge) error { challengeSeen <- challenge; return nil })
		result <- outcome{value, err}
	}()
	select {
	case challenge := <-challengeSeen:
		if challenge.ExpiresAtUnix != ^uint64(0) {
			t.Fatal("lossy challenge expiry")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("challenge waited for enrollment completion or inherited ordinary timeout")
	}
	close(f.commit)
	select {
	case got := <-result:
		if got.err != nil || got.value.RevocationGeneration != credentialExact {
			t.Fatalf("enrollment: %v %v", got.value, got.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("committed metadata was not delivered")
	}
	if httpClient.Timeout != time.Nanosecond {
		t.Fatal("caller HTTP timeout was mutated")
	}
	if f.count() != 1 {
		t.Fatal("enrollment used another RPC")
	}
}

func TestCredentialsUncertainEnrollmentNeverRetries(t *testing.T) {
	f, server := newCredentialFixture(t)
	c := codewire.New("synthetic-opaque-oauth", codewire.WithBaseURL(server.URL), codewire.WithHTTPClient(server.Client()))
	for _, name := range []string{"eof", "error", "duplicate"} {
		before := f.count()
		challenges := 0
		_, err := c.Credentials.EnrollCodex(context.Background(), name, func(codewire.CodexDeviceChallenge) error { challenges++; return nil })
		var unknown *codewire.EnrollmentOutcomeUnknownError
		if !errors.As(err, &unknown) || challenges != 1 || f.count() != before+1 {
			t.Fatalf("%s: challenges=%d error=%v calls=%d", name, challenges, err, f.count()-before)
		}
	}
}

func TestCredentialsCancellationClosesOriginalStream(t *testing.T) {
	for _, name := range []string{"cancel", "callback-error"} {
		t.Run(name, func(t *testing.T) {
			f, server := newCredentialFixture(t)
			c := codewire.New("synthetic-opaque-oauth", codewire.WithBaseURL(server.URL), codewire.WithHTTPClient(server.Client()))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, err := c.Credentials.EnrollCodex(ctx, name, func(codewire.CodexDeviceChallenge) error {
				if name == "cancel" {
					cancel()
					return nil
				}
				return errors.New("synthetic callback stopped")
			})
			var unknown *codewire.EnrollmentOutcomeUnknownError
			if !errors.As(err, &unknown) {
				t.Fatalf("expected uncertain cancellation: %v", err)
			}
			select {
			case <-f.cancelled:
			case <-time.After(3 * time.Second):
				t.Fatal("server did not observe original request cancellation")
			}
			if f.count() != 1 {
				t.Fatal("cancellation retried or revoked")
			}
		})
	}
}
