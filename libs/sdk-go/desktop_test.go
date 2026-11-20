package codewire

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	codewirev1connect "github.com/codewiresh/codewire/libs/gen-go/codewire/v1/codewirev1connect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type desktopServiceHandler struct {
	codewirev1connect.UnimplementedEnvironmentDesktopServiceHandler
	t     *testing.T
	calls []string
	// startDeadline is how long the start's context had left when it arrived.
	startDeadline time.Duration
	refuse        bool
}

func (h *desktopServiceHandler) scoped(rpc, authorization, org, env string) {
	h.t.Helper()
	if authorization != "Bearer test-key" || org != "org_test" || env != "env_123" {
		h.t.Fatalf("%s arrived as %q for %q/%q", rpc, authorization, org, env)
	}
	h.calls = append(h.calls, rpc)
}

func runningDesktop() *codewirev1.EnvironmentDesktop {
	return &codewirev1.EnvironmentDesktop{
		State: codewirev1.EnvironmentDesktopState_ENVIRONMENT_DESKTOP_STATE_RUNNING,
		Running: &codewirev1.EnvironmentDesktopRunning{
			Display: ":1", Port: 5901, ViewerPassword: "a1b2c3d4",
			StartedAt: timestamppb.New(time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)),
		},
	}
}

func (h *desktopServiceHandler) StartDesktop(ctx context.Context, req *connect.Request[codewirev1.StartDesktopRequest]) (*connect.Response[codewirev1.StartDesktopResponse], error) {
	h.scoped("start", req.Header().Get("Authorization"), req.Msg.GetOrgId(), req.Msg.GetEnvironmentId())
	if deadline, ok := ctx.Deadline(); ok {
		h.startDeadline = time.Until(deadline)
	}
	if h.refuse {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("this environment's image has no desktop: its launcher is not in the image"))
	}
	return connect.NewResponse(&codewirev1.StartDesktopResponse{Desktop: runningDesktop()}), nil
}

func (h *desktopServiceHandler) GetDesktop(_ context.Context, req *connect.Request[codewirev1.GetDesktopRequest]) (*connect.Response[codewirev1.GetDesktopResponse], error) {
	h.scoped("get", req.Header().Get("Authorization"), req.Msg.GetOrgId(), req.Msg.GetEnvironmentId())
	return connect.NewResponse(&codewirev1.GetDesktopResponse{Desktop: runningDesktop()}), nil
}

func (h *desktopServiceHandler) StopDesktop(_ context.Context, req *connect.Request[codewirev1.StopDesktopRequest]) (*connect.Response[codewirev1.StopDesktopResponse], error) {
	h.scoped("stop", req.Header().Get("Authorization"), req.Msg.GetOrgId(), req.Msg.GetEnvironmentId())
	return connect.NewResponse(&codewirev1.StopDesktopResponse{Desktop: &codewirev1.EnvironmentDesktop{
		State: codewirev1.EnvironmentDesktopState_ENVIRONMENT_DESKTOP_STATE_STOPPED,
	}}), nil
}

func desktopFixture(t *testing.T, handler *desktopServiceHandler) *Desktop {
	t.Helper()
	handler.t = t
	mux := http.NewServeMux()
	mux.Handle(codewirev1connect.NewEnvironmentDesktopServiceHandler(handler))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	desktop, err := New("test-key", WithBaseURL(server.URL), WithOrgID("org_test")).Environments.Desktop("env_123")
	if err != nil {
		t.Fatal(err)
	}
	return desktop
}

func TestDesktopCallsNameTheirEnvironmentAndARunningDesktopArrivesWhole(t *testing.T) {
	handler := &desktopServiceHandler{}
	desktop := desktopFixture(t, handler)
	ctx := context.Background()

	started, err := desktop.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if started.State != "running" || started.UnavailableReason != nil || started.Running == nil {
		t.Fatalf("start answered %+v", started.State)
	}
	running := started.Running
	if running.Display != ":1" || running.Port != 5901 || running.ViewerPassword != "a1b2c3d4" ||
		running.StartedAt == nil || *running.StartedAt != "2026-11-20T10:00:00Z" {
		t.Fatalf("a running desktop lost a field: display %q port %d started %v", running.Display, running.Port, running.StartedAt)
	}
	// Longer than the server's own 40 seconds, and bounded.
	if handler.startDeadline < 40*time.Second || handler.startDeadline > desktopStartTimeout {
		t.Fatalf("start had %s left", handler.startDeadline)
	}

	read, err := desktop.Get(ctx)
	if err != nil || read.Running == nil || read.Running.ViewerPassword != "a1b2c3d4" {
		t.Fatalf("get: %v", err)
	}
	stopped, err := desktop.Stop(ctx)
	if err != nil || stopped.State != "stopped" || stopped.Running != nil {
		t.Fatalf("stop: %v", err)
	}
	if got := strings.Join(handler.calls, ","); got != "start,get,stop" {
		t.Fatalf("calls: %s", got)
	}
}

func TestDesktopRefusalKeepsTheServersReason(t *testing.T) {
	desktop := desktopFixture(t, &desktopServiceHandler{refuse: true})
	_, err := desktop.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "has no desktop") {
		t.Fatalf("start: %v", err)
	}
}

func TestDesktopConverterCoversBothMessagesAndNamesEachState(t *testing.T) {
	if err := ensureDesktopConverterCoverage(); err != nil {
		t.Fatal(err)
	}
	if _, err := fromProtoEnvironmentDesktop(nil); err == nil {
		t.Fatal("a response without a desktop was accepted")
	}
	unavailable, err := fromProtoEnvironmentDesktop(&codewirev1.EnvironmentDesktop{
		State:             codewirev1.EnvironmentDesktopState_ENVIRONMENT_DESKTOP_STATE_UNAVAILABLE,
		UnavailableReason: "its launcher is not in the image",
	})
	if err != nil || unavailable.State != "unavailable" || unavailable.Running != nil ||
		unavailable.UnavailableReason == nil || *unavailable.UnavailableReason != "its launcher is not in the image" {
		t.Fatalf("unavailable: %v", err)
	}
	for state, name := range map[codewirev1.EnvironmentDesktopState]string{
		codewirev1.EnvironmentDesktopState_ENVIRONMENT_DESKTOP_STATE_STOPPED:     "stopped",
		codewirev1.EnvironmentDesktopState_ENVIRONMENT_DESKTOP_STATE_STARTING:    "starting",
		codewirev1.EnvironmentDesktopState_ENVIRONMENT_DESKTOP_STATE_RUNNING:     "running",
		codewirev1.EnvironmentDesktopState_ENVIRONMENT_DESKTOP_STATE_UNSPECIFIED: "unknown",
	} {
		if got := desktopState(state); got != name {
			t.Fatalf("%v is named %q", state, got)
		}
	}
}
