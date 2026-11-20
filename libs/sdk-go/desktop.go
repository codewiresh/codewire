package codewire

import (
	"context"
	"fmt"
	"sync"
	"time"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	codewirev1connect "github.com/codewiresh/codewire/libs/gen-go/codewire/v1/codewirev1connect"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// A start answers only once the desktop accepts a viewer. The server allows
// it 40 seconds; this waits a little longer, so its own answer arrives
// instead of a local timeout.
const desktopStartTimeout = 45 * time.Second

// EnvironmentDesktop is the state of an environment's graphical desktop.
type EnvironmentDesktop struct {
	// State is "unavailable", "stopped", "starting", "running" or "unknown".
	State string `json:"state"`
	// UnavailableReason says what the image lacks, when State is "unavailable".
	UnavailableReason *string `json:"unavailable_reason,omitempty"`
	// Running is set while State is "running".
	Running *EnvironmentDesktopRunning `json:"running,omitempty"`
}

// EnvironmentDesktopRunning says where a running desktop is.
type EnvironmentDesktopRunning struct {
	// Display is the X display programs in the environment draw on, such as ":1".
	Display string `json:"display"`
	// Port is the VNC listener's port on the environment's loopback.
	Port      int64   `json:"port"`
	StartedAt *string `json:"started_at,omitempty"`
	// ViewerPassword is what the VNC server asks a viewer for, made at each
	// start. It is not an access control; do not log it.
	ViewerPassword string `json:"viewer_password"`
}

// Desktop starts, reads and stops the graphical desktop of one environment.
type Desktop struct {
	client       codewirev1connect.EnvironmentDesktopServiceClient
	orgID, envID string
}

func newDesktop(client *Client, orgID, envID string) *Desktop {
	// A start owns its bounded context without changing the caller's HTTP
	// transport, redirect policy, cookie jar or ordinary client timeout.
	httpClient := *client.httpClient
	httpClient.Timeout = 0
	return &Desktop{client: codewirev1connect.NewEnvironmentDesktopServiceClient(&httpClient, client.baseURL,
		connect.WithInterceptors(bearerInterceptor{apiKey: client.apiKey})), orgID: orgID, envID: envID}
}

// Desktop returns the desktop of the environment envID.
func (s *EnvironmentService) Desktop(envID string) (*Desktop, error) {
	org, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	return newDesktop(s.client, org, envID), nil
}

// Start starts the desktop, or returns the one that runs.
func (d *Desktop) Start(ctx context.Context) (*EnvironmentDesktop, error) {
	ctx, cancel := context.WithTimeout(ctx, desktopStartTimeout)
	defer cancel()
	response, err := d.client.StartDesktop(ctx, connect.NewRequest(&codewirev1.StartDesktopRequest{OrgId: d.orgID, EnvironmentId: d.envID}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	return fromProtoEnvironmentDesktop(response.Msg.GetDesktop())
}

// Get reads the desktop's state.
func (d *Desktop) Get(ctx context.Context) (*EnvironmentDesktop, error) {
	response, err := d.client.GetDesktop(ctx, connect.NewRequest(&codewirev1.GetDesktopRequest{OrgId: d.orgID, EnvironmentId: d.envID}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	return fromProtoEnvironmentDesktop(response.Msg.GetDesktop())
}

// Stop stops the desktop. Stopping one that does not run succeeds.
func (d *Desktop) Stop(ctx context.Context) (*EnvironmentDesktop, error) {
	response, err := d.client.StopDesktop(ctx, connect.NewRequest(&codewirev1.StopDesktopRequest{OrgId: d.orgID, EnvironmentId: d.envID}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	return fromProtoEnvironmentDesktop(response.Msg.GetDesktop())
}

var (
	desktopCoverageOnce sync.Once
	desktopCoverageErr  error
)

// A field added to either message fails here until this converter carries it.
func ensureDesktopConverterCoverage() error {
	desktopCoverageOnce.Do(func() {
		messages := codewirev1.File_codewire_v1_environment_desktop_proto.Messages()
		desktopCoverageErr = ensureDescriptorCoverage("environment desktop", messages.ByName("EnvironmentDesktop"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "state", 2: "unavailable_reason", 3: "running",
		})
		if desktopCoverageErr != nil {
			return
		}
		desktopCoverageErr = ensureDescriptorCoverage("running environment desktop", messages.ByName("EnvironmentDesktopRunning"), map[protoreflect.FieldNumber]protoreflect.Name{
			1: "display", 2: "port", 3: "started_at", 4: "viewer_password",
		})
	})
	return desktopCoverageErr
}

func fromProtoEnvironmentDesktop(desktop *codewirev1.EnvironmentDesktop) (*EnvironmentDesktop, error) {
	if err := ensureDesktopConverterCoverage(); err != nil {
		return nil, err
	}
	if desktop == nil {
		return nil, fmt.Errorf("codewire: desktop response omitted desktop")
	}
	converted := &EnvironmentDesktop{State: desktopState(desktop.GetState())}
	if reason := desktop.GetUnavailableReason(); reason != "" {
		converted.UnavailableReason = &reason
	}
	if running := desktop.GetRunning(); running != nil {
		startedAt, err := formatSDKTimestamp("environment desktop started_at", running.GetStartedAt())
		if err != nil {
			return nil, err
		}
		converted.Running = &EnvironmentDesktopRunning{
			Display: running.GetDisplay(), Port: int64(running.GetPort()),
			StartedAt: startedAt, ViewerPassword: running.GetViewerPassword(),
		}
	}
	return converted, nil
}

func desktopState(state codewirev1.EnvironmentDesktopState) string {
	switch state {
	case codewirev1.EnvironmentDesktopState_ENVIRONMENT_DESKTOP_STATE_UNAVAILABLE:
		return "unavailable"
	case codewirev1.EnvironmentDesktopState_ENVIRONMENT_DESKTOP_STATE_STOPPED:
		return "stopped"
	case codewirev1.EnvironmentDesktopState_ENVIRONMENT_DESKTOP_STATE_STARTING:
		return "starting"
	case codewirev1.EnvironmentDesktopState_ENVIRONMENT_DESKTOP_STATE_RUNNING:
		return "running"
	default:
		return "unknown"
	}
}
