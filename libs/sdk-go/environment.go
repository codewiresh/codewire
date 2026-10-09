package codewire

import (
	"context"
	"fmt"
	"time"
)

// Environment is the fluent handle returned from the [EnvironmentService].
// It embeds [EnvironmentData] so callers see the same fields as the raw API
// response, with convenience methods (Exec, Stop, Remove, WaitReady) bound
// to the owning client.
type Environment struct {
	EnvironmentData
	Files   *Files
	Runtime *CwRuntime
	Agents  *PlatformAgents

	client       *Client
	orgID        string
	pollInterval time.Duration
}

// Exec runs a command in the environment and returns the result.
func (e *Environment) Exec(ctx context.Context, body ExecBody) (*ExecResult, error) {
	return e.client.Environments.Exec(ctx, e.Id, body)
}

// Start starts the environment.
func (e *Environment) Start(ctx context.Context) error {
	return e.client.Environments.Start(ctx, e.Id)
}

// Stop stops the environment.
func (e *Environment) Stop(ctx context.Context) error {
	return e.client.Environments.Stop(ctx, e.Id)
}

// Resize starts an idempotent platform resize for this environment.
func (e *Environment) Resize(ctx context.Context, body ResizeEnvironmentRequest) (*EnvironmentResizeOperation, error) {
	return e.client.Environments.Resize(ctx, e.Id, body)
}

// PlanResize asks how the platform will apply a desired allocation.
func (e *Environment) PlanResize(ctx context.Context, desired EnvironmentResources) (*EnvironmentResizePlan, error) {
	return e.client.Environments.PlanResize(ctx, e.Id, desired)
}

// GetResizeOperation reads a durable resize operation for this environment.
func (e *Environment) GetResizeOperation(ctx context.Context, operationID string) (*EnvironmentResizeOperation, error) {
	return e.client.Environments.GetResizeOperation(ctx, e.Id, operationID)
}

// Remove destroys the environment.
func (e *Environment) Remove(ctx context.Context) error {
	return e.client.Environments.Delete(ctx, e.Id)
}

// ListPorts returns all forwarded ports for the environment.
func (e *Environment) ListPorts(ctx context.Context) ([]EnvironmentPort, error) {
	return e.client.Environments.ListPorts(ctx, e.Id)
}

// CreatePort creates a new port forward for the environment.
func (e *Environment) CreatePort(ctx context.Context, body CreatePortBody) (*EnvironmentPort, error) {
	return e.client.Environments.CreatePort(ctx, e.Id, body)
}

// DeletePort removes a port forward from the environment.
func (e *Environment) DeletePort(ctx context.Context, portID string) error {
	return e.client.Environments.DeletePort(ctx, e.Id, portID)
}

// WaitReady polls until the environment reaches "running" state. It returns
// an error if the environment enters an error or destroyed state, or if the
// context is cancelled. The receiver's embedded data is refreshed each poll
// so callers can read the final state without a follow-up Get.
func (e *Environment) WaitReady(ctx context.Context) error {
	for {
		env, err := e.client.Environments.Get(ctx, e.Id)
		if err != nil {
			return err
		}
		e.EnvironmentData = env.EnvironmentData
		e.pollInterval = env.pollInterval
		switch e.State {
		case "running":
			return nil
		case "error", "destroyed":
			reason := ""
			if e.ErrorReason != nil {
				reason = *e.ErrorReason
			}
			return &Error{Detail: fmt.Sprintf("environment %s entered state %s: %s", e.Id, e.State, reason)}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(e.pollInterval):
		}
	}
}
