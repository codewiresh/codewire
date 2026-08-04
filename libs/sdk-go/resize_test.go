package codewire_test

import (
	"context"
	"math"
	"strings"
	"testing"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"

	codewire "codewire.sh/sdk-go"
)

func TestEnvironmentResizeServiceAndFluentParity(t *testing.T) {
	planCalls := 0
	resizeCalls := 0
	getCalls := 0
	client, _ := testRuntimeServer(t, environmentServiceHandler{
		get: func(_ context.Context, req *connect.Request[codewirev1.GetEnvironmentRequest]) (*connect.Response[codewirev1.GetEnvironmentResponse], error) {
			if req.Msg.GetOrgId() != "org_test" || req.Msg.GetEnvironmentId() != "env_123" {
				t.Errorf("unexpected environment get request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.GetEnvironmentResponse{Environment: environmentProto(codewire.EnvironmentData{
				Id: "env_123", OrgId: "org_test", State: "running", DesiredState: "started",
				Type: "sandbox", StateChangedAt: "2026-01-01T00:00:00Z", CreatedAt: "2026-01-01T00:00:00Z",
			})}), nil
		},
		planResize: func(_ context.Context, req *connect.Request[codewirev1.PlanEnvironmentResizeRequest]) (*connect.Response[codewirev1.PlanEnvironmentResizeResponse], error) {
			planCalls++
			if req.Msg.GetOrgId() != "org_test" || req.Msg.GetEnvironmentId() != "env_123" ||
				req.Msg.GetCpuMillicores() != 4000 || req.Msg.GetMemoryMb() != 8192 || req.Msg.GetDiskGb() != 40 {
				t.Errorf("unexpected resize plan request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.PlanEnvironmentResizeResponse{Plan: &codewirev1.EnvironmentResizePlan{
				PreviousResources: &codewirev1.EnvironmentResources{CpuMillicores: 2000, MemoryMb: 4096, DiskGb: 20},
				DesiredResources:  &codewirev1.EnvironmentResources{CpuMillicores: 4000, MemoryMb: 8192, DiskGb: 40},
				ExecutionMode:     codewirev1.EnvironmentResizeExecutionMode_ENVIRONMENT_RESIZE_EXECUTION_MODE_IN_PLACE,
				Warnings:          []string{"active session"},
			}}), nil
		},
		resize: func(_ context.Context, req *connect.Request[codewirev1.ResizeEnvironmentRequest]) (*connect.Response[codewirev1.ResizeEnvironmentResponse], error) {
			resizeCalls++
			if req.Msg.GetOrgId() != "org_test" || req.Msg.GetEnvironmentId() != "env_123" ||
				req.Msg.GetRequestId() != "resize_123" || !req.Msg.GetForce() ||
				req.Msg.GetDisruptionPolicy() != codewirev1.EnvironmentResizeDisruptionPolicy_ENVIRONMENT_RESIZE_DISRUPTION_POLICY_ALLOW_RESTART ||
				req.Msg.GetCpuMillicores() != 4000 || req.Msg.GetMemoryMb() != 8192 || req.Msg.GetDiskGb() != 40 {
				t.Errorf("unexpected resize request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.ResizeEnvironmentResponse{Operation: resizeOperationProto()}), nil
		},
		getResize: func(_ context.Context, req *connect.Request[codewirev1.GetEnvironmentResizeOperationRequest]) (*connect.Response[codewirev1.GetEnvironmentResizeOperationResponse], error) {
			getCalls++
			if req.Msg.GetOrgId() != "org_test" || req.Msg.GetEnvironmentId() != "env_123" || req.Msg.GetOperationId() != "op_123" {
				t.Errorf("unexpected resize operation request: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.GetEnvironmentResizeOperationResponse{Operation: resizeOperationProto()}), nil
		},
	}, execServiceHandler{}, fileServiceHandler{}, portServiceHandler{})

	ctx := context.Background()
	desired := codewire.EnvironmentResources{CpuMillicores: 4000, MemoryMb: 8192, DiskGb: 40}
	body := codewire.ResizeEnvironmentRequest{
		EnvironmentResources: desired,
		RequestId:            "resize_123",
		Force:                true,
		AllowRestart:         true,
	}

	plan, err := client.Environments.PlanResize(ctx, "env_123", desired)
	if err != nil {
		t.Fatalf("plan resize: %v", err)
	}
	if plan.ExecutionMode != "in_place" || plan.DesiredResources == nil || plan.DesiredResources.MemoryMb != 8192 {
		t.Fatalf("unexpected resize plan: %#v", plan)
	}
	operation, err := client.Environments.Resize(ctx, "env_123", body)
	if err != nil {
		t.Fatalf("resize: %v", err)
	}
	assertResizeOperation(t, operation)
	operation, err = client.Environments.GetResizeOperation(ctx, "env_123", "op_123")
	if err != nil {
		t.Fatalf("get resize operation: %v", err)
	}
	assertResizeOperation(t, operation)

	environment, err := client.Environments.Get(ctx, "env_123")
	if err != nil {
		t.Fatalf("get fluent environment: %v", err)
	}
	if _, err := environment.PlanResize(ctx, desired); err != nil {
		t.Fatalf("fluent plan resize: %v", err)
	}
	if _, err := environment.Resize(ctx, body); err != nil {
		t.Fatalf("fluent resize: %v", err)
	}
	if _, err := environment.GetResizeOperation(ctx, "op_123"); err != nil {
		t.Fatalf("fluent get resize operation: %v", err)
	}
	if planCalls != 2 || resizeCalls != 2 || getCalls != 2 {
		t.Fatalf("fluent resize methods did not delegate exactly once: plan=%d resize=%d get=%d", planCalls, resizeCalls, getCalls)
	}
}

func TestEnvironmentResizeRejectsInvalidInputsAndResponses(t *testing.T) {
	resizeCalls := 0
	client, _ := testRuntimeServer(t, environmentServiceHandler{
		planResize: func(context.Context, *connect.Request[codewirev1.PlanEnvironmentResizeRequest]) (*connect.Response[codewirev1.PlanEnvironmentResizeResponse], error) {
			return connect.NewResponse(&codewirev1.PlanEnvironmentResizeResponse{}), nil
		},
		resize: func(_ context.Context, req *connect.Request[codewirev1.ResizeEnvironmentRequest]) (*connect.Response[codewirev1.ResizeEnvironmentResponse], error) {
			resizeCalls++
			if req.Msg.GetForce() || req.Msg.GetDisruptionPolicy() != codewirev1.EnvironmentResizeDisruptionPolicy_ENVIRONMENT_RESIZE_DISRUPTION_POLICY_LIVE_ONLY {
				t.Errorf("default resize request was not live-only: %#v", req.Msg)
			}
			return connect.NewResponse(&codewirev1.ResizeEnvironmentResponse{}), nil
		},
		getResize: func(context.Context, *connect.Request[codewirev1.GetEnvironmentResizeOperationRequest]) (*connect.Response[codewirev1.GetEnvironmentResizeOperationResponse], error) {
			return connect.NewResponse(&codewirev1.GetEnvironmentResizeOperationResponse{}), nil
		},
	}, execServiceHandler{}, fileServiceHandler{}, portServiceHandler{})

	ctx := context.Background()
	invalid := []struct {
		name      string
		resources codewire.EnvironmentResources
		field     string
	}{
		{name: "cpu", resources: codewire.EnvironmentResources{CpuMillicores: math.MaxInt32 + 1}, field: "cpu_millicores"},
		{name: "memory", resources: codewire.EnvironmentResources{MemoryMb: math.MaxInt32 + 1}, field: "memory_mb"},
		{name: "disk", resources: codewire.EnvironmentResources{DiskGb: math.MaxInt32 + 1}, field: "disk_gb"},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			_, err := client.Environments.Resize(ctx, "env_123", codewire.ResizeEnvironmentRequest{
				EnvironmentResources: test.resources,
			})
			if err == nil || !strings.Contains(err.Error(), test.field+" is outside the API integer range") {
				t.Fatalf("expected local %s range error, got %v", test.field, err)
			}
		})
	}
	if resizeCalls != 0 {
		t.Fatalf("invalid resources reached the transport %d time(s)", resizeCalls)
	}

	valid := codewire.EnvironmentResources{CpuMillicores: 1000, MemoryMb: 2048, DiskGb: 20}
	if _, err := client.Environments.PlanResize(ctx, "env_123", valid); err == nil || !strings.Contains(err.Error(), "omitted plan") {
		t.Fatalf("expected missing plan error, got %v", err)
	}
	if _, err := client.Environments.Resize(ctx, "env_123", codewire.ResizeEnvironmentRequest{EnvironmentResources: valid}); err == nil || !strings.Contains(err.Error(), "omitted operation") {
		t.Fatalf("expected missing resize operation error, got %v", err)
	}
	if _, err := client.Environments.GetResizeOperation(ctx, "env_123", "op_123"); err == nil || !strings.Contains(err.Error(), "omitted operation") {
		t.Fatalf("expected missing operation lookup error, got %v", err)
	}
}

func resizeOperationProto() *codewirev1.EnvironmentResizeOperation {
	return &codewirev1.EnvironmentResizeOperation{
		Id:                   "op_123",
		EnvironmentId:        "env_123",
		RequestId:            "resize_123",
		PreviousResources:    &codewirev1.EnvironmentResources{CpuMillicores: 2000, MemoryMb: 4096, DiskGb: 20},
		DesiredResources:     &codewirev1.EnvironmentResources{CpuMillicores: 4000, MemoryMb: 8192, DiskGb: 40},
		LastAppliedResources: &codewirev1.EnvironmentResources{CpuMillicores: 4000, MemoryMb: 8192, DiskGb: 40},
		State:                codewirev1.EnvironmentResizeOperationState_ENVIRONMENT_RESIZE_OPERATION_STATE_COMPLETED,
		DisruptionPolicy:     codewirev1.EnvironmentResizeDisruptionPolicy_ENVIRONMENT_RESIZE_DISRUPTION_POLICY_ALLOW_RESTART,
		PlannedMode:          codewirev1.EnvironmentResizeExecutionMode_ENVIRONMENT_RESIZE_EXECUTION_MODE_RESTART,
		AppliedMode:          codewirev1.EnvironmentResizeExecutionMode_ENVIRONMENT_RESIZE_EXECUTION_MODE_RESTART,
		PodReplaced:          true,
	}
}

func assertResizeOperation(t *testing.T, operation *codewire.EnvironmentResizeOperation) {
	t.Helper()
	if operation.Id != "op_123" || operation.EnvironmentId != "env_123" || operation.RequestId != "resize_123" ||
		operation.State != "completed" || operation.DisruptionPolicy != "allow_restart" || operation.PlannedMode != "restart" ||
		operation.AppliedMode != "restart" || !operation.PodReplaced || operation.LastAppliedResources == nil ||
		operation.LastAppliedResources.CpuMillicores != 4000 {
		t.Fatalf("unexpected resize operation: %#v", operation)
	}
}
