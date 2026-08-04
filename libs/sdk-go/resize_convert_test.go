package codewire

import (
	"reflect"
	"strings"
	"testing"
	"time"

	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFromProtoEnvironmentResizeOperationGolden(t *testing.T) {
	operation, err := fromProtoEnvironmentResizeOperation(&codewirev1.EnvironmentResizeOperation{
		Id:                   "op_123",
		EnvironmentId:        "env_123",
		RequestId:            "req_123",
		PreviousResources:    &codewirev1.EnvironmentResources{CpuMillicores: 1000, MemoryMb: 2048, DiskGb: 20},
		DesiredResources:     &codewirev1.EnvironmentResources{CpuMillicores: 2000, MemoryMb: 4096, DiskGb: 30},
		LastAppliedResources: &codewirev1.EnvironmentResources{CpuMillicores: 2000, MemoryMb: 4096, DiskGb: 30},
		State:                codewirev1.EnvironmentResizeOperationState_ENVIRONMENT_RESIZE_OPERATION_STATE_FAILED,
		Failure:              &codewirev1.EnvironmentResizeFailure{Code: "runtime", Message: "resize failed"},
		CreatedAt:            timestamppb.New(time.Date(2026, 8, 4, 1, 2, 3, 0, time.UTC)),
		UpdatedAt:            timestamppb.New(time.Date(2026, 8, 4, 1, 3, 3, 0, time.UTC)),
		CompletedAt:          timestamppb.New(time.Date(2026, 8, 4, 1, 4, 3, 0, time.UTC)),
		DisruptionPolicy:     codewirev1.EnvironmentResizeDisruptionPolicy_ENVIRONMENT_RESIZE_DISRUPTION_POLICY_ALLOW_RESTART,
		PlannedMode:          codewirev1.EnvironmentResizeExecutionMode_ENVIRONMENT_RESIZE_EXECUTION_MODE_RESTART,
		AppliedMode:          codewirev1.EnvironmentResizeExecutionMode_ENVIRONMENT_RESIZE_EXECUTION_MODE_IN_PLACE,
		PodReplaced:          true,
	})
	if err != nil {
		t.Fatalf("convert resize operation: %v", err)
	}
	want := EnvironmentResizeOperation{
		Id:                   "op_123",
		EnvironmentId:        "env_123",
		RequestId:            "req_123",
		PreviousResources:    &EnvironmentResources{CpuMillicores: 1000, MemoryMb: 2048, DiskGb: 20},
		DesiredResources:     &EnvironmentResources{CpuMillicores: 2000, MemoryMb: 4096, DiskGb: 30},
		LastAppliedResources: &EnvironmentResources{CpuMillicores: 2000, MemoryMb: 4096, DiskGb: 30},
		State:                "failed",
		Failure:              &EnvironmentResizeFailure{Code: "runtime", Message: "resize failed"},
		CreatedAt:            stringPointer("2026-08-04T01:02:03Z"),
		UpdatedAt:            stringPointer("2026-08-04T01:03:03Z"),
		CompletedAt:          stringPointer("2026-08-04T01:04:03Z"),
		DisruptionPolicy:     "allow_restart",
		PlannedMode:          "restart",
		AppliedMode:          "in_place",
		PodReplaced:          true,
	}
	if !reflect.DeepEqual(operation, want) {
		t.Fatalf("resize operation mismatch\nwant: %#v\n got: %#v", want, operation)
	}
}

func TestFromProtoEnvironmentResizePlanGolden(t *testing.T) {
	plan, err := fromProtoEnvironmentResizePlan(&codewirev1.EnvironmentResizePlan{
		PreviousResources:              &codewirev1.EnvironmentResources{CpuMillicores: 1000, MemoryMb: 2048, DiskGb: 20},
		DesiredResources:               &codewirev1.EnvironmentResources{CpuMillicores: 2000, MemoryMb: 4096, DiskGb: 30},
		ExecutionMode:                  codewirev1.EnvironmentResizeExecutionMode_ENVIRONMENT_RESIZE_EXECUTION_MODE_APPLY_ON_START,
		ActiveSessionCount:             2,
		ActiveSessionsWillBeTerminated: true,
		Reason:                         "environment is stopped",
		Warnings:                       []string{"sessions will be terminated"},
	})
	if err != nil {
		t.Fatalf("convert resize plan: %v", err)
	}
	want := EnvironmentResizePlan{
		PreviousResources:              &EnvironmentResources{CpuMillicores: 1000, MemoryMb: 2048, DiskGb: 20},
		DesiredResources:               &EnvironmentResources{CpuMillicores: 2000, MemoryMb: 4096, DiskGb: 30},
		ExecutionMode:                  "apply_on_start",
		ActiveSessionCount:             2,
		ActiveSessionsWillBeTerminated: true,
		Reason:                         "environment is stopped",
		Warnings:                       []string{"sessions will be terminated"},
	}
	if !reflect.DeepEqual(plan, want) {
		t.Fatalf("resize plan mismatch\nwant: %#v\n got: %#v", want, plan)
	}
}

func TestEnvironmentResizeConvertersHandleUnknownEnumsAndInvalidTimestamps(t *testing.T) {
	operation, err := fromProtoEnvironmentResizeOperation(&codewirev1.EnvironmentResizeOperation{
		State:            codewirev1.EnvironmentResizeOperationState(99),
		DisruptionPolicy: codewirev1.EnvironmentResizeDisruptionPolicy(99),
		PlannedMode:      codewirev1.EnvironmentResizeExecutionMode(99),
		AppliedMode:      codewirev1.EnvironmentResizeExecutionMode(99),
	})
	if err != nil {
		t.Fatalf("convert unknown resize enums: %v", err)
	}
	if operation.State != "unknown" || operation.DisruptionPolicy != "unknown" || operation.PlannedMode != "unknown" || operation.AppliedMode != "unknown" {
		t.Fatalf("unknown resize enums were not preserved safely: %#v", operation)
	}

	_, err = fromProtoEnvironmentResizeOperation(&codewirev1.EnvironmentResizeOperation{
		CreatedAt: &timestamppb.Timestamp{Seconds: 253402300800},
	})
	if err == nil || !strings.Contains(err.Error(), "environment resize created_at: invalid timestamp") {
		t.Fatalf("expected invalid resize timestamp error, got %v", err)
	}
}

func TestEnvironmentResizeEnumConversionsCoverEveryKnownValue(t *testing.T) {
	states := map[codewirev1.EnvironmentResizeOperationState]string{
		codewirev1.EnvironmentResizeOperationState_ENVIRONMENT_RESIZE_OPERATION_STATE_UNSPECIFIED: "unspecified",
		codewirev1.EnvironmentResizeOperationState_ENVIRONMENT_RESIZE_OPERATION_STATE_PENDING:     "pending",
		codewirev1.EnvironmentResizeOperationState_ENVIRONMENT_RESIZE_OPERATION_STATE_APPLYING:    "applying",
		codewirev1.EnvironmentResizeOperationState_ENVIRONMENT_RESIZE_OPERATION_STATE_RESTARTING:  "restarting",
		codewirev1.EnvironmentResizeOperationState_ENVIRONMENT_RESIZE_OPERATION_STATE_COMPLETED:   "completed",
		codewirev1.EnvironmentResizeOperationState_ENVIRONMENT_RESIZE_OPERATION_STATE_FAILED:      "failed",
	}
	for value, want := range states {
		if got := environmentResizeOperationState(value); got != want {
			t.Errorf("resize state %d: want %q, got %q", value, want, got)
		}
	}

	policies := map[codewirev1.EnvironmentResizeDisruptionPolicy]string{
		codewirev1.EnvironmentResizeDisruptionPolicy_ENVIRONMENT_RESIZE_DISRUPTION_POLICY_UNSPECIFIED:   "unspecified",
		codewirev1.EnvironmentResizeDisruptionPolicy_ENVIRONMENT_RESIZE_DISRUPTION_POLICY_LIVE_ONLY:     "live_only",
		codewirev1.EnvironmentResizeDisruptionPolicy_ENVIRONMENT_RESIZE_DISRUPTION_POLICY_ALLOW_RESTART: "allow_restart",
	}
	for value, want := range policies {
		if got := environmentResizeDisruptionPolicy(value); got != want {
			t.Errorf("resize disruption policy %d: want %q, got %q", value, want, got)
		}
	}

	modes := map[codewirev1.EnvironmentResizeExecutionMode]string{
		codewirev1.EnvironmentResizeExecutionMode_ENVIRONMENT_RESIZE_EXECUTION_MODE_UNSPECIFIED:    "unspecified",
		codewirev1.EnvironmentResizeExecutionMode_ENVIRONMENT_RESIZE_EXECUTION_MODE_NOOP:           "noop",
		codewirev1.EnvironmentResizeExecutionMode_ENVIRONMENT_RESIZE_EXECUTION_MODE_APPLY_ON_START: "apply_on_start",
		codewirev1.EnvironmentResizeExecutionMode_ENVIRONMENT_RESIZE_EXECUTION_MODE_IN_PLACE:       "in_place",
		codewirev1.EnvironmentResizeExecutionMode_ENVIRONMENT_RESIZE_EXECUTION_MODE_RESTART:        "restart",
	}
	for value, want := range modes {
		if got := environmentResizeExecutionMode(value); got != want {
			t.Errorf("resize execution mode %d: want %q, got %q", value, want, got)
		}
	}

	plan, err := fromProtoEnvironmentResizePlan(&codewirev1.EnvironmentResizePlan{})
	if err != nil {
		t.Fatalf("convert empty resize plan: %v", err)
	}
	if plan.Warnings == nil {
		t.Fatal("empty resize warnings must remain an empty JSON array, not null")
	}
}
