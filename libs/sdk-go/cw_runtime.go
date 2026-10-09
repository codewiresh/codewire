package codewire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"connectrpc.com/connect"
	codewirev1 "github.com/codewiresh/codewire/libs/gen-go/codewire/v1"
	codewirev1connect "github.com/codewiresh/codewire/libs/gen-go/codewire/v1/codewirev1connect"
	"google.golang.org/protobuf/proto"
)

const cwRuntimeChunkBytes = 64 * 1024
const cwRuntimeMaximumBytes = 256 * 1024 * 1024
const cwRuntimeMutationTimeout = 960 * time.Second

// CwRuntimeOutcomeUnknownError retains the original UUID. Observe it; do not
// replay Update/Rollback or choose a new UUID after a transport failure.
type CwRuntimeOutcomeUnknownError struct {
	RequestID string
	Cause     error
}

func (e *CwRuntimeOutcomeUnknownError) Error() string {
	return "codewire: cw runtime outcome is uncertain; observe the original request_id"
}
func (e *CwRuntimeOutcomeUnknownError) Unwrap() error { return e.Cause }

// CwRuntime changes defaults for future ordinary workload invocations only.
// Full generated identities/incarnations and uint64 values remain lossless.
type CwRuntime struct {
	client       codewirev1connect.EnvironmentCwRuntimeServiceClient
	orgID, envID string
}

func newCwRuntime(client *Client, orgID, envID string) *CwRuntime {
	// The operation owns its bounded context without changing the caller's
	// HTTP transport, redirect policy, cookie jar or ordinary client timeout.
	httpClient := *client.httpClient
	httpClient.Timeout = 0
	return &CwRuntime{client: codewirev1connect.NewEnvironmentCwRuntimeServiceClient(&httpClient, client.baseURL,
		connect.WithInterceptors(bearerInterceptor{apiKey: client.apiKey}), connect.WithReadMaxBytes(32*1024), connect.WithSendMaxBytes(cwRuntimeChunkBytes+1024)), orgID: orgID, envID: envID}
}

func (s *EnvironmentService) Runtime(envID string) (*CwRuntime, error) {
	org, err := s.client.resolveOrgID()
	if err != nil {
		return nil, err
	}
	return newCwRuntime(s.client, org, envID), nil
}

func (r *CwRuntime) Status(ctx context.Context) (*codewirev1.GetEnvironmentCwRuntimeResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	response, err := r.client.GetEnvironmentCwRuntime(ctx, connect.NewRequest(&codewirev1.GetEnvironmentCwRuntimeRequest{OrgId: r.orgID, EnvironmentId: r.envID}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	if response.Msg.Incarnation == nil || response.Msg.Selection == nil {
		return nil, fmt.Errorf("codewire: cw runtime status omitted required metadata")
	}
	return response.Msg, nil
}

// streamCwCandidate retains at most one chunk and probes EOF after the exact
// admitted size. A zero-progress or oversized read fails instead of looping.
func streamCwCandidate(src io.Reader, size uint64, send func([]byte) error) error {
	if size < 64 || size > cwRuntimeMaximumBytes {
		return fmt.Errorf("codewire: cw runtime candidate size is invalid")
	}
	buffer := make([]byte, cwRuntimeChunkBytes)
	var count uint64
	chunks := 0
	for count < size {
		wanted := min(uint64(len(buffer)), size-count)
		n, err := src.Read(buffer[:wanted])
		if n < 0 || uint64(n) > wanted {
			return fmt.Errorf("codewire: cw runtime reader exceeded its bound")
		}
		if n > 0 {
			chunks++
			if chunks > 8192 {
				return fmt.Errorf("codewire: cw runtime candidate exceeds its chunk bound")
			}
			count += uint64(n)
			if sendErr := send(append([]byte(nil), buffer[:n]...)); sendErr != nil {
				return sendErr
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) || count != size {
				return fmt.Errorf("codewire: cw runtime candidate stream is incomplete: %w", err)
			}
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	var extra [1]byte
	n, err := src.Read(extra[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		return fmt.Errorf("codewire: cw runtime candidate did not end at its admitted size")
	}
	return nil
}

func (r *CwRuntime) Update(ctx context.Context, header *codewirev1.UpdateEnvironmentCwRuntimeHeader, source io.Reader) (*codewirev1.EnvironmentCwRuntimeOperation, error) {
	if header == nil || header.OrgId != r.orgID || header.EnvironmentId != r.envID || header.RequestId == "" || header.Identity == nil || source == nil ||
		header.Identity.Size < 64 || header.Identity.Size > cwRuntimeMaximumBytes || proto.Size(header) > 32*1024 {
		return nil, fmt.Errorf("codewire: cw runtime header or scope is invalid")
	}
	header = proto.Clone(header).(*codewirev1.UpdateEnvironmentCwRuntimeHeader)
	ctx, cancel := context.WithTimeout(ctx, cwRuntimeMutationTimeout)
	defer cancel()
	stream := r.client.UpdateEnvironmentCwRuntime(ctx)
	unknown := func(err error) (*codewirev1.EnvironmentCwRuntimeOperation, error) {
		return nil, &CwRuntimeOutcomeUnknownError{RequestID: header.RequestId, Cause: connectSDKError(err)}
	}
	if err := stream.Send(&codewirev1.UpdateEnvironmentCwRuntimeRequest{Payload: &codewirev1.UpdateEnvironmentCwRuntimeRequest_Header{Header: header}}); err != nil {
		return unknown(err)
	}
	err := streamCwCandidate(source, header.Identity.Size, func(chunk []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return stream.Send(&codewirev1.UpdateEnvironmentCwRuntimeRequest{Payload: &codewirev1.UpdateEnvironmentCwRuntimeRequest_Chunk{Chunk: chunk}})
	})
	if err != nil {
		return unknown(err)
	}
	response, err := stream.CloseAndReceive()
	if err != nil {
		return unknown(err)
	}
	if response.Msg.Operation == nil || response.Msg.Operation.RequestId != header.RequestId {
		return unknown(fmt.Errorf("cw runtime response omitted original request"))
	}
	return response.Msg.Operation, nil
}

func (r *CwRuntime) Rollback(ctx context.Context, request *codewirev1.RollbackEnvironmentCwRuntimeRequest) (*codewirev1.EnvironmentCwRuntimeOperation, error) {
	if request == nil || request.OrgId != r.orgID || request.EnvironmentId != r.envID || request.RequestId == "" || proto.Size(request) > 32*1024 {
		return nil, fmt.Errorf("codewire: cw runtime request scope is invalid")
	}
	request = proto.Clone(request).(*codewirev1.RollbackEnvironmentCwRuntimeRequest)
	ctx, cancel := context.WithTimeout(ctx, cwRuntimeMutationTimeout)
	defer cancel()
	response, err := r.client.RollbackEnvironmentCwRuntime(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, &CwRuntimeOutcomeUnknownError{RequestID: request.RequestId, Cause: connectSDKError(err)}
	}
	if response.Msg.Operation == nil || response.Msg.Operation.RequestId != request.RequestId {
		return nil, &CwRuntimeOutcomeUnknownError{RequestID: request.RequestId}
	}
	return response.Msg.Operation, nil
}

func (r *CwRuntime) Observe(ctx context.Context, requestID string) (*codewirev1.EnvironmentCwRuntimeOperation, error) {
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	response, err := r.client.ObserveEnvironmentCwRuntime(ctx, connect.NewRequest(&codewirev1.ObserveEnvironmentCwRuntimeRequest{OrgId: r.orgID, EnvironmentId: r.envID, RequestId: requestID}))
	if err != nil {
		return nil, connectSDKError(err)
	}
	if response.Msg.Operation == nil || response.Msg.Operation.RequestId != requestID {
		return nil, fmt.Errorf("codewire: cw runtime observation omitted original request")
	}
	return response.Msg.Operation, nil
}
