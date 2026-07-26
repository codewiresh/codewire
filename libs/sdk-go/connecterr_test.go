package codewire

import (
	"errors"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestConnectSDKErrorUsesCanonicalStatusAndDetails(t *testing.T) {
	badRequest := appendBytesField(nil, 1, appendStringField(appendStringField(nil, 1, "disabled"), 2, "must be set"))
	errorInfo := appendBytesField(nil, 3, appendStringField(appendStringField(nil, 1, "request_id"), 2, "detail-request-id"))
	badRequestDetail, err := connect.NewErrorDetail(&anypb.Any{
		TypeUrl: "type.googleapis.com/google.rpc.BadRequest",
		Value:   badRequest,
	})
	if err != nil {
		t.Fatalf("BadRequest detail: %v", err)
	}
	errorInfoDetail, err := connect.NewErrorDetail(&anypb.Any{
		TypeUrl: "type.googleapis.com/google.rpc.ErrorInfo",
		Value:   errorInfo,
	})
	if err != nil {
		t.Fatalf("ErrorInfo detail: %v", err)
	}

	connectError := connect.NewError(connect.CodeInvalidArgument, errors.New("invalid API key"))
	connectError.Meta().Set("X-Request-Id", "header-request-id")
	connectError.AddDetail(badRequestDetail)
	connectError.AddDetail(errorInfoDetail)

	got, ok := connectSDKError(connectError).(*Error)
	if !ok {
		t.Fatalf("unexpected error type: %T", connectSDKError(connectError))
	}
	if got.StatusCode != 400 || got.Detail != "invalid API key" || got.RequestID != "detail-request-id" {
		t.Errorf("unexpected API error: %#v", got)
	}
	if len(got.Violations()) != 1 || got.Violations()[0] != (FieldViolation{Field: "disabled", Message: "must be set"}) {
		t.Errorf("unexpected violations: %#v", got.Violations())
	}
}

func TestConnectStatusCode(t *testing.T) {
	for _, test := range []struct {
		code connect.Code
		want int
	}{
		{connect.CodeCanceled, 499},
		{connect.CodeInvalidArgument, 400},
		{connect.CodeDeadlineExceeded, 504},
		{connect.CodeNotFound, 404},
		{connect.CodeAlreadyExists, 409},
		{connect.CodePermissionDenied, 403},
		{connect.CodeResourceExhausted, 429},
		{connect.CodeFailedPrecondition, 400},
		{connect.CodeAborted, 409},
		{connect.CodeOutOfRange, 400},
		{connect.CodeUnimplemented, 501},
		{connect.CodeInternal, 500},
		{connect.CodeUnavailable, 503},
		{connect.CodeDataLoss, 500},
		{connect.CodeUnauthenticated, 401},
	} {
		if got := connectStatusCode(test.code); got != test.want {
			t.Errorf("%s = %d, want %d", test.code, got, test.want)
		}
	}
}

func appendStringField(message []byte, number protowire.Number, value string) []byte {
	message = protowire.AppendTag(message, number, protowire.BytesType)
	return protowire.AppendString(message, value)
}

func appendBytesField(message []byte, number protowire.Number, value []byte) []byte {
	message = protowire.AppendTag(message, number, protowire.BytesType)
	return protowire.AppendBytes(message, value)
}
