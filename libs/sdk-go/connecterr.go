package codewire

import (
	"errors"
	"fmt"
	"net/http"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protowire"
)

func connectSDKError(err error) error {
	if err == nil {
		return nil
	}

	var connectError *connect.Error
	if !errors.As(err, &connectError) {
		return fmt.Errorf("codewire: request: %w", err)
	}

	sdkError := &Error{
		StatusCode: connectStatusCode(connectError.Code()),
		Detail:     connectError.Message(),
		RequestID:  connectError.Meta().Get("X-Request-Id"),
	}
	for _, detail := range connectError.Details() {
		switch detail.Type() {
		case "google.rpc.ErrorInfo":
			if requestID := requestIDFromErrorInfo(detail.Bytes()); requestID != "" {
				sdkError.RequestID = requestID
			}
		case "google.rpc.BadRequest":
			sdkError.violations = append(sdkError.violations, fieldViolationsFromBadRequest(detail.Bytes())...)
		}
	}
	return sdkError
}

func connectStatusCode(code connect.Code) int {
	switch code {
	case connect.CodeCanceled:
		return 499
	case connect.CodeInvalidArgument, connect.CodeFailedPrecondition, connect.CodeOutOfRange:
		return http.StatusBadRequest
	case connect.CodeDeadlineExceeded:
		return http.StatusGatewayTimeout
	case connect.CodeNotFound:
		return http.StatusNotFound
	case connect.CodeAlreadyExists, connect.CodeAborted:
		return http.StatusConflict
	case connect.CodePermissionDenied:
		return http.StatusForbidden
	case connect.CodeResourceExhausted:
		return http.StatusTooManyRequests
	case connect.CodeUnimplemented:
		return http.StatusNotImplemented
	case connect.CodeUnavailable:
		return http.StatusServiceUnavailable
	case connect.CodeUnauthenticated:
		return http.StatusUnauthorized
	case connect.CodeUnknown, connect.CodeInternal, connect.CodeDataLoss:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

func requestIDFromErrorInfo(message []byte) string {
	for len(message) > 0 {
		number, kind, length := protowire.ConsumeTag(message)
		if length < 0 {
			return ""
		}
		message = message[length:]
		if number == 3 && kind == protowire.BytesType {
			entry, consumed := protowire.ConsumeBytes(message)
			if consumed < 0 {
				return ""
			}
			if key, value, ok := stringMapEntry(entry); ok && key == "request_id" {
				return value
			}
			message = message[consumed:]
			continue
		}
		consumed := protowire.ConsumeFieldValue(number, kind, message)
		if consumed < 0 {
			return ""
		}
		message = message[consumed:]
	}
	return ""
}

func fieldViolationsFromBadRequest(message []byte) []FieldViolation {
	var violations []FieldViolation
	for len(message) > 0 {
		number, kind, length := protowire.ConsumeTag(message)
		if length < 0 {
			return violations
		}
		message = message[length:]
		if number == 1 && kind == protowire.BytesType {
			encoded, consumed := protowire.ConsumeBytes(message)
			if consumed < 0 {
				return violations
			}
			violation := fieldViolationFromProto(encoded)
			if violation.Field != "" || violation.Message != "" {
				violations = append(violations, violation)
			}
			message = message[consumed:]
			continue
		}
		consumed := protowire.ConsumeFieldValue(number, kind, message)
		if consumed < 0 {
			return violations
		}
		message = message[consumed:]
	}
	return violations
}

func fieldViolationFromProto(message []byte) FieldViolation {
	var violation FieldViolation
	for len(message) > 0 {
		number, kind, length := protowire.ConsumeTag(message)
		if length < 0 {
			return violation
		}
		message = message[length:]
		if kind == protowire.BytesType {
			value, consumed := protowire.ConsumeString(message)
			if consumed < 0 {
				return violation
			}
			switch number {
			case 1:
				violation.Field = value
			case 2:
				violation.Message = value
			}
			message = message[consumed:]
			continue
		}
		consumed := protowire.ConsumeFieldValue(number, kind, message)
		if consumed < 0 {
			return violation
		}
		message = message[consumed:]
	}
	return violation
}

func stringMapEntry(message []byte) (string, string, bool) {
	var key, value string
	var haveKey, haveValue bool
	for len(message) > 0 {
		number, kind, length := protowire.ConsumeTag(message)
		if length < 0 {
			return "", "", false
		}
		message = message[length:]
		if kind == protowire.BytesType {
			part, consumed := protowire.ConsumeString(message)
			if consumed < 0 {
				return "", "", false
			}
			switch number {
			case 1:
				key, haveKey = part, true
			case 2:
				value, haveValue = part, true
			}
			message = message[consumed:]
			continue
		}
		consumed := protowire.ConsumeFieldValue(number, kind, message)
		if consumed < 0 {
			return "", "", false
		}
		message = message[consumed:]
	}
	return key, value, haveKey && haveValue
}
