from __future__ import annotations

from connectrpc.code import Code
from connectrpc.errors import ConnectError
from google.protobuf.message import DecodeError
from google.rpc.error_details_pb2 import BadRequest, ErrorInfo


class CodewireError(Exception):
    def __init__(
        self,
        status: int,
        detail: str,
        request_id: str = "",
        violations: list[dict[str, str]] | None = None,
    ):
        self.status = status
        self.detail = detail
        self.request_id = request_id
        self.violations = violations or []
        msg = f"Codewire API error {status}: {detail}"
        if request_id:
            msg += f" (request_id: {request_id})"
        super().__init__(msg)


_CONNECT_STATUS = {
    Code.CANCELED: 499,
    Code.INVALID_ARGUMENT: 400,
    Code.FAILED_PRECONDITION: 400,
    Code.OUT_OF_RANGE: 400,
    Code.DEADLINE_EXCEEDED: 504,
    Code.NOT_FOUND: 404,
    Code.ALREADY_EXISTS: 409,
    Code.ABORTED: 409,
    Code.PERMISSION_DENIED: 403,
    Code.RESOURCE_EXHAUSTED: 429,
    Code.UNIMPLEMENTED: 501,
    Code.UNAVAILABLE: 503,
    Code.UNAUTHENTICATED: 401,
    Code.UNKNOWN: 500,
    Code.INTERNAL: 500,
    Code.DATA_LOSS: 500,
}


def codewire_error_from_connect(error: ConnectError) -> CodewireError:
    """Map one generated-runtime error into the stable SDK error shape."""
    violations: list[dict[str, str]] = []
    request_id = ""
    for detail in error.details:
        if detail.type_name == "google.rpc.BadRequest":
            bad_request = _decode_detail(detail.message_bytes, BadRequest)
            if bad_request is not None:
                violations.extend(
                    {
                        "field": violation.field,
                        "description": violation.description,
                    }
                    for violation in bad_request.field_violations
                )
        elif detail.type_name == "google.rpc.ErrorInfo" and not request_id:
            error_info = _decode_detail(detail.message_bytes, ErrorInfo)
            if error_info is not None:
                request_id = error_info.metadata.get("request_id", "")
    return CodewireError(
        _CONNECT_STATUS[error.code],
        error.message,
        request_id,
        violations,
    )


def _decode_detail(data: bytes, message_type: type[BadRequest] | type[ErrorInfo]):
    """Decode a standard ``google.rpc`` detail from Connect's raw Any bytes.

    ``connectrpc`` owns the outer ``Any`` representation while generated
    Codewire messages use ``google.protobuf``. Decoding the wire payload here
    keeps that runtime implementation detail out of the SDK's public API.
    """
    message = message_type()
    try:
        message.ParseFromString(data)
    except DecodeError:
        return None
    return message
