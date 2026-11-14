import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class NetworkPolicyEnforcement(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    NETWORK_POLICY_ENFORCEMENT_UNSPECIFIED: _ClassVar[NetworkPolicyEnforcement]
    NETWORK_POLICY_ENFORCEMENT_NOT_ENFORCED: _ClassVar[NetworkPolicyEnforcement]
    NETWORK_POLICY_ENFORCEMENT_ENFORCED: _ClassVar[NetworkPolicyEnforcement]
    NETWORK_POLICY_ENFORCEMENT_ENFORCING: _ClassVar[NetworkPolicyEnforcement]
    NETWORK_POLICY_ENFORCEMENT_FAILED_CLOSED: _ClassVar[NetworkPolicyEnforcement]
NETWORK_POLICY_ENFORCEMENT_UNSPECIFIED: NetworkPolicyEnforcement
NETWORK_POLICY_ENFORCEMENT_NOT_ENFORCED: NetworkPolicyEnforcement
NETWORK_POLICY_ENFORCEMENT_ENFORCED: NetworkPolicyEnforcement
NETWORK_POLICY_ENFORCEMENT_ENFORCING: NetworkPolicyEnforcement
NETWORK_POLICY_ENFORCEMENT_FAILED_CLOSED: NetworkPolicyEnforcement

class NetworkPolicySelector(_message.Message):
    __slots__ = ("name", "id")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    name: str
    id: str
    def __init__(self, name: _Optional[str] = ..., id: _Optional[str] = ...) -> None: ...

class NetworkPolicyRule(_message.Message):
    __slots__ = ("target", "ports")
    TARGET_FIELD_NUMBER: _ClassVar[int]
    PORTS_FIELD_NUMBER: _ClassVar[int]
    target: str
    ports: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, target: _Optional[str] = ..., ports: _Optional[_Iterable[int]] = ...) -> None: ...

class NetworkPolicy(_message.Message):
    __slots__ = ("id", "org_id", "name", "revision", "current_revision", "rules", "digest", "created_at", "created_by")
    ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    CURRENT_REVISION_FIELD_NUMBER: _ClassVar[int]
    RULES_FIELD_NUMBER: _ClassVar[int]
    DIGEST_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    CREATED_BY_FIELD_NUMBER: _ClassVar[int]
    id: str
    org_id: str
    name: str
    revision: int
    current_revision: int
    rules: _containers.RepeatedCompositeFieldContainer[NetworkPolicyRule]
    digest: str
    created_at: _timestamp_pb2.Timestamp
    created_by: str
    def __init__(self, id: _Optional[str] = ..., org_id: _Optional[str] = ..., name: _Optional[str] = ..., revision: _Optional[int] = ..., current_revision: _Optional[int] = ..., rules: _Optional[_Iterable[_Union[NetworkPolicyRule, _Mapping]]] = ..., digest: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., created_by: _Optional[str] = ...) -> None: ...

class CreateNetworkPolicyRequest(_message.Message):
    __slots__ = ("org_id", "name", "allow")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    FROM_FIELD_NUMBER: _ClassVar[int]
    ALLOW_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    name: str
    allow: _containers.RepeatedCompositeFieldContainer[NetworkPolicyRule]
    def __init__(self, org_id: _Optional[str] = ..., name: _Optional[str] = ..., allow: _Optional[_Iterable[_Union[NetworkPolicyRule, _Mapping]]] = ..., **kwargs) -> None: ...

class CreateNetworkPolicyResponse(_message.Message):
    __slots__ = ("policy",)
    POLICY_FIELD_NUMBER: _ClassVar[int]
    policy: NetworkPolicy
    def __init__(self, policy: _Optional[_Union[NetworkPolicy, _Mapping]] = ...) -> None: ...

class ListNetworkPoliciesRequest(_message.Message):
    __slots__ = ("org_id",)
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    def __init__(self, org_id: _Optional[str] = ...) -> None: ...

class ListNetworkPoliciesResponse(_message.Message):
    __slots__ = ("policies",)
    POLICIES_FIELD_NUMBER: _ClassVar[int]
    policies: _containers.RepeatedCompositeFieldContainer[NetworkPolicy]
    def __init__(self, policies: _Optional[_Iterable[_Union[NetworkPolicy, _Mapping]]] = ...) -> None: ...

class GetNetworkPolicyRequest(_message.Message):
    __slots__ = ("org_id", "policy", "revision")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    policy: NetworkPolicySelector
    revision: int
    def __init__(self, org_id: _Optional[str] = ..., policy: _Optional[_Union[NetworkPolicySelector, _Mapping]] = ..., revision: _Optional[int] = ...) -> None: ...

class GetNetworkPolicyResponse(_message.Message):
    __slots__ = ("policy",)
    POLICY_FIELD_NUMBER: _ClassVar[int]
    policy: NetworkPolicy
    def __init__(self, policy: _Optional[_Union[NetworkPolicy, _Mapping]] = ...) -> None: ...

class UpdateNetworkPolicyRequest(_message.Message):
    __slots__ = ("org_id", "policy", "allow", "remove", "expected_revision")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    ALLOW_FIELD_NUMBER: _ClassVar[int]
    REMOVE_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    policy: NetworkPolicySelector
    allow: _containers.RepeatedCompositeFieldContainer[NetworkPolicyRule]
    remove: _containers.RepeatedScalarFieldContainer[str]
    expected_revision: int
    def __init__(self, org_id: _Optional[str] = ..., policy: _Optional[_Union[NetworkPolicySelector, _Mapping]] = ..., allow: _Optional[_Iterable[_Union[NetworkPolicyRule, _Mapping]]] = ..., remove: _Optional[_Iterable[str]] = ..., expected_revision: _Optional[int] = ...) -> None: ...

class UpdateNetworkPolicyResponse(_message.Message):
    __slots__ = ("policy",)
    POLICY_FIELD_NUMBER: _ClassVar[int]
    policy: NetworkPolicy
    def __init__(self, policy: _Optional[_Union[NetworkPolicy, _Mapping]] = ...) -> None: ...

class DeleteNetworkPolicyRequest(_message.Message):
    __slots__ = ("org_id", "policy")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    policy: NetworkPolicySelector
    def __init__(self, org_id: _Optional[str] = ..., policy: _Optional[_Union[NetworkPolicySelector, _Mapping]] = ...) -> None: ...

class DeleteNetworkPolicyResponse(_message.Message):
    __slots__ = ("policy",)
    POLICY_FIELD_NUMBER: _ClassVar[int]
    policy: NetworkPolicy
    def __init__(self, policy: _Optional[_Union[NetworkPolicy, _Mapping]] = ...) -> None: ...

class UpdateEnvironmentNetworkPolicyRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "network_policy")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_POLICY_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    network_policy: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., network_policy: _Optional[str] = ...) -> None: ...

class UpdateEnvironmentNetworkPolicyResponse(_message.Message):
    __slots__ = ("network_policy",)
    NETWORK_POLICY_FIELD_NUMBER: _ClassVar[int]
    network_policy: EnvironmentNetworkPolicy
    def __init__(self, network_policy: _Optional[_Union[EnvironmentNetworkPolicy, _Mapping]] = ...) -> None: ...

class EnvironmentNetworkPolicy(_message.Message):
    __slots__ = ("reference", "name", "revision", "digest", "enforcement", "enforced_revision", "enforced_digest", "enforced_at")
    REFERENCE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    DIGEST_FIELD_NUMBER: _ClassVar[int]
    ENFORCEMENT_FIELD_NUMBER: _ClassVar[int]
    ENFORCED_REVISION_FIELD_NUMBER: _ClassVar[int]
    ENFORCED_DIGEST_FIELD_NUMBER: _ClassVar[int]
    ENFORCED_AT_FIELD_NUMBER: _ClassVar[int]
    reference: str
    name: str
    revision: int
    digest: str
    enforcement: NetworkPolicyEnforcement
    enforced_revision: int
    enforced_digest: str
    enforced_at: _timestamp_pb2.Timestamp
    def __init__(self, reference: _Optional[str] = ..., name: _Optional[str] = ..., revision: _Optional[int] = ..., digest: _Optional[str] = ..., enforcement: _Optional[_Union[NetworkPolicyEnforcement, str]] = ..., enforced_revision: _Optional[int] = ..., enforced_digest: _Optional[str] = ..., enforced_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...
