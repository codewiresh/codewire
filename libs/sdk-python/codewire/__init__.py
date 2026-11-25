from pkgutil import extend_path

# The checked-in generated ``codewire.v1`` modules live beside this package
# during source-tree tests and are folded into it when the wheel is built.
__path__ = extend_path(__path__, __name__)

from codewire.client import Codewire
from codewire.environment import Environment
from codewire.errors import CodewireError
from codewire.files import Files
from codewire.cw_runtime import CwRuntime, CwRuntimeOutcomeUnknownError
from codewire.desktop import Desktop
from codewire.platform_agents import PlatformAgents, PlatformAgentOutcomeUnknownError
from codewire.credentials import (
    Credentials, Credential, GithubPendingPermissions, GithubRepository, GithubRepositoryPage, SshPublicKey,
    CodexDeviceChallenge, CodexEnrollmentEvent,
    EnrollmentOutcomeUnknownError,
)
from codewire.access_profiles import (
    AccessProfiles,
    AccessProfile,
    AccessProfileEntry,
    EnvironmentAccessProfile,
    EnvironmentAccessProfileBinding,
)
from codewire.network_policies import (
    EnvironmentNetworkPolicy,
    NetworkPolicies,
    NetworkPolicy,
    NetworkPolicyRule,
)
from codewire.sandbox_identity import (
    EnvironmentIdentityGroups,
    IdentityAudience,
    IdentityGroupUser,
    SandboxIdentity,
    SetEnvironmentIdentityGroupsResult,
)
from codewire.audit import (
    Audit,
    AuditAccess,
    AuditActor,
    AuditApiKey,
    AuditCredentials,
    AuditEnvironment,
    AuditEvent,
    AuditEventKind,
    AuditEventPage,
    AuditLifecycle,
    AuditPolicyChange,
    AuditPolicyRevision,
    AuditRefusal,
    AuditRefusalOverflow,
    AuditSize,
    AuditUser,
)
from codewire.mesh import (
    MeshClient,
    MeshEnrollment,
    MeshGroup,
    MeshGroupDebugPolicy,
    MeshGroupMember,
    MeshGroupMessagesPolicy,
    MeshGroupPolicy,
    MeshGroups,
    MeshKV,
    MeshKVEntry,
    MeshNetwork,
    MeshNetworks,
    MeshNode,
    MeshNodeRegistration,
    MeshNodes,
)

__all__ = [
    "Codewire",
    "Environment",
    "CodewireError",
    "Files",
    "CwRuntime",
    "CwRuntimeOutcomeUnknownError",
    "Desktop",
    "PlatformAgents",
    "PlatformAgentOutcomeUnknownError",
    "Credentials",
    "Credential",
    "GithubPendingPermissions",
    "GithubRepository",
    "GithubRepositoryPage",
    "SshPublicKey",
    "CodexDeviceChallenge",
    "CodexEnrollmentEvent",
    "EnrollmentOutcomeUnknownError",
    "AccessProfiles",
    "AccessProfile",
    "AccessProfileEntry",
    "EnvironmentAccessProfile",
    "EnvironmentAccessProfileBinding",
    "EnvironmentNetworkPolicy",
    "NetworkPolicies",
    "NetworkPolicy",
    "NetworkPolicyRule",
    "SandboxIdentity",
    "EnvironmentIdentityGroups",
    "IdentityAudience",
    "IdentityGroupUser",
    "SetEnvironmentIdentityGroupsResult",
    "Audit",
    "AuditAccess",
    "AuditActor",
    "AuditApiKey",
    "AuditCredentials",
    "AuditEnvironment",
    "AuditEvent",
    "AuditEventKind",
    "AuditEventPage",
    "AuditLifecycle",
    "AuditPolicyChange",
    "AuditPolicyRevision",
    "AuditRefusal",
    "AuditRefusalOverflow",
    "AuditSize",
    "AuditUser",
    "MeshClient",
    "MeshEnrollment",
    "MeshGroup",
    "MeshGroupDebugPolicy",
    "MeshGroupMember",
    "MeshGroupMessagesPolicy",
    "MeshGroupPolicy",
    "MeshGroups",
    "MeshKV",
    "MeshKVEntry",
    "MeshNetwork",
    "MeshNetworks",
    "MeshNode",
    "MeshNodeRegistration",
    "MeshNodes",
]
