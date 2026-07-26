from pkgutil import extend_path

# The checked-in generated ``codewire.v1`` modules live beside this package
# during source-tree tests and are folded into it when the wheel is built.
__path__ = extend_path(__path__, __name__)

from codewire.client import Codewire
from codewire.environment import Environment
from codewire.errors import CodewireError
from codewire.files import Files
from codewire.local import (
    LocalError,
    LocalExecResult,
    LocalInstance,
    LocalMount,
    LocalPort,
    LocalService,
    LocalSpec,
    LocalSpecMount,
    LocalSpecPort,
)
from codewire.mesh import (
    MeshClient,
    MeshCredentials,
    MeshEnrollment,
    MeshGroup,
    MeshGroupMember,
    MeshGroupPolicy,
    MeshGroups,
    MeshKV,
    MeshKVEntry,
    MeshNetwork,
    MeshNetworks,
    MeshNode,
    MeshNodeCredentials,
    MeshNodes,
    MeshRuntimeCredential,
    MeshSenderDelegation,
    MeshVerifierBundle,
    MeshVerifierKey,
)

__all__ = [
    "Codewire",
    "Environment",
    "CodewireError",
    "Files",
    "LocalError",
    "LocalExecResult",
    "LocalInstance",
    "LocalMount",
    "LocalPort",
    "LocalService",
    "LocalSpec",
    "LocalSpecMount",
    "LocalSpecPort",
    "MeshClient",
    "MeshCredentials",
    "MeshEnrollment",
    "MeshGroup",
    "MeshGroupMember",
    "MeshGroupPolicy",
    "MeshGroups",
    "MeshKV",
    "MeshKVEntry",
    "MeshNetwork",
    "MeshNetworks",
    "MeshNode",
    "MeshNodeCredentials",
    "MeshNodes",
    "MeshRuntimeCredential",
    "MeshSenderDelegation",
    "MeshVerifierBundle",
    "MeshVerifierKey",
]
