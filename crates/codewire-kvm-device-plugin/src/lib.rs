//! The node's `/dev/kvm` device plugin for the `standard` runtime profile
//! (`docs/dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md`, "The device"). It registers
//! the extended resource `codewire.sh/kvm` with the kubelet and, for each
//! container given one, has the kubelet add the node's `/dev/kvm` to it with
//! read and write access and nothing else.
#![forbid(unsafe_code)]

mod plugin;
mod serve;

pub use serve::{Config, Error, run};

/// The kubelet's device plugin protocol, compiled from
/// `proto/deviceplugin/v1beta1/api.proto`.
pub mod v1beta1 {
    tonic::include_proto!("v1beta1");
}

/// The extended resource a Pod requests to be given `/dev/kvm`.
pub const RESOURCE_NAME: &str = "codewire.sh/kvm";

/// The kubelet's device plugin directory on a node: its registration socket
/// and every plugin's own socket.
pub const KUBELET_PLUGIN_DIR: &str = "/var/lib/kubelet/device-plugins";

/// The kubelet's registration socket, in [`KUBELET_PLUGIN_DIR`].
pub const KUBELET_SOCKET: &str = "kubelet.sock";

/// This plugin's socket, in [`KUBELET_PLUGIN_DIR`].
pub const PLUGIN_SOCKET: &str = "codewire-kvm.sock";

/// Where the device appears in a container, whatever the node's path.
pub const CONTAINER_DEVICE: &str = "/dev/kvm";
