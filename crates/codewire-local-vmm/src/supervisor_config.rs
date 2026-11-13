//! Shared native-supervisor configuration and private compatibility contract.
//!
//! This module admits configuration and protocol values, not host ownership.
//! It performs no process spawning, store/replay, credential or VM effects.
//! Platform control entrypoints remain responsible for those boundaries.

use std::fs;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::control::v1;

// Bump for every detached-supervisor behavior change, even if the protobuf
// message layout itself remains wire-compatible. Linux and Darwin serve the
// same shared supervisor; Darwin's former stopped-state dispatcher was 8.
pub const NATIVE_SUPERVISOR_PROTOCOL_VERSION: u32 = 22;
/// The oldest supervisor protocol this cw works with: v0.3.388's (#2826). After a cw
/// update, a supervisor in [minimum, current] keeps serving its VMs; only an
/// idle older one is replaced (`supervisor_upgrade`).
pub const MINIMUM_SUPERVISOR_PROTOCOL_VERSION: u32 = 10;

/// What each protocol after the minimum changed, oldest first. Every protocol
/// in (minimum, current] has a row, so a bump says what an older supervisor
/// lacks; a client checks [`SupervisorFeature`] before using anything newer.
pub const SUPERVISOR_PROTOCOL_CHANGES: &[(u32, &str)] = &[
    (
        11,
        "sockets in the short per-user socket directory (#2735); no RPC change",
    ),
    (
        12,
        "RetireSupervisor (for its own protocol or a newer one); a stopped environment's runner of another cw is retired; the pre-#2735 runners directory is removed only under the lock",
    ),
    (
        13,
        "create keeps codewire.yaml workspace.vm_only paths on the VM's own disk (LocalMountInput.vm_only, CreateEnvironmentRequest.implicit_vm_only); an older supervisor would ignore them",
    ),
    (
        14,
        "workspace.vm_only entries are .dockerignore-style patterns: a copy skips every matching folder and the guest expands them at every boot; an older supervisor would treat them as plain paths",
    ),
    (
        15,
        "SSH (#3025): OpenEnvironmentSshStream, and GetEnvironmentHostKey answers with the environment's host key",
    ),
    (
        16,
        "network policies (#2537): CreateNetworkPolicy, ListNetworkPolicies, GetNetworkPolicy, UpdateNetworkPolicy and DeleteNetworkPolicy over the host's policy store",
    ),
    (
        17,
        "network policy selection (#2537): CreateEnvironmentRequest.network_policy, UpdateEnvironmentNetworkPolicy and Environment.network_policy; an older supervisor would ignore the selection and enforce `open`",
    ),
    (
        18,
        "live network policies (#2537): an edit to a selected policy, or a new selection, applies to a running VM's egress broker at once and ends the flows it refuses; NetworkPolicy.enforced_in and restart_required_in name those VMs; an older supervisor applies it at the next start",
    ),
    (
        19,
        "local disk snapshots (#3046, Linux): LocalSnapshotService (CreateSnapshot, ListSnapshots, GetSnapshot, DeleteSnapshot) and CreateEnvironmentRequest.snapshot; an older supervisor would refuse a create journaled from a snapshot as an invalid replay",
    ),
    (
        20,
        "VM checkpoints (#3046 R4, Linux): LocalCheckpointService (CreateCheckpoint, ListCheckpoints, GetCheckpoint, DeleteCheckpoint), runner protocol 10 (CheckpointVm), snapshots.db schema 3; an older supervisor cannot open the store after this one migrated it",
    ),
    (
        21,
        "retained images (#4262): the newest pulled image of each of at most two repositories survives its last environment's removal, recorded in a supervisor_metadata row an older supervisor ignores; LocalImageCacheService (PruneImages) forgets them and collects",
    ),
    (
        22,
        "operations by request ID (#3609): GetOperation also names an operation by the lifecycle request ID it was journaled for, so a host agent tells a request it already sent from a new one; an older supervisor refuses such a request as an invalid operation ID",
    ),
];

/// A supervisor capability newer than the minimum protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorFeature {
    /// `RetireSupervisor`: an idle supervisor hands its root to a newer one.
    Retire,
    /// `OpenEnvironmentSshStream` and the local `GetEnvironmentHostKey`.
    Ssh,
    /// The network policy RPCs.
    NetworkPolicies,
    /// Selecting a network policy for an environment.
    NetworkPolicySelection,
    /// Local disk snapshots and creating environments from them.
    LocalSnapshots,
    /// VM checkpoints of running local VMs.
    LocalCheckpoints,
    /// Retained images and `PruneImages`.
    LocalImageCache,
    /// `GetOperation` by request ID.
    OperationByRequest,
}

impl SupervisorFeature {
    pub const ALL: [Self; 8] = [
        Self::Retire,
        Self::Ssh,
        Self::NetworkPolicies,
        Self::NetworkPolicySelection,
        Self::LocalSnapshots,
        Self::LocalCheckpoints,
        Self::LocalImageCache,
        Self::OperationByRequest,
    ];

    /// The protocol that introduced it.
    pub const fn since(self) -> u32 {
        match self {
            Self::Retire => 12,
            Self::Ssh => 15,
            Self::NetworkPolicies => 16,
            Self::NetworkPolicySelection => 17,
            Self::LocalSnapshots => 19,
            Self::LocalCheckpoints => 20,
            Self::LocalImageCache => 21,
            Self::OperationByRequest => 22,
        }
    }
}

/// Why a supervisor outside the supported range cannot serve this cw.
pub(crate) fn unsupported_protocol_message(actual: u32) -> String {
    let supported = format!(
        "this cw works with {MINIMUM_SUPERVISOR_PROTOCOL_VERSION} to {NATIVE_SUPERVISOR_PROTOCOL_VERSION}"
    );
    if actual > NATIVE_SUPERVISOR_PROTOCOL_VERSION {
        format!(
            "a newer cw runs your local VMs (local VM supervisor protocol {actual}; {supported}); use that cw, or update this one"
        )
    } else {
        format!(
            "an older cw runs your local VMs (local VM supervisor protocol {actual}; {supported}); stop its VMs with that cw, then end its `cw __native-supervisor` process"
        )
    }
}
const NATIVE_SUPERVISOR_CONFIG_DIGEST_DOMAIN: &[u8] =
    b"codewire.native-supervisor.runtime-config.sha256.v1";

#[derive(Debug, Clone)]
pub struct NativeRuntimeConfig {
    pub root: PathBuf,
    pub artifact_root: PathBuf,
    pub artifact_lock: PathBuf,
    pub mesh_data_dir: PathBuf,
    pub platform_config_dir: PathBuf,
    pub credential_authority_root: PathBuf,
    pub executable: PathBuf,
}

impl NativeRuntimeConfig {
    /// Bind a retained supervisor without changing any other configuration input.
    /// The caller admits this executable from the live kernel peer first.
    pub(crate) fn with_supervisor_executable(
        &self,
        executable: PathBuf,
    ) -> Result<Self, SupervisorConfigError> {
        let mut retained = self.clone();
        retained.executable = executable;
        retained.validate()?;
        Ok(retained)
    }

    pub fn cw_runtime_lock(&self) -> PathBuf {
        self.artifact_lock.with_file_name("cw-runtime.lock.json")
    }

    /// This root's short private socket directory (#2735); see
    /// [`crate::socket_dir`]. The supervisor creates it.
    pub fn socket_dir(&self) -> PathBuf {
        crate::socket_dir::predicted(&self.root)
    }

    pub fn supervisor_socket(&self) -> PathBuf {
        self.socket_dir().join("supervisor.sock")
    }

    pub fn runner_socket(&self, environment_id: impl std::fmt::Display) -> PathBuf {
        self.socket_dir()
            .join("runners")
            .join(format!("{environment_id}.sock"))
    }

    /// The exact arguments a supervisor for this configuration runs with, as
    /// `spawn_supervisor` starts it. Peer admission compares them.
    pub(crate) fn supervisor_argv(&self) -> Vec<std::ffi::OsString> {
        let mut argv = vec![
            self.executable.as_os_str().to_owned(),
            "__native-supervisor".into(),
        ];
        for (flag, path) in self.supervisor_flags() {
            argv.push(flag.into());
            argv.push(path.as_os_str().to_owned());
        }
        argv
    }

    /// Each configuration flag of [`Self::supervisor_argv`] with its value.
    pub(crate) fn supervisor_flags(&self) -> [(&'static str, &Path); 6] {
        [
            ("--root", &self.root),
            ("--artifact-root", &self.artifact_root),
            ("--artifact-lock", &self.artifact_lock),
            ("--mesh-data-dir", &self.mesh_data_dir),
            ("--platform-config-dir", &self.platform_config_dir),
            (
                "--credential-authority-root",
                &self.credential_authority_root,
            ),
        ]
    }

    /// Where a supervisor from before #2735 (protocol 10 and earlier) listens
    /// until it exits: in the state root itself.
    pub fn legacy_supervisor_socket(&self) -> PathBuf {
        self.root.join("supervisor.sock")
    }

    /// Where a runner a supervisor from before #2735 started listens until it
    /// exits. On Linux it outlives that supervisor.
    pub fn legacy_runner_socket(&self, environment_id: impl std::fmt::Display) -> PathBuf {
        self.root
            .join("runners")
            .join(format!("{environment_id}.sock"))
    }

    pub fn validate(&self) -> Result<(), SupervisorConfigError> {
        for path in [
            &self.root,
            &self.artifact_root,
            &self.artifact_lock,
            &self.mesh_data_dir,
            &self.platform_config_dir,
            &self.credential_authority_root,
            &self.executable,
        ] {
            if !path.is_absolute() {
                return Err(SupervisorConfigError::InvalidConfiguration);
            }
        }
        if self.artifact_root.parent() != self.artifact_lock.parent() {
            return Err(SupervisorConfigError::InvalidConfiguration);
        }
        let executable =
            fs::canonicalize(&self.executable).map_err(|source| SupervisorConfigError::Io {
                path: self.executable.clone(),
                source,
            })?;
        if executable != self.executable {
            return Err(SupervisorConfigError::InvalidConfiguration);
        }
        self.validate_socket_paths()?;
        Ok(())
    }

    /// Every socket must fit the kernel's `sun_path` (107 bytes on Linux, 103
    /// on macOS). They live in short per-user directories, so this only fails
    /// for an unusual fallback; it fails before anything is created, naming
    /// the path and the limit.
    fn validate_socket_paths(&self) -> Result<(), SupervisorConfigError> {
        let id = "00000000-0000-0000-0000-000000000000";
        let vm = crate::socket_dir::predicted(&self.root.join("engine"))
            .join("vms")
            .join(id);
        for socket in [
            self.supervisor_socket(),
            self.runner_socket(id),
            vm.join("vsock").join(crate::state::VSOCK_SOCKET_NAME),
            vm.join("api").join("api.sock"),
            vm.join("fs").join(crate::state::direct_share_socket_name(
                codewire_vmm_guest_probe::MAX_DIRECT_SHARES - 1,
            )),
        ] {
            crate::socket_dir::check_length(&socket).map_err(|error| match error {
                crate::socket_dir::SocketDirError::PathTooLong {
                    path,
                    length,
                    limit,
                } => SupervisorConfigError::SocketPathTooLong {
                    path,
                    length,
                    limit,
                },
                _ => SupervisorConfigError::InvalidConfiguration,
            })?;
        }
        Ok(())
    }

    pub fn configuration_digest(&self) -> [u8; 32] {
        // Keep this exhaustive so adding any runtime path fails compilation
        // until its supervisor-identity semantics are decided explicitly.
        let Self {
            root,
            artifact_root,
            artifact_lock,
            mesh_data_dir,
            platform_config_dir,
            credential_authority_root,
            executable,
        } = self;
        let mut digest = Sha256::new();
        update_supervisor_config_digest(
            &mut digest,
            b"domain",
            NATIVE_SUPERVISOR_CONFIG_DIGEST_DOMAIN,
        );
        for (field, path) in [
            (b"root".as_slice(), root),
            (b"artifact_root".as_slice(), artifact_root),
            (b"artifact_lock".as_slice(), artifact_lock),
            (b"mesh_data_dir".as_slice(), mesh_data_dir),
            (b"platform_config_dir".as_slice(), platform_config_dir),
            (
                b"credential_authority_root".as_slice(),
                credential_authority_root,
            ),
            (b"executable".as_slice(), executable),
        ] {
            update_supervisor_config_digest(&mut digest, field, path.as_os_str().as_bytes());
        }
        digest.finalize().into()
    }
}

fn update_supervisor_config_digest(digest: &mut Sha256, field: &[u8], value: &[u8]) {
    for component in [field, value] {
        let length = u64::try_from(component.len())
            .expect("native supervisor configuration component exceeds u64");
        digest.update(length.to_be_bytes());
        digest.update(component);
    }
}

pub fn admit_supervisor_info(
    info: &v1::SupervisorInfo,
    expected_configuration_digest: Option<&[u8; 32]>,
) -> Result<(), SupervisorConfigError> {
    if !(MINIMUM_SUPERVISOR_PROTOCOL_VERSION..=NATIVE_SUPERVISOR_PROTOCOL_VERSION)
        .contains(&info.protocol_version)
    {
        return Err(SupervisorConfigError::SupervisorProtocolMismatch {
            expected: NATIVE_SUPERVISOR_PROTOCOL_VERSION,
            actual: info.protocol_version,
        });
    }
    let reported_configuration_digest: [u8; 32] =
        info.configuration_sha256
            .as_slice()
            .try_into()
            .map_err(|_| SupervisorConfigError::InvalidSupervisorInfo)?;
    if expected_configuration_digest
        .is_some_and(|expected| expected != &reported_configuration_digest)
    {
        return Err(SupervisorConfigError::SupervisorConfigurationMismatch);
    }
    Ok(())
}

pub fn supervisor_info(config: &NativeRuntimeConfig) -> v1::SupervisorInfo {
    v1::SupervisorInfo {
        protocol_version: NATIVE_SUPERVISOR_PROTOCOL_VERSION,
        configuration_sha256: config.configuration_digest().to_vec(),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SupervisorConfigError {
    #[error("native runtime configuration is invalid")]
    InvalidConfiguration,
    #[error("{}", unsupported_protocol_message(*.actual))]
    SupervisorProtocolMismatch { expected: u32, actual: u32 },
    #[error("the running native supervisor returned invalid compatibility information")]
    InvalidSupervisorInfo,
    #[error("the running native supervisor uses a different runtime configuration")]
    SupervisorConfigurationMismatch,
    #[error("the local VM socket path {path} would be {length} bytes, over the {limit}-byte limit")]
    SocketPathTooLong {
        path: PathBuf,
        length: usize,
        limit: usize,
    },
    #[error("filesystem operation failed for {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    use super::*;

    fn test_config() -> NativeRuntimeConfig {
        NativeRuntimeConfig {
            root: PathBuf::from("/runtime"),
            artifact_root: PathBuf::from("/config/artifacts"),
            artifact_lock: PathBuf::from("/config/artifacts.lock"),
            mesh_data_dir: PathBuf::from("/config/mesh"),
            platform_config_dir: PathBuf::from("/config/platform"),
            credential_authority_root: PathBuf::from("/authority"),
            executable: PathBuf::from("/bin/codewire"),
        }
    }

    #[test]
    fn compatibility_requires_the_expected_configuration_but_not_host_effects() {
        let config = test_config();
        let info = supervisor_info(&config);
        assert_eq!(info.protocol_version, 22);
        assert!(admit_supervisor_info(&info, None).is_ok());
        assert!(admit_supervisor_info(&info, Some(&config.configuration_digest())).is_ok());
        assert!(matches!(
            admit_supervisor_info(&info, Some(&[0; 32])),
            Err(SupervisorConfigError::SupervisorConfigurationMismatch)
        ));
        for size in [0, 31, 33, 64] {
            let malformed = v1::SupervisorInfo {
                configuration_sha256: vec![0; size],
                ..info.clone()
            };
            assert!(matches!(
                admit_supervisor_info(&malformed, None),
                Err(SupervisorConfigError::InvalidSupervisorInfo)
            ));
        }
    }

    #[test]
    fn validation_preserves_absolute_paths_and_artifact_parent_relationship() {
        let mut config = test_config();
        config.executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.supervisor_socket(),
            crate::socket_dir::predicted(&config.root).join("supervisor.sock")
        );
        assert_eq!(
            config.runner_socket(uuid::Uuid::nil()),
            crate::socket_dir::predicted(&config.root)
                .join("runners")
                .join(format!("{}.sock", uuid::Uuid::nil()))
        );
        for field in 0..7 {
            let mut invalid = config.clone();
            let paths = [
                &mut invalid.root,
                &mut invalid.artifact_root,
                &mut invalid.artifact_lock,
                &mut invalid.mesh_data_dir,
                &mut invalid.platform_config_dir,
                &mut invalid.credential_authority_root,
                &mut invalid.executable,
            ];
            *paths.into_iter().nth(field).unwrap() = PathBuf::from("relative");
            assert!(matches!(
                invalid.validate(),
                Err(SupervisorConfigError::InvalidConfiguration)
            ));
        }
        config.artifact_lock = PathBuf::from("/elsewhere/artifacts.lock");
        assert!(matches!(
            config.validate(),
            Err(SupervisorConfigError::InvalidConfiguration)
        ));
    }

    #[test]
    fn validation_rejects_executable_alias_and_preserves_lookup_error() {
        let directory = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(directory.path()).unwrap();
        let mut config = test_config();
        config.executable = root.join("alias");
        std::os::unix::fs::symlink(std::env::current_exe().unwrap(), &config.executable).unwrap();
        assert!(matches!(
            config.validate(),
            Err(SupervisorConfigError::InvalidConfiguration)
        ));
        config.executable = root.join("missing");
        assert!(
            matches!(config.validate(), Err(SupervisorConfigError::Io { path, source })
            if path == config.executable && source.kind() == std::io::ErrorKind::NotFound)
        );
    }

    #[test]
    fn supervisor_info_admits_the_supported_range_and_a_valid_digest_shape() {
        let config = test_config();
        let mut info = supervisor_info(&config);
        for protocol in MINIMUM_SUPERVISOR_PROTOCOL_VERSION..=NATIVE_SUPERVISOR_PROTOCOL_VERSION {
            info.protocol_version = protocol;
            assert!(admit_supervisor_info(&info, None).is_ok(), "{protocol}");
        }
        info.protocol_version = NATIVE_SUPERVISOR_PROTOCOL_VERSION + 1;
        let error = admit_supervisor_info(&info, None).unwrap_err();
        assert!(matches!(
            error,
            SupervisorConfigError::SupervisorProtocolMismatch {
                expected: NATIVE_SUPERVISOR_PROTOCOL_VERSION,
                actual,
            } if actual == NATIVE_SUPERVISOR_PROTOCOL_VERSION + 1
        ));
        assert!(
            error
                .to_string()
                .starts_with("a newer cw runs your local VMs")
        );

        info.protocol_version = MINIMUM_SUPERVISOR_PROTOCOL_VERSION - 1;
        let error = admit_supervisor_info(&info, None).unwrap_err();
        assert!(matches!(
            error,
            SupervisorConfigError::SupervisorProtocolMismatch { .. }
        ));
        assert!(
            error
                .to_string()
                .starts_with("an older cw runs your local VMs")
        );

        info.protocol_version = NATIVE_SUPERVISOR_PROTOCOL_VERSION;
        info.configuration_sha256.pop();
        assert!(matches!(
            admit_supervisor_info(&info, None),
            Err(SupervisorConfigError::InvalidSupervisorInfo)
        ));
    }

    #[test]
    fn supervisor_configuration_digest_binds_each_raw_unix_path() {
        let vector = NativeRuntimeConfig {
            root: PathBuf::from("/runtime"),
            artifact_root: PathBuf::from("/artifacts"),
            artifact_lock: PathBuf::from("/config/artifacts.lock"),
            mesh_data_dir: PathBuf::from("/config/mesh"),
            platform_config_dir: PathBuf::from("/config/platform"),
            credential_authority_root: PathBuf::from("/authority"),
            executable: PathBuf::from("/bin/codewire"),
        };
        assert_eq!(
            vector.configuration_digest(),
            [
                0xbb, 0x55, 0x18, 0x7d, 0x67, 0x5f, 0x63, 0xf6, 0x64, 0x36, 0x2d, 0x06, 0xbd, 0x4a,
                0xb5, 0xc9, 0xe2, 0x07, 0x70, 0x1b, 0xa1, 0xbd, 0xd1, 0xb2, 0xeb, 0x86, 0xa5, 0x0c,
                0x04, 0x4d, 0x88, 0x87,
            ]
        );

        let config = vector;
        let expected = config.configuration_digest();
        for changed in [
            NativeRuntimeConfig {
                root: config.root.join("changed"),
                ..config.clone()
            },
            NativeRuntimeConfig {
                artifact_root: config.artifact_root.join("changed"),
                ..config.clone()
            },
            NativeRuntimeConfig {
                artifact_lock: config.artifact_lock.with_file_name("changed.lock"),
                ..config.clone()
            },
            NativeRuntimeConfig {
                mesh_data_dir: config.mesh_data_dir.join("changed"),
                ..config.clone()
            },
            NativeRuntimeConfig {
                platform_config_dir: config.platform_config_dir.join("changed"),
                ..config.clone()
            },
            NativeRuntimeConfig {
                credential_authority_root: config.credential_authority_root.join("changed"),
                ..config.clone()
            },
            NativeRuntimeConfig {
                executable: config.executable.with_file_name("changed"),
                ..config.clone()
            },
        ] {
            assert_ne!(changed.configuration_digest(), expected);
        }

        let mut raw = config.clone();
        raw.credential_authority_root = PathBuf::from(OsString::from_vec(
            b"/tmp/codewire-credentials-\xff".to_vec(),
        ));
        let raw_digest = raw.configuration_digest();
        raw.credential_authority_root = PathBuf::from("/tmp/codewire-credentials-�");
        assert_ne!(raw.configuration_digest(), raw_digest);
    }

    #[test]
    fn every_protocol_after_the_minimum_says_what_it_changed() {
        let protocols: Vec<u32> = SUPERVISOR_PROTOCOL_CHANGES
            .iter()
            .map(|(protocol, _)| *protocol)
            .collect();
        assert_eq!(
            protocols,
            ((MINIMUM_SUPERVISOR_PROTOCOL_VERSION + 1)..=NATIVE_SUPERVISOR_PROTOCOL_VERSION)
                .collect::<Vec<_>>(),
            "a supervisor protocol bump needs a SUPERVISOR_PROTOCOL_CHANGES row"
        );
        assert!(
            SUPERVISOR_PROTOCOL_CHANGES
                .iter()
                .all(|(_, change)| !change.trim().is_empty())
        );
        for feature in SupervisorFeature::ALL {
            assert!(
                (MINIMUM_SUPERVISOR_PROTOCOL_VERSION + 1..=NATIVE_SUPERVISOR_PROTOCOL_VERSION)
                    .contains(&feature.since()),
                "{feature:?}"
            );
        }
    }
}
