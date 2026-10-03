//! Shared native-supervisor configuration and private compatibility contract.
//!
//! This module admits configuration and protocol values, not host ownership.
//! It performs no process spawning, store/replay, credential or VM effects.
//! Platform control entrypoints remain responsible for those boundaries.

use std::fs;
use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;

use sha2::{Digest as _, Sha256};

use crate::control::v1;

// Bump for every detached-supervisor behavior change, even if the protobuf
// message layout itself remains wire-compatible.
// The first Darwin stopped-state dispatcher joins version 6: there is no older
// detached Darwin service, and Linux behavior and wire/configuration contracts
// are unchanged. Subsequent Darwin behavior changes follow the same bump rule.
pub const NATIVE_SUPERVISOR_PROTOCOL_VERSION: u32 = 8;
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
    #[cfg(target_os = "linux")]
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

    pub fn supervisor_socket(&self) -> PathBuf {
        self.root.join("supervisor.sock")
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
    if info.protocol_version != NATIVE_SUPERVISOR_PROTOCOL_VERSION {
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
    #[error(
        "native supervisor protocol version mismatch: expected {expected}, running supervisor reported {actual}"
    )]
    SupervisorProtocolMismatch { expected: u32, actual: u32 },
    #[error("the running native supervisor returned invalid compatibility information")]
    InvalidSupervisorInfo,
    #[error("the running native supervisor uses a different runtime configuration")]
    SupervisorConfigurationMismatch,
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
        assert_eq!(info.protocol_version, 8);
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
            config.root.join("supervisor.sock")
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
    fn supervisor_info_requires_the_exact_protocol_and_valid_digest_shape() {
        let config = test_config();
        let mut info = supervisor_info(&config);
        info.protocol_version = NATIVE_SUPERVISOR_PROTOCOL_VERSION + 1;
        let error = admit_supervisor_info(&info, None).unwrap_err();
        assert!(matches!(
            error,
            SupervisorConfigError::SupervisorProtocolMismatch {
                expected: NATIVE_SUPERVISOR_PROTOCOL_VERSION,
                actual,
            } if actual == NATIVE_SUPERVISOR_PROTOCOL_VERSION + 1
        ));
        assert!(error.to_string().contains("protocol version mismatch"));

        info.protocol_version = NATIVE_SUPERVISOR_PROTOCOL_VERSION - 1;
        assert!(matches!(
            admit_supervisor_info(&info, None),
            Err(SupervisorConfigError::SupervisorProtocolMismatch { .. })
        ));

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
}
