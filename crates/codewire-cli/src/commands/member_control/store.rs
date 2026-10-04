//! Private caller identity, explicit aliases, and retained mutation intentions.
//! No command/input body or owner/provider credential is saved here.
use super::{
    super::mesh_commands::retained,
    wire::{Binding, canonical_uuid},
};
use anyhow::{Context, ensure};
use codewire_gateway_proto::daemon::v1;
use codewire_tailnet::derp::key::NodePrivate;
use prost::Message;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroize;

const MAX_REQUESTS: usize = 256;
const MAX_ALIASES: usize = 32;
pub(super) const MAX_MESSAGE_LOCATORS: usize = 256;

/// Walk the entire authority chain, never just its leaf. A root-owned sticky
/// scratch parent is allowed only above an owner-private component. No promise
/// is made against root or another process running under the same UID.
pub(super) fn admit_chain(path: &Path) -> anyhow::Result<()> {
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "member state path must be absolute and canonical"
    );
    let uid = unsafe { libc::geteuid() };
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&current)?;
        ensure!(
            metadata.is_dir() && (metadata.uid() == 0 || metadata.uid() == uid),
            "member state ancestor is foreign or linked"
        );
        if metadata.uid() == 0 {
            ensure!(
                metadata.mode() & 0o022 == 0 || metadata.mode() & 0o1000 != 0,
                "member state ancestor is writable by another UID"
            );
        } else {
            ensure!(
                metadata.mode() & 0o022 == 0,
                "member state ancestor is writable by another UID"
            );
        }
    }
    let leaf = std::fs::symlink_metadata(path)?;
    ensure!(
        leaf.uid() == uid && leaf.mode() & 0o7777 == 0o700,
        "member state must be owner-private"
    );
    ensure!(
        std::fs::canonicalize(path)? == path,
        "member state path contains a link"
    );
    Ok(())
}

pub(super) fn create_chain(path: &Path) -> anyhow::Result<()> {
    ensure!(path.is_absolute(), "member state path must be absolute");
    if path.exists() {
        return admit_chain(path);
    }
    let parent = path.parent().context("member state parent missing")?;
    if !parent.exists() {
        create_chain(parent)?;
    }
    let mut current = PathBuf::from("/");
    let uid = unsafe { libc::geteuid() };
    for component in parent.components().skip(1) {
        ensure!(
            matches!(component, Component::Normal(_)),
            "member state path must be canonical"
        );
        current.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&current)?;
        ensure!(
            metadata.is_dir()
                && (metadata.uid() == uid || metadata.uid() == 0)
                && (metadata.mode() & 0o022 == 0
                    || (metadata.uid() == 0 && metadata.mode() & 0o1000 != 0)),
            "member ancestor authority is unsafe"
        );
    }
    // Existing nonprivate ancestors are permitted for an owned new private
    // child, but are still fully checked after mkdir before any file write.
    std::fs::DirBuilder::new().mode(0o700).create(path)?;
    admit_chain(path)
}

pub(super) struct Directory {
    pub path: PathBuf,
    inner: retained::StateDir,
}
impl Directory {
    pub fn open(path: &Path, create: bool) -> anyhow::Result<Self> {
        if create {
            create_chain(path)?;
        }
        admit_chain(path)?;
        let inner = retained::StateDir::open(path, false)?.context("member state is absent")?;
        Ok(Self {
            path: path.to_owned(),
            inner,
        })
    }
    pub fn read<T: for<'de> Deserialize<'de>>(&self, name: &str) -> anyhow::Result<Option<T>> {
        leaf(name)?;
        admit_chain(&self.path)?;
        let value = self.inner.read(name)?;
        admit_chain(&self.path)?;
        value
            .map(|bytes| serde_json::from_slice(&bytes).context("invalid closed member record"))
            .transpose()
    }
    pub fn write<T: Serialize>(&self, name: &str, value: &T) -> anyhow::Result<()> {
        leaf(name)?;
        admit_chain(&self.path)?;
        self.inner.write(name, &serde_json::to_vec(value)?)?;
        admit_chain(&self.path)
    }
    pub async fn lock(&self) -> anyhow::Result<retained::ControlLock> {
        admit_chain(&self.path)?;
        self.inner.lock().await
    }
    pub fn retained(&self) -> &retained::StateDir {
        &self.inner
    }
    pub fn remove(&self, name: &str) -> anyhow::Result<()> {
        leaf(name)?;
        admit_chain(&self.path)?;
        let previous = self.inner.read(name)?;
        if let Some(previous) = previous {
            self.inner.remove(name, Some(&previous))?;
        }
        admit_chain(&self.path)
    }
    pub fn read_held<T: for<'de> Deserialize<'de>>(
        &self,
        name: &str,
    ) -> anyhow::Result<Option<(T, retained::MemberRecord)>> {
        admit_chain(&self.path)?;
        let record = self.inner.hold_member_record(name)?;
        admit_chain(&self.path)?;
        record
            .map(|record| {
                let value = serde_json::from_slice(record.bytes())
                    .context("invalid closed member cleanup record")?;
                Ok((value, record))
            })
            .transpose()
    }
    pub fn validate_held(&self, record: &retained::MemberRecord) -> anyhow::Result<()> {
        admit_chain(&self.path)?;
        self.inner.validate_member_record(record)?;
        admit_chain(&self.path)
    }
    pub fn remove_held(&self, record: &retained::MemberRecord) -> anyhow::Result<()> {
        admit_chain(&self.path)?;
        self.inner.remove_member_record(record)?;
        admit_chain(&self.path)
    }
    pub(super) fn count(&self, prefix: &str) -> anyhow::Result<usize> {
        admit_chain(&self.path)?;
        let mut count = 0;
        let mut entries = 0;
        for entry in std::fs::read_dir(&self.path)? {
            let entry = entry?;
            entries += 1;
            ensure!(
                entries <= MAX_REQUESTS + MAX_ALIASES + MAX_MESSAGE_LOCATORS + 16,
                "member directory capacity exhausted"
            );
            if entry
                .file_name()
                .to_str()
                .is_some_and(|s| s.starts_with(prefix))
            {
                count += 1;
            }
        }
        Ok(count)
    }
}
fn leaf(name: &str) -> anyhow::Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 100
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "member record name is invalid"
    );
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    schema: u32,
    secret: [u8; 32],
    wg_secret: [u8; 32],
}
impl Drop for Identity {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.wg_secret.zeroize();
    }
}
impl Identity {
    pub async fn load(directory: &Directory, create: bool) -> anyhow::Result<Self> {
        if let Some(value) = directory.read::<Self>("identity.json")? {
            ensure!(
                value.schema == 1 && value.secret != [0; 32] && value.wg_secret != [0; 32],
                "member identity unavailable"
            );
            return Ok(value);
        }
        ensure!(create, "member identity is absent; use cw member identity");
        let _lock = directory.lock().await?;
        if directory.read::<Self>("identity.json")?.is_some() {
            let value: Self = directory
                .read("identity.json")?
                .context("member identity changed")?;
            ensure!(
                value.schema == 1 && value.secret != [0; 32] && value.wg_secret != [0; 32],
                "member identity unavailable"
            );
            return Ok(value);
        }
        let mut value = Self {
            schema: 1,
            secret: [0; 32],
            wg_secret: [0; 32],
        };
        OsRng.fill_bytes(&mut value.secret);
        OsRng.fill_bytes(&mut value.wg_secret);
        directory.write("identity.json", &value)?;
        Ok(value)
    }
    pub fn secret(&self) -> NodePrivate {
        NodePrivate::from_raw(self.secret)
    }
    pub fn wg(&self) -> codewire_tailnet::wg::StaticSecret {
        codewire_tailnet::wg::StaticSecret::from(self.wg_secret)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Alias {
    pub schema: u32,
    pub name: String,
    pub origin: String,
    pub route_name: String,
    pub binding: Binding,
    pub derp_only: bool,
    #[serde(default)]
    pub required_transport: Option<MemberPath>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub(super) enum MemberPath {
    DirectUdp,
    Derp,
}
impl MemberPath {
    pub fn name(self) -> &'static str {
        match self {
            Self::DirectUdp => "direct_udp",
            Self::Derp => "derp",
        }
    }
}
impl Alias {
    pub fn validate(&self) -> anyhow::Result<()> {
        super::name(&self.name)?;
        super::name(&self.route_name)?;
        self.binding.validate()?;
        ensure!(self.schema == 1, "member alias schema is unavailable");
        ensure!(
            !(self.derp_only && self.required_transport == Some(MemberPath::DirectUdp))
                && (self.required_transport != Some(MemberPath::Derp) || self.derp_only),
            "member required transport conflicts with direct path policy"
        );
        let url = url::Url::parse(&self.origin)?;
        ensure!(
            matches!(url.scheme(), "https" | "http")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none(),
            "member Mesh origin is invalid"
        );
        Ok(())
    }
    pub async fn save(&self, directory: &Directory) -> anyhow::Result<()> {
        self.validate()?;
        let _lock = directory.lock().await?;
        let file = format!("alias-{}.json", self.name);
        let old = directory.read::<Self>(&file)?;
        ensure!(
            old.is_none(),
            "member alias already exists; retained key bindings cannot be replaced"
        );
        ensure!(
            directory.count("alias-")? < MAX_ALIASES,
            "member alias capacity exhausted"
        );
        directory.write(&file, self)
    }
    pub fn load(directory: &Directory, name: &str) -> anyhow::Result<Self> {
        super::name(name)?;
        let value: Self = directory
            .read(&format!("alias-{name}.json"))?
            .context("member alias is absent")?;
        value.validate()?;
        ensure!(value.name == name, "member alias identity changed");
        Ok(value)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RequestRecord {
    pub schema: u32,
    pub id: String,
    pub binding: Binding,
    pub wire_sha256: String,
    pub verb: i32,
    pub session_id: String,
    pub generation: u64,
    #[serde(default)]
    pub driver_id: String,
    #[serde(default)]
    pub message_id: String,
    pub attempted: bool,
    pub receipt: Option<Vec<u8>>,
}
impl RequestRecord {
    fn file(id: &str) -> anyhow::Result<String> {
        canonical_uuid(id)?;
        Ok(format!("request-{id}.json"))
    }
    pub fn load(directory: &Directory, id: &str) -> anyhow::Result<Self> {
        let value: Self = directory
            .read(&Self::file(id)?)?
            .context("member request is absent; no permission to reissue")?;
        value.binding.validate()?;
        canonical_uuid(&value.id)?;
        ensure!(
            value.id == id
                && value.schema == 1
                && value.generation > 0
                && matches!(value.verb, 2..=10)
                && value.wire_sha256.len() == 64
                && value
                    .wire_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && value.session_id.starts_with("session-"),
            "member request record is invalid"
        );
        canonical_uuid(
            value
                .session_id
                .strip_prefix("session-")
                .expect("prefix checked"),
        )?;
        if (5..=10).contains(&value.verb) {
            canonical_uuid(&value.driver_id)?;
            ensure!(
                value.session_id == format!("session-{}", value.driver_id),
                "managed journal binding differs"
            );
            if !value.message_id.is_empty() {
                canonical_uuid(&value.message_id)?;
            }
            ensure!(
                match value.verb {
                    5 =>
                        value.driver_id == value.id
                            && value.generation == 1
                            && (value.message_id.is_empty() || value.message_id == value.id),
                    6..=8 => value.message_id == value.id,
                    9 | 10 => value.message_id.is_empty(),
                    _ => false,
                },
                "managed journal reservation differs"
            );
        } else {
            ensure!(
                value.driver_id.is_empty() && value.message_id.is_empty(),
                "terminal journal carries managed identity"
            );
        }
        if let Some(bytes) = &value.receipt {
            value.validate_receipt(&super::wire::decode::<v1::HostControlReceipt>(bytes)?)?;
        }
        Ok(value)
    }
    pub async fn prepare(
        directory: &Directory,
        binding: Binding,
        request: &v1::HostControlMutationRequest,
    ) -> anyhow::Result<(Self, bool)> {
        ensure!(
            request.encoded_len() <= super::wire::MAX_PAYLOAD,
            "member mutation exceeds its payload bound"
        );
        canonical_uuid(&request.request_id)?;
        binding.validate()?;
        ensure!(
            request.scope.as_ref() == Some(&binding.scope()),
            "member mutation scope changed"
        );
        let (verb, sid, generation) = match request
            .operation
            .as_ref()
            .context("member mutation absent")?
        {
            v1::host_control_mutation_request::Operation::Launch(_) => {
                (2, format!("session-{}", request.request_id), 1)
            }
            v1::host_control_mutation_request::Operation::Input(x) => {
                (3, x.session_id.clone(), x.expected_launch_generation)
            }
            v1::host_control_mutation_request::Operation::Stop(x) => {
                (4, x.session_id.clone(), x.expected_launch_generation)
            }
            v1::host_control_mutation_request::Operation::ManagedLaunch(_) => {
                (5, format!("session-{}", request.request_id), 1)
            }
            v1::host_control_mutation_request::Operation::ManagedControl(x) => {
                let verb = match v1::HostManagedAction::try_from(x.action) {
                    Ok(v1::HostManagedAction::Message) => 6,
                    Ok(v1::HostManagedAction::Steer) => 7,
                    Ok(v1::HostManagedAction::Interrupt) => 8,
                    Ok(v1::HostManagedAction::Stop) => 9,
                    Ok(v1::HostManagedAction::Restart) => 10,
                    _ => anyhow::bail!("invalid managed action"),
                };
                (verb, x.session_id.clone(), x.expected_launch_generation)
            }
        };
        let (driver_id, message_id) = match request.operation.as_ref().expect("matched operation") {
            v1::host_control_mutation_request::Operation::ManagedLaunch(x) => (
                request.request_id.clone(),
                if x.prompt.is_some() {
                    request.request_id.clone()
                } else {
                    String::new()
                },
            ),
            v1::host_control_mutation_request::Operation::ManagedControl(x) => (
                x.driver_id.clone(),
                if (6..=8).contains(&verb) {
                    request.request_id.clone()
                } else {
                    String::new()
                },
            ),
            _ => (String::new(), String::new()),
        };
        ensure!(
            generation > 0,
            "member mutation requires positive launch generation"
        );
        let sha = format!("{:x}", Sha256::digest(request.encode_to_vec()));
        let _lock = directory.lock().await?;
        if directory
            .read::<Self>(&Self::file(&request.request_id)?)?
            .is_some()
        {
            let existing = Self::load(directory, &request.request_id)?;
            ensure!(
                existing.binding == binding
                    && existing.wire_sha256 == sha
                    && existing.verb == verb
                    && existing.session_id == sid
                    && existing.generation == generation,
                "member request UUID conflicts with retained intent"
            );
            return Ok((existing, true));
        }
        ensure!(
            directory.count("request-")? < MAX_REQUESTS,
            "member retained request capacity exhausted"
        );
        let record = Self {
            schema: 1,
            id: request.request_id.clone(),
            binding,
            wire_sha256: sha,
            verb,
            session_id: sid,
            generation,
            driver_id,
            message_id,
            attempted: false,
            receipt: None,
        };
        directory.write(&Self::file(&record.id)?, &record)?;
        Ok((record, false))
    }
    pub async fn begin(&mut self, directory: &Directory) -> anyhow::Result<()> {
        let _lock = directory.lock().await?;
        let old = Self::load(directory, &self.id)?;
        ensure!(
            !old.attempted && old.wire_sha256 == self.wire_sha256 && old.binding == self.binding,
            "member request was already attempted; observe only"
        );
        self.attempted = true;
        directory.write(&Self::file(&self.id)?, self)
    }
    pub fn validate_receipt(&self, value: &v1::HostControlReceipt) -> anyhow::Result<()> {
        ensure!(
            value.request_id == self.id
                && value.scope.as_ref() == Some(&self.binding.scope())
                && value.session_id == self.session_id
                && (value.launch_generation == self.generation
                    || (self.verb == 10
                        && matches!(value.phase, 3 | 5)
                        && Some(value.launch_generation) == self.generation.checked_add(1)))
                && !(self.verb == 10
                    && value.phase == 3
                    && value.launch_generation == self.generation)
                && value.driver_id == self.driver_id
                && value.message_id == self.message_id
                && value.verb == self.verb
                && (1..=5).contains(&value.phase)
                && value.fingerprint_sha256.len() == 64
                && value
                    .fingerprint_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "member receipt identity changed"
        );
        if let Some(old) = &self.receipt {
            let old = super::wire::decode::<v1::HostControlReceipt>(old)?;
            ensure!(
                old.fingerprint_sha256 == value.fingerprint_sha256,
                "member retained receipt fingerprint changed"
            );
        }
        Ok(())
    }
    pub async fn finish(
        &mut self,
        directory: &Directory,
        value: v1::HostControlReceipt,
    ) -> anyhow::Result<()> {
        self.validate_receipt(&value)?;
        let _lock = directory.lock().await?;
        let old = Self::load(directory, &self.id)?;
        ensure!(
            old.wire_sha256 == self.wire_sha256 && old.binding == self.binding,
            "member retained intent changed"
        );
        old.validate_receipt(&value)?;
        self.receipt = Some(value.encode_to_vec());
        self.attempted = old.attempted;
        directory.write(&Self::file(&self.id)?, self)
    }
}
