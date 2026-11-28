//! The Create sheet's form: the dashboard's Create Sandbox fields, checked by
//! the same rules (`codewire_project::create_input`) and sent as the same
//! request (`codewire_project_proto::create_request`), so a preset alone
//! creates what it creates on the dashboard.
//! The journey is `ios-create` in `docs/journeys/ios-app.md`.

use codewire_client::create_options::{
    GetEnvironmentCreateOptionsRequest, GetEnvironmentCreateOptionsResponse,
};
use codewire_client::{ClientError, CodewireClient, CreateEnvironmentRequest};
use codewire_project::create_input::{
    CreateError, CreateField, CreateInput, PortInput, PresetDefaults, RepositoryInput,
    allowlisted_access, lifetime_field_value,
};
use codewire_project_proto::{SourceChoice as ChosenSources, create_request, source_selection};

use super::{CreatedEnvironment, OrgTarget, client_for, on_own_runtime};
use crate::ShellError;

/// What the organization offers a new environment.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CreateOptions {
    pub presets: Vec<PresetOption>,
    /// The organization opted in to the confidential tier.
    pub confidential_available: bool,
    /// The domain previews are served under; empty when previews are off.
    pub preview_base_domain: String,
}

/// A preset, with its defaults as the form shows them: a field left empty
/// takes the preset's value.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PresetOption {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    /// Codewire's own preset, offered to every organization.
    pub official: bool,
    pub image: String,
    pub cpu: String,
    pub memory: String,
    pub disk: String,
    pub delete_after: String,
    pub install_command: String,
    pub startup_script: String,
    pub ports: Vec<PortField>,
}

/// The sheet's fields as typed. Numbers and lifetimes stay text so a refusal
/// names the field, as on the dashboard.
#[derive(Clone, Default, uniffi::Record)]
pub struct CreateForm {
    pub name: String,
    pub preset_id: String,
    pub image: String,
    /// Millicores.
    pub cpu: String,
    /// MiB.
    pub memory: String,
    /// GiB.
    pub disk: String,
    /// A number with `s`, `m`, `h` or `d`; minutes without one.
    pub delete_after: String,
    pub confidential: bool,
    pub install_command: String,
    pub startup_script: String,
    pub repositories: Vec<RepositoryField>,
    pub ports: Vec<PortField>,
    /// The person chose the ports, so none means none, not the preset's.
    pub ports_chosen: bool,
    pub sources: SourceChoice,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct RepositoryField {
    pub url: String,
    pub branch: String,
    /// Under `/workspace`; empty uses the repository's name.
    pub mount_path: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct PortField {
    pub port: String,
    pub label: String,
    pub access: PreviewAccess,
}

/// Who can open a port's HTTPS preview.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, uniffi::Enum)]
pub enum PreviewAccess {
    /// Only the person who created the environment.
    #[default]
    Creator,
    OrgMembers,
    Public,
}

impl PreviewAccess {
    fn from_form(value: &str) -> Self {
        match allowlisted_access(value) {
            "public" => Self::Public,
            "org_members" => Self::OrgMembers,
            _ => Self::Creator,
        }
    }

    fn as_form(self) -> &'static str {
        match self {
            Self::Creator => "creator",
            Self::OrgMembers => "org_members",
            Self::Public => "public",
        }
    }
}

/// The environment's sources, by the ids the source lists gave.
#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct SourceChoice {
    pub secret_project_id: Option<String>,
    pub organization_secrets: bool,
    pub personal_secrets: bool,
    pub credential_profile: Option<ProfileChoice>,
}

/// A credential profile at the revision the list showed.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ProfileChoice {
    pub id: String,
    pub revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CreateOutcome {
    Created {
        environment: CreatedEnvironment,
    },
    /// The form's rules refused it; nothing was sent.
    Refused {
        refusals: Vec<FieldRefusal>,
    },
}

/// A refusal and the field it belongs to, in the dashboard's words.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FieldRefusal {
    pub field: FormField,
    pub message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FormField {
    Name,
    Image,
    Cpu,
    Memory,
    Disk,
    DeleteAfter,
    Repositories,
    /// The form as a whole.
    Form,
    PortNumber {
        index: u32,
    },
    PortLabel {
        index: u32,
    },
    PortAccess {
        index: u32,
    },
}

#[uniffi::export]
pub async fn create_options(target: OrgTarget) -> Result<CreateOptions, ShellError> {
    let client = client_for(&target)?;
    let org_id = target.org_id.clone();
    let response = on_own_runtime("codewire-create-options", async move {
        fetch_options(&client, org_id).await
    })
    .await??;
    Ok(CreateOptions {
        presets: presets(&response)?
            .into_iter()
            .map(|preset| preset_option(preset.summary, preset.defaults))
            .collect(),
        confidential_available: response.confidential_available,
        preview_base_domain: response.preview_base_domain,
    })
}

/// Create from the form: a preset's defaults fill the fields left empty, the
/// dashboard's rules check it, and the server applies its own checks.
#[uniffi::export]
pub async fn create_environment(
    target: OrgTarget,
    form: CreateForm,
) -> Result<CreateOutcome, ShellError> {
    let client = client_for(&target)?;
    let org_id = target.org_id.clone();
    on_own_runtime("codewire-create", async move {
        create_from_form(&client, &org_id, form).await
    })
    .await?
}

/// The create the app runs, apart from its runtime, for the Kind smoke.
pub async fn create_from_form(
    client: &CodewireClient,
    org_id: &str,
    form: CreateForm,
) -> Result<CreateOutcome, ShellError> {
    let options = fetch_options(client, org_id.to_owned()).await?;
    let request = match request_for(
        org_id,
        &form,
        &presets(&options)?,
        options.confidential_available,
    ) {
        Ok(request) => request,
        Err(refusals) => return Ok(CreateOutcome::Refused { refusals }),
    };
    let environment = client
        .create_environment(request)
        .await?
        .environment
        .into_option()
        .ok_or_else(|| ShellError::Unavailable {
            message: "the server answered the create without an environment".into(),
        })?;
    Ok(CreateOutcome::Created {
        environment: CreatedEnvironment {
            id: environment.id,
            name: environment.name,
        },
    })
}

/// The request for the form, or every refusal in the form's order.
fn request_for(
    org_id: &str,
    form: &CreateForm,
    presets: &[Preset],
    confidential_available: bool,
) -> Result<CreateEnvironmentRequest, Vec<FieldRefusal>> {
    let mut input = create_input(form);
    if let Some(preset) = presets
        .iter()
        .find(|preset| preset.summary.id == input.preset_id.trim())
    {
        input.apply_preset_defaults(&preset.defaults);
    }
    let draft = input
        .draft(confidential_available)
        .map_err(|errors| errors.iter().map(refusal).collect::<Vec<_>>())?;
    let sources = &form.sources;
    let selection = source_selection(ChosenSources {
        secret_project: sources.secret_project_id.as_deref(),
        organization_secrets: sources.organization_secrets,
        personal_secrets: sources.personal_secrets,
        credential_profile: sources
            .credential_profile
            .as_ref()
            .map(|profile| (profile.id.as_str(), profile.revision)),
    });
    Ok(create_request(org_id, draft, &selection))
}

async fn fetch_options(
    client: &CodewireClient,
    org_id: String,
) -> Result<GetEnvironmentCreateOptionsResponse, ClientError> {
    client
        .get_environment_create_options(GetEnvironmentCreateOptionsRequest {
            org_id,
            ..Default::default()
        })
        .await
}

struct Preset {
    summary: PresetSummary,
    defaults: PresetDefaults,
}

struct PresetSummary {
    id: String,
    name: String,
    description: Option<String>,
    official: bool,
}

/// The presets with their defaults read from each canonical project, as the
/// dashboard reads them.
fn presets(response: &GetEnvironmentCreateOptionsResponse) -> Result<Vec<Preset>, ShellError> {
    response
        .presets
        .iter()
        .map(|preset| {
            let spec = preset.project_spec.as_option().cloned().ok_or_else(|| {
                ShellError::Unavailable {
                    message: format!("the preset {} came without its project", preset.name),
                }
            })?;
            let spec = codewire_project_proto::from_proto(spec).map_err(|error| {
                ShellError::Unavailable {
                    message: format!("the preset {} has an invalid project: {error}", preset.name),
                }
            })?;
            Ok(Preset {
                summary: PresetSummary {
                    id: preset.id.clone(),
                    name: preset.name.clone(),
                    description: preset
                        .description
                        .clone()
                        .filter(|text| !text.trim().is_empty()),
                    official: preset.official,
                },
                defaults: PresetDefaults::from_project(spec, preset.default_ttl_seconds),
            })
        })
        .collect()
}

fn preset_option(summary: PresetSummary, defaults: PresetDefaults) -> PresetOption {
    let text = |value: Option<String>| value.unwrap_or_default();
    PresetOption {
        id: summary.id,
        name: summary.name,
        description: summary.description,
        official: summary.official,
        image: defaults.image,
        cpu: text(defaults.cpu_millicores.map(|cpu| cpu.to_string())),
        memory: text(defaults.memory_mib.map(|memory| memory.to_string())),
        disk: text(defaults.disk_gib.map(|disk| disk.to_string())),
        delete_after: text(defaults.ttl_seconds.map(lifetime_field_value)),
        install_command: defaults.install_command,
        startup_script: defaults.startup_script,
        ports: defaults
            .app_ports
            .into_iter()
            .map(|port| PortField {
                port: port.port,
                label: port.label,
                access: PreviewAccess::from_form(&port.access),
            })
            .collect(),
    }
}

fn create_input(form: &CreateForm) -> CreateInput {
    CreateInput {
        name: form.name.clone(),
        preset_id: form.preset_id.clone(),
        image: form.image.clone(),
        install_command: form.install_command.clone(),
        startup_script: form.startup_script.clone(),
        cpu: form.cpu.clone(),
        memory: form.memory.clone(),
        disk: form.disk.clone(),
        ttl: form.delete_after.clone(),
        isolation_tier: if form.confidential {
            "confidential"
        } else {
            "standard"
        }
        .into(),
        repositories: form
            .repositories
            .iter()
            .map(|repository| RepositoryInput {
                url: repository.url.clone(),
                branch: repository.branch.clone(),
                mount_path: repository.mount_path.clone(),
            })
            .collect(),
        app_ports: form
            .ports
            .iter()
            .map(|port| PortInput {
                port: port.port.clone(),
                label: port.label.clone(),
                access: port.access.as_form().to_owned(),
            })
            .collect(),
        application_previews_explicit: form.ports_chosen,
    }
}

fn refusal(error: &CreateError) -> FieldRefusal {
    // At most `MAX_APP_PORTS` rows reach the rules, so an index always fits.
    let index = |index: usize| u32::try_from(index).unwrap_or(u32::MAX);
    FieldRefusal {
        field: match error.field {
            CreateField::Name => FormField::Name,
            CreateField::Image => FormField::Image,
            CreateField::Cpu => FormField::Cpu,
            CreateField::Memory => FormField::Memory,
            CreateField::Disk => FormField::Disk,
            CreateField::Ttl => FormField::DeleteAfter,
            CreateField::Repositories => FormField::Repositories,
            CreateField::Form => FormField::Form,
            CreateField::PortNumber(row) => FormField::PortNumber { index: index(row) },
            CreateField::PortLabel(row) => FormField::PortLabel { index: index(row) },
            CreateField::PortAccess(row) => FormField::PortAccess { index: index(row) },
        },
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests;
