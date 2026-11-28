//! What `cw secrets set`'s binding flags ask for, worked out against the
//! key's current binding before any value is read (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Host-bound application secrets").
//! The stores check the result again; this refuses what it can first, so a
//! person is never asked for a value the change would refuse.

use std::collections::BTreeSet;

use clap::Args;
use codewire_access::{
    ANTHROPIC_API_HOST, BindingError, BindingWrite, CLAUDE_TOKEN_HOST, CODEX_TOKEN_HOST,
    DEFAULT_BOUND_HEADER, DEFAULT_BOUND_SCHEME, GITHUB_HOSTS, HostBinding, MAX_BOUND_HEADERS,
    OPENAI_API_HOST, ReservedHosts, StoredBinding, StoredPresentation, binding_preset,
    change_needs_value, nearest_binding_preset,
};

use crate::error_report::with_next_step;
use crate::secret_client::NO_SCHEME;

/// The binding flags of `cw secrets set`. They stay out of `--help`, and
/// are refused, until host-bound secrets ship
/// ([`codewire_access::HOST_BOUND_SECRETS`]). No flag here conflicts with
/// another at parse time, so every use is answered by that refusal first.
#[derive(Clone, Debug, Default, Args)]
pub(crate) struct SecretBindingArgs {
    #[arg(
        long = "host",
        value_name = "HOST",
        hide = true,
        help = "Send the value only to HOST; adds to its hosts; repeatable"
    )]
    pub(crate) hosts: Vec<String>,
    #[arg(
        long = "remove-host",
        value_name = "HOST",
        hide = true,
        help = "Stop sending the value to HOST; repeatable; needs no value"
    )]
    pub(crate) remove_hosts: Vec<String>,
    #[arg(
        long = "header",
        value_name = "NAME",
        hide = true,
        help = "The header that carries the value (default Authorization); at most 2"
    )]
    pub(crate) headers: Vec<String>,
    #[arg(
        long,
        value_name = "WORD",
        hide = true,
        help = "The word before the value (default Bearer); none for the value alone"
    )]
    pub(crate) scheme: Option<String>,
    #[arg(
        long,
        value_name = "PREFIX",
        hide = true,
        help = "Put before the placeholder; '' clears it; needs no value"
    )]
    pub(crate) prefix: Option<String>,
    #[arg(
        long,
        hide = true,
        help = "Send it as a Basic auth password (user name x-access-token)"
    )]
    pub(crate) basic: bool,
    #[arg(
        long,
        value_name = "NAME",
        hide = true,
        help = "The Basic auth user name, with --basic"
    )]
    pub(crate) username: Option<String>,
    #[arg(
        long = "basic-user",
        hide = true,
        help = "Send it as a Basic auth user name with an empty password"
    )]
    pub(crate) basic_user: bool,
    #[arg(
        long,
        value_name = "NAME",
        hide = true,
        help = "Fill hosts, header, scheme and prefix from a preset (cw secrets presets)"
    )]
    pub(crate) preset: Option<String>,
    #[arg(
        long,
        hide = true,
        help = "Remove every host: the secret becomes plain"
    )]
    pub(crate) plain: bool,
}

impl SecretBindingArgs {
    pub(crate) fn any(&self) -> bool {
        !self.hosts.is_empty()
            || !self.remove_hosts.is_empty()
            || !self.headers.is_empty()
            || self.scheme.is_some()
            || self.prefix.is_some()
            || self.basic
            || self.username.is_some()
            || self.basic_user
            || self.preset.is_some()
            || self.plain
    }

    /// The flags again, as a person would type them, for a step that
    /// repeats the command.
    pub(crate) fn words(&self) -> String {
        let mut words = Vec::new();
        let mut flag = |name: &str, value: Option<&str>| match value {
            Some("") => words.push(format!("--{name} ''")),
            Some(value) => words.push(format!("--{name} {value}")),
            None => words.push(format!("--{name}")),
        };
        if let Some(preset) = &self.preset {
            flag("preset", Some(preset));
        }
        for host in &self.hosts {
            flag("host", Some(host));
        }
        for host in &self.remove_hosts {
            flag("remove-host", Some(host));
        }
        for header in &self.headers {
            flag("header", Some(header));
        }
        if let Some(scheme) = &self.scheme {
            flag("scheme", Some(scheme));
        }
        if let Some(prefix) = &self.prefix {
            flag("prefix", Some(prefix));
        }
        if self.basic {
            flag("basic", None);
        }
        if let Some(username) = &self.username {
            flag("username", Some(username));
        }
        if self.basic_user {
            flag("basic-user", None);
        }
        if self.plain {
            flag("plain", None);
        }
        words.join(" ")
    }
}

/// The refusal while host-bound secrets are off. One plain sentence, no
/// next step: there is nothing to do yet.
pub(crate) fn host_bound_unavailable() -> anyhow::Error {
    anyhow::anyhow!("sending a secret only to its hosts isn't available yet")
}

/// Why a change needs the secret's value entered again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reentry {
    Bind,
    AddHost,
    Presentation,
    Plain,
}

impl Reentry {
    fn of(before: Option<&HostBinding>, after: Option<&HostBinding>) -> Self {
        match (before, after) {
            (None, Some(_)) => Self::Bind,
            (Some(_), None) => Self::Plain,
            (Some(before), Some(after)) if before.presentation() != after.presentation() => {
                Self::Presentation
            }
            _ => Self::AddHost,
        }
    }

    /// The refusal's sentence: `adding a host to KEY needs its value again`.
    pub(crate) fn needs_value(self, key: &str) -> String {
        let change = match self {
            Self::Bind => format!("binding {key} to hosts"),
            Self::AddHost => format!("adding a host to {key}"),
            Self::Presentation => format!("changing how {key} is sent"),
            Self::Plain => format!("making {key} plain"),
        };
        format!("{change} needs its value again")
    }

    /// The prompt at a terminal, with the reason it asks.
    pub(crate) fn prompt(self, key: &str) -> String {
        let reason = match self {
            Self::Bind => "binding it to hosts sends it somewhere new",
            Self::AddHost => "adding a host sends it somewhere new",
            Self::Presentation => "a new header or scheme sends it somewhere new",
            Self::Plain => "making it plain puts it in every environment",
        };
        format!("Paste the value of {key} again ({reason}): ")
    }
}

/// Whether, and why, a set reads a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValueNeed {
    /// A change to a bound secret that needs none: no stdin is read.
    None,
    /// A new value, as every set without binding flags takes.
    New,
    /// A binding change that could send the value somewhere new.
    Again(Reentry),
}

/// A set's effect on the key's binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BindingPlan {
    pub(crate) write: BindingWrite,
    pub(crate) before: Option<StoredBinding>,
    pub(crate) after: Option<StoredBinding>,
    pub(crate) value: ValueNeed,
}

/// The key a set writes, as it is before the set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Current {
    pub(crate) exists: bool,
    pub(crate) binding: Option<StoredBinding>,
}

/// Work out what `flags` do to the key as it is now. `command` is the start
/// of the command that sets this key (`cw secrets --cloud
/// --project=myapp`), for the steps a refusal names.
pub(crate) fn plan(
    command: &str,
    key: &str,
    flags: &SecretBindingArgs,
    current: Current,
) -> anyhow::Result<BindingPlan> {
    let before = current.binding;
    if !flags.any() {
        return Ok(BindingPlan {
            write: BindingWrite::Keep,
            after: before.clone(),
            before,
            value: ValueNeed::New,
        });
    }
    let after = if flags.plain {
        anyhow::ensure!(
            !SecretBindingArgs {
                plain: false,
                ..flags.clone()
            }
            .any(),
            "--plain removes every host; give it without the other binding flags"
        );
        None
    } else {
        Some(bound(command, key, flags, before.as_ref())?)
    };
    let reserved = ReservedHosts::default();
    let parsed_after = after
        .as_ref()
        .map(|after| after.parse(&reserved))
        .transpose()
        .map_err(refused_binding)?;
    // In the stores' canonical form, so what changed is compared exactly.
    let after = after
        .zip(parsed_after.as_ref())
        .map(|(after, parsed)| StoredBinding {
            preset: after.preset,
            ..StoredBinding::from(parsed)
        });
    // A stored binding the rules now refuse is read as plain, so every
    // change to it needs the value.
    let parsed_before = before
        .as_ref()
        .and_then(|before| before.parse(&reserved).ok());
    let value = match (&parsed_before, &parsed_after) {
        (None, None) => ValueNeed::New,
        _ if !current.exists => ValueNeed::New,
        (Some(_), Some(_))
            if !change_needs_value(parsed_before.as_ref(), parsed_after.as_ref()) =>
        {
            ValueNeed::None
        }
        _ => ValueNeed::Again(Reentry::of(parsed_before.as_ref(), parsed_after.as_ref())),
    };
    Ok(BindingPlan {
        write: match &after {
            Some(after) => BindingWrite::Bind(after.clone()),
            None => BindingWrite::Plain,
        },
        before,
        after,
        value,
    })
}

/// The binding the flags make of `before`, not yet checked against the
/// rules.
fn bound(
    command: &str,
    key: &str,
    flags: &SecretBindingArgs,
    before: Option<&StoredBinding>,
) -> anyhow::Result<StoredBinding> {
    anyhow::ensure!(
        !(flags.basic && flags.basic_user),
        "--basic and --basic-user send the value two different ways; choose one"
    );
    let basic = if flags.basic {
        Some("--basic")
    } else if flags.basic_user {
        Some("--basic-user")
    } else {
        None
    };
    if let Some(basic) = basic {
        anyhow::ensure!(
            flags.headers.is_empty() && flags.scheme.is_none(),
            "With {basic}, the value goes in Authorization, so --header and --scheme don't apply"
        );
    }
    anyhow::ensure!(
        flags.username.is_none() || flags.basic,
        "--username names the Basic auth user name, with --basic"
    );
    if flags.headers.len() > MAX_BOUND_HEADERS {
        return Err(refused_binding(BindingError::TooManyHeaders));
    }
    let preset = match flags.preset.as_deref() {
        Some(name) => Some(binding_preset(name).ok_or_else(|| unknown_preset(name))?),
        None => None,
    };
    let base = match preset {
        Some(preset) => Some(preset.binding()),
        None => before.cloned(),
    };
    let mut hosts: Vec<String> = match (preset, base.as_ref()) {
        // A preset's hosts give way to the ones named.
        (Some(_), Some(base)) if flags.hosts.is_empty() => base.hosts.clone(),
        (Some(_), _) => Vec::new(),
        (None, Some(base)) => base.hosts.clone(),
        (None, None) => Vec::new(),
    };
    for host in &flags.hosts {
        let host = host.to_ascii_lowercase();
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    let remove: BTreeSet<String> = flags
        .remove_hosts
        .iter()
        .map(|host| host.to_ascii_lowercase())
        .collect();
    for host in &remove {
        anyhow::ensure!(
            base.is_some(),
            "Secret {key} is plain: it has no hosts to remove"
        );
        anyhow::ensure!(
            hosts.contains(host),
            "Host {host} isn't one of {key}'s hosts"
        );
    }
    hosts.retain(|host| !remove.contains(host));
    if hosts.is_empty() {
        if let Some(only) = remove.iter().next() {
            return Err(with_next_step(
                anyhow::anyhow!("Host {only} is {key}'s only host"),
                format!("to make it plain: {command} set {key} --plain"),
            ));
        }
        return Err(with_next_step(
            anyhow::anyhow!("Secret {key} has no hosts yet: name one"),
            format!("{command} set {key} --host HOST {}", flags.words()),
        ));
    }
    let base_presentation = base.as_ref().map(|base| &base.presentation);
    let presentation = presentation(flags, base_presentation);
    let prefix = match flags.prefix.as_deref() {
        Some("") => None,
        Some(prefix) => Some(prefix.to_owned()),
        None => base.as_ref().and_then(|base| base.prefix.clone()),
    };
    // A preset names the binding it filled, while it is still the one that
    // presents the value; a new way of sending it drops the name.
    let preset = base
        .as_ref()
        .and_then(|base| base.preset.clone())
        .filter(|_| Some(&presentation) == base_presentation);
    Ok(StoredBinding {
        hosts,
        presentation,
        prefix,
        preset,
    })
}

fn presentation(
    flags: &SecretBindingArgs,
    base: Option<&StoredPresentation>,
) -> StoredPresentation {
    if flags.basic {
        return StoredPresentation::Basic {
            username: flags
                .username
                .clone()
                .or_else(|| match base {
                    Some(StoredPresentation::Basic { username }) => Some(username.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| codewire_access::DEFAULT_BASIC_USERNAME.to_owned()),
        };
    }
    if flags.basic_user {
        return StoredPresentation::BasicUser;
    }
    let (base_headers, base_scheme) = match base {
        Some(StoredPresentation::Header { headers, scheme }) => {
            (Some(headers.clone()), Some(scheme.clone()))
        }
        // Any other base keeps its own presentation unless a header flag
        // asks for one.
        Some(other) if flags.headers.is_empty() && flags.scheme.is_none() => {
            return other.clone();
        }
        _ => (None, None),
    };
    StoredPresentation::Header {
        headers: if flags.headers.is_empty() {
            base_headers.unwrap_or_else(|| vec![DEFAULT_BOUND_HEADER.to_owned()])
        } else {
            flags.headers.clone()
        },
        scheme: match flags.scheme.as_deref() {
            Some(word) if word.eq_ignore_ascii_case(NO_SCHEME) => None,
            Some(word) => Some(word.to_owned()),
            None => base_scheme.unwrap_or_else(|| Some(DEFAULT_BOUND_SCHEME.to_owned())),
        },
    }
}

fn unknown_preset(name: &str) -> anyhow::Error {
    let error = anyhow::anyhow!("no preset named {name}");
    match nearest_binding_preset(name) {
        Some(nearest) => with_next_step(error, format!("did you mean {}?", nearest.name)),
        None => with_next_step(error, "cw secrets presets"),
    }
}

/// A binding the rules refuse, in their words, with the command that
/// connects a provider's own host.
pub(crate) fn refused_binding(error: BindingError) -> anyhow::Error {
    let step = match &error {
        BindingError::ProviderHost(host) => provider_step(host),
        _ => None,
    };
    let error = anyhow::Error::new(error);
    match step {
        Some(step) => with_next_step(error, step),
        None => error,
    }
}

/// The credential that serves a provider's host.
fn provider_step(host: &str) -> Option<&'static str> {
    if host == ANTHROPIC_API_HOST || host == CLAUDE_TOKEN_HOST {
        Some("cw credentials connect claude")
    } else if host == OPENAI_API_HOST
        || host == CODEX_TOKEN_HOST
        || host == codewire_access::CHATGPT_HOST
        || host.ends_with(".chatgpt.com")
    {
        Some("cw credentials connect codex")
    } else if GITHUB_HOSTS.contains(&host) {
        Some("cw credentials connect github")
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
