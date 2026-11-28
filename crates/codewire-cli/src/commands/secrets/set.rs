//! `cw secrets … set KEY` for every store and scope: a new value, a change
//! to the key's binding, or both (#4003; docs/dev/SECRETS-AND-CREDENTIALS.md,
//! "Host-bound application secrets"). A set with no binding flags makes the
//! same calls and prints the same line as before; while host-bound secrets
//! are off nothing else is reachable.

use std::io::Read as _;

use codewire_access::{BindingWrite, ReservedHosts, StoredBinding};
use zeroize::Zeroizing;

use super::binding::{self, Current, Reentry, SecretBindingArgs, ValueNeed};
use super::outcome::{SetOutcome, SetRow};
use super::{OutputFormat, ScopedSecretKeyArgs, read_workload_secret_bytes, trimmed_required};
use crate::error_report::with_next_step;
use crate::output::{Capabilities, OutputMode};
use crate::secret_client::SecretMetadata;
use codewire_workload_secrets::{MAX_WORKLOAD_SECRET_VALUE_BYTES, validate_workload_secret_value};

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod local;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) use local::LocalKeys;
mod cloud;
pub(super) use cloud::CloudKeys;

/// One store's keys in one scope, as a set reads and writes them.
pub(super) trait KeyStore {
    /// The command that names this scope: `cw secrets --cloud --project=myapp`.
    fn command(&self) -> String;
    /// Where a key lives, after `set`: ` in project myapp`, or empty.
    fn place(&self) -> String;
    /// The line a plain value set has always printed.
    fn plain_set_line(&self, key: &str) -> String;
    async fn find(&mut self, key: &str) -> anyhow::Result<Option<SecretMetadata>>;
    /// Make sure the store keeps bindings before one is written, or a write
    /// with no value is sent.
    async fn require_bindings(&mut self) -> anyhow::Result<()>;
    /// The key's row after the write, when the store answers with it.
    async fn write(
        &mut self,
        key: &str,
        value: Option<Zeroizing<Vec<u8>>>,
        binding: &BindingWrite,
    ) -> anyhow::Result<Option<SecretMetadata>>;
}

pub(super) async fn set_key(
    store: &mut impl KeyStore,
    args: &ScopedSecretKeyArgs,
) -> anyhow::Result<()> {
    let key = trimmed_required(
        args.key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("secret key is required"))?,
        "secret key",
    )?;
    let flags = &args.binding;
    if flags.any() && !args.host_bound {
        return Err(binding::host_bound_unavailable());
    }
    // Without binding flags, and with host-bound secrets off, only a guided
    // set reads first, as it always has.
    let found = if args.guided || flags.any() || args.host_bound {
        store.find(key).await?
    } else {
        None
    };
    if args.guided
        && found.is_some()
        && !super::super::guided::confirm(&format!("Replace the existing value for {key}?"))?
    {
        return Ok(());
    }
    let command = store.command();
    let current = Current {
        exists: found.is_some(),
        binding: found
            .and_then(|found| found.binding)
            .map(|binding| binding.stored()),
    };
    let plan = binding::plan(&command, key, flags, current)?;
    if plan.write != BindingWrite::Keep || plan.value == ValueNeed::None {
        store.require_bindings().await?;
    }
    let value = match plan.value {
        ValueNeed::None => None,
        ValueNeed::New => Some(read_value(key, None, args.output, &command, flags)?),
        ValueNeed::Again(reentry) => Some(read_value(
            key,
            Some(reentry),
            args.output,
            &command,
            flags,
        )?),
    };
    if let (Some(value), Some(after)) = (&value, &plan.after) {
        validate_bound_value(after, value)?;
    }
    let value_changed = value.is_some();
    let written = store
        .write(key, value, &plan.write)
        .await
        .map_err(|error| refused_write(error, key, &plan.value, &command, flags))?;
    match args.output {
        OutputFormat::Json => {
            let secret = match written {
                Some(secret) => Some(secret),
                None => store.find(key).await?,
            }
            .ok_or_else(|| anyhow::anyhow!("Secret {key} was set, but the store didn't list it"))?;
            let row = SetRow {
                secret: &secret,
                value_changed,
                running_environments: None,
            };
            println!("{}", serde_json::to_string_pretty(&row)?);
        }
        OutputFormat::Text if plan.write == BindingWrite::Keep && plan.after.is_none() => {
            eprintln!("{}", store.plain_set_line(key));
        }
        OutputFormat::Text => {
            let outcome = SetOutcome {
                key,
                place: store.place(),
                before: plan.before.as_ref(),
                after: plan.after.as_ref(),
                value_changed,
            };
            let caps = Capabilities::from_process(OutputMode::Text);
            print!("{}", outcome.render(caps.stdout_style()));
        }
    }
    Ok(())
}

/// The value, from a hidden prompt at a terminal or from stdin. A binding
/// change that needs it says why at the prompt, and without a terminal
/// fails at once when stdin holds none.
fn read_value(
    key: &str,
    reentry: Option<Reentry>,
    output: OutputFormat,
    command: &str,
    flags: &SecretBindingArgs,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        if output == OutputFormat::Json {
            return Err(with_next_step(
                anyhow::anyhow!("--output json reads the value from stdin, never a prompt"),
                format!("{} --output json < FILE", set_command(command, key, flags)),
            ));
        }
        let prompt = reentry.map_or_else(|| "Value: ".to_owned(), |reentry| reentry.prompt(key));
        let value = crate::commands::credential_input::read_hidden_terminal_bytes(
            &prompt,
            MAX_WORKLOAD_SECRET_VALUE_BYTES,
        );
        eprintln!();
        let value = value?;
        validate_workload_secret_value(&value)?;
        return Ok(value);
    }
    let Some(reentry) = reentry else {
        return read_workload_secret_bytes(std::io::stdin().lock(), false);
    };
    let mut first = [0_u8; 1];
    let mut stdin = std::io::stdin().lock();
    let read = stdin.read(&mut first)?;
    if read == 0 {
        return Err(value_required(reentry, key, command, flags));
    }
    let rest = std::io::Read::chain(&first[..read], stdin);
    read_workload_secret_bytes(std::io::BufReader::new(rest), false)
}

fn value_required(
    reentry: Reentry,
    key: &str,
    command: &str,
    flags: &SecretBindingArgs,
) -> anyhow::Error {
    with_next_step(
        anyhow::anyhow!(reentry.needs_value(key)),
        format!(
            "pass the value on stdin: {} < FILE",
            set_command(command, key, flags)
        ),
    )
}

/// `cw secrets --cloud --project=myapp set KEY --host HOST`: the set again,
/// with the binding flags it was given.
fn set_command(command: &str, key: &str, flags: &SecretBindingArgs) -> String {
    let words = flags.words();
    if words.is_empty() {
        format!("{command} set {key}")
    } else {
        format!("{command} set {key} {words}")
    }
}

/// A bound value is printable ASCII, at most 8 KiB, and a Basic user name
/// holds no `:`; refused before it is sent.
fn validate_bound_value(after: &StoredBinding, value: &[u8]) -> anyhow::Result<()> {
    after
        .parse(&ReservedHosts::default())
        .and_then(|binding| binding.validate_value(value))
        .map_err(binding::refused_binding)
}

/// A store's refusal of a binding write in the CLI's words: the cloud's
/// `ErrorInfo` reason, or the local authority's store refusal. Anything
/// else is left as it is.
fn refused_write(
    error: anyhow::Error,
    key: &str,
    value: &ValueNeed,
    command: &str,
    flags: &SecretBindingArgs,
) -> anyhow::Error {
    let Some((reason, message, trace_id)) = refusal(&error) else {
        return error;
    };
    match reason.as_str() {
        "secret_value_required" => {
            let reentry = match value {
                ValueNeed::Again(reentry) => *reentry,
                _ => Reentry::AddHost,
            };
            value_required(reentry, key, command, flags)
        }
        "bound_host_provider" | "bound_host_reserved" | "secret_binding_invalid" => {
            crate::reworded::reworded(message, trace_id.as_deref())
        }
        "LOCAL_HOST_BOUND_SECRETS_UNAVAILABLE" => binding::host_bound_unavailable(),
        _ => error,
    }
}

/// The refusal reason, its message and the answer's trace, wherever the
/// store's answer sits in `error`'s chain.
fn refusal(error: &anyhow::Error) -> Option<(String, String, Option<String>)> {
    for cause in error.chain() {
        if let Some(client) = cause.downcast_ref::<codewire_client::ClientError>() {
            return client.reason().map(|reason| {
                (
                    reason.to_owned(),
                    client.message().to_owned(),
                    client.trace_id().map(str::to_owned),
                )
            });
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(status) = cause.downcast_ref::<tonic::Status>() {
            return codewire_local_credentials::store_refusal_reason(status)
                .map(|reason| (reason.to_owned(), status.message().to_owned(), None));
        }
    }
    None
}

#[cfg(test)]
mod tests;
