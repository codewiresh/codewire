//! The durable create/start/restart result: outcome, allocated size and the
//! selected credential, secret and network references.
//!
//! A summary holds references and allocated sizes only. It never holds or
//! renders credential material, secret values or live usage.

use crate::commands::progress::terminal_text;

use super::style::{Role, Status, Style};

const KIB: u64 = 1024;
const MIB: u64 = KIB * 1024;
const GIB: u64 = MIB * 1024;
const TIB: u64 = GIB * 1024;

/// Where an environment's VM runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VmLocation {
    Local,
    Cloud,
}

impl VmLocation {
    fn label(self) -> &'static str {
        match self {
            VmLocation::Local => "local VM",
            VmLocation::Cloud => "cloud VM",
        }
    }
}

/// Resources allocated to an environment, from its reported units. Zero or
/// negative values are unknown and are left out rather than shown as zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Allocation {
    cpu_millicores: Option<u64>,
    memory_bytes: Option<u64>,
    disk_bytes: Option<u64>,
}

impl Allocation {
    /// A local VM's `vcpus`, `memory_mib` and `disk_bytes`.
    pub(crate) fn local(vcpus: u32, memory_mib: u32, disk_bytes: u64) -> Self {
        Self {
            cpu_millicores: positive(u64::from(vcpus) * 1000),
            memory_bytes: positive(u64::from(memory_mib) * MIB),
            disk_bytes: positive(disk_bytes),
        }
    }

    /// A cloud environment's `cpu_millicores`, memory in MiB and disk in
    /// GiB (the platform's `memory_mb` and `disk_gb` carry binary units).
    pub(crate) fn cloud(cpu_millicores: i32, memory_mib: i32, disk_gib: i32) -> Self {
        let unsigned = |value: i32| u64::try_from(value).ok();
        Self {
            cpu_millicores: unsigned(cpu_millicores).and_then(positive),
            memory_bytes: unsigned(memory_mib).and_then(|mib| positive(mib * MIB)),
            disk_bytes: unsigned(disk_gib).and_then(|gib| positive(gib * GIB)),
        }
    }

    /// `2 vCPU · 4 GiB RAM · 40 GiB disk`, or `None` when nothing is known.
    pub(crate) fn render(&self, style: Style) -> Option<String> {
        let parts: Vec<String> = [
            self.cpu_millicores
                .map(|millis| format!("{} vCPU", cpus(millis))),
            self.memory_bytes
                .map(|bytes| format!("{} RAM", binary_size(bytes))),
            self.disk_bytes
                .map(|bytes| format!("{} disk", binary_size(bytes))),
        ]
        .into_iter()
        .flatten()
        .collect();
        (!parts.is_empty()).then(|| parts.join(style.separator()))
    }
}

fn positive(value: u64) -> Option<u64> {
    (value > 0).then_some(value)
}

/// Whole CPUs, or up to three decimals for a fractional allocation.
fn cpus(millis: u64) -> String {
    let (whole, fraction) = (millis / 1000, millis % 1000);
    if fraction == 0 {
        whole.to_string()
    } else {
        let digits = format!("{fraction:03}");
        format!("{whole}.{}", digits.trim_end_matches('0'))
    }
}

/// The largest binary unit that states the size exactly with at most two
/// decimals: `4 GiB`, `1.5 GiB`, `512 MiB`, `1 TiB`.
fn binary_size(bytes: u64) -> String {
    for (unit, name) in [(TIB, "TiB"), (GIB, "GiB"), (MIB, "MiB"), (KIB, "KiB")] {
        let hundredths = u128::from(bytes) * 100;
        if bytes >= unit && hundredths % u128::from(unit) == 0 {
            let hundredths = hundredths / u128::from(unit);
            let (whole, fraction) = (hundredths / 100, hundredths % 100);
            return match fraction {
                0 => format!("{whole} {name}"),
                f if f % 10 == 0 => format!("{whole}.{} {name}", f / 10),
                f => format!("{whole}.{f:02} {name}"),
            };
        }
    }
    format!("{bytes} B")
}

/// Where a credential profile or secret source is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourcePlacement {
    Local,
    Platform,
}

impl SourcePlacement {
    fn prefix(self) -> &'static str {
        match self {
            SourcePlacement::Local => "local",
            SourcePlacement::Platform => "platform",
        }
    }
}

/// A selected credential profile or application-secret source, by
/// reference only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SourceRef {
    /// Nothing selected.
    None,
    /// A resolved name: `platform:work`.
    Named {
        placement: SourcePlacement,
        name: String,
    },
    /// A canonical reference whose name could not be resolved, shown as is.
    Unresolved(String),
    /// A whole store scope rather than one named source, such as the
    /// organization's application secrets: `organization secrets (platform)`.
    Scope {
        placement: SourcePlacement,
        scope: &'static str,
    },
    /// Several selections shown together, such as a secret project and the
    /// organization's secrets. Build it with [`SourceRef::several`].
    Several(Vec<SourceRef>),
}

impl SourceRef {
    /// The selections as one reference: `None` for none, the reference
    /// itself for one, [`SourceRef::Several`] otherwise.
    pub(crate) fn several(references: Vec<SourceRef>) -> Self {
        let mut references: Vec<SourceRef> = references
            .into_iter()
            .filter(|reference| !reference.is_none())
            .collect();
        match references.len() {
            0 => SourceRef::None,
            1 => references.remove(0),
            _ => SourceRef::Several(references),
        }
    }

    pub(crate) fn is_none(&self) -> bool {
        match self {
            SourceRef::None => true,
            SourceRef::Several(references) => references.iter().all(SourceRef::is_none),
            _ => false,
        }
    }

    /// `platform:work`, `local:app-dev`, the unresolved reference, a scope
    /// such as `organization secrets (platform)`, several of these joined by
    /// commas, or `none`.
    pub(crate) fn text(&self) -> String {
        match self {
            SourceRef::None => "none".to_owned(),
            SourceRef::Named { placement, name } => {
                format!("{}:{}", placement.prefix(), terminal_text(name))
            }
            SourceRef::Unresolved(reference) => terminal_text(reference),
            SourceRef::Scope { placement, scope } => format!("{scope} ({})", placement.prefix()),
            SourceRef::Several(references) => {
                let parts: Vec<String> = references
                    .iter()
                    .filter(|reference| !reference.is_none())
                    .map(SourceRef::text)
                    .collect();
                if parts.is_empty() {
                    "none".to_owned()
                } else {
                    parts.join(", ")
                }
            }
        }
    }
}

/// Which Mesh service owns a network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MeshPlacement {
    /// The platform's hosted Mesh.
    Cloud,
    /// A self-managed local Mesh service.
    Local,
}

/// An environment's saved network attachment. Not a connectivity claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NetworkRef {
    NotAttached,
    Attached {
        mesh: MeshPlacement,
        network: String,
    },
}

impl NetworkRef {
    pub(crate) fn is_attached(&self) -> bool {
        matches!(self, NetworkRef::Attached { .. })
    }

    /// `cloud:work`, `local:work` or `not attached`.
    pub(crate) fn text(&self) -> String {
        match self {
            NetworkRef::NotAttached => "not attached".to_owned(),
            NetworkRef::Attached { mesh, network } => {
                let mesh = match mesh {
                    MeshPlacement::Cloud => "cloud",
                    MeshPlacement::Local => "local",
                };
                format!("{mesh}:{}", terminal_text(network))
            }
        }
    }
}

/// The lifecycle outcome a summary reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Created,
    Started,
    Restarted,
    /// The create was accepted but its readiness was not observed, as with
    /// `--no-wait`: a pending result, not a confirmed one.
    Creating,
}

impl Outcome {
    fn verb(self) -> &'static str {
        match self {
            Outcome::Created => "created",
            Outcome::Started => "started",
            Outcome::Restarted => "restarted",
            Outcome::Creating => "is being created",
        }
    }

    fn status(self) -> Status {
        match self {
            Outcome::Created | Outcome::Started | Outcome::Restarted => Status::Done,
            Outcome::Creating => Status::Attention,
        }
    }
}

/// A create, start or restart result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifecycleSummary {
    pub(crate) outcome: Outcome,
    pub(crate) name: String,
    pub(crate) location: VmLocation,
    pub(crate) allocation: Allocation,
    pub(crate) credentials: SourceRef,
    pub(crate) secrets: SourceRef,
    pub(crate) network: NetworkRef,
    /// The next useful command, such as `cw --local run claude --in app`.
    pub(crate) next: Option<String>,
}

impl LifecycleSummary {
    /// The durable result for stdout:
    ///
    /// ```text
    /// ✓ Environment app started · local VM
    ///   2 vCPU · 4 GiB RAM · 40 GiB disk
    ///
    ///   Credentials: platform:work
    ///   Secrets:     platform:app-dev
    ///   Network:     cloud:work
    ///
    /// → cw --local run claude --in app
    /// ```
    pub(crate) fn render(&self, style: Style) -> String {
        let mut out = format!(
            "{} Environment {} {}{}\n",
            style.status(self.outcome.status()),
            terminal_text(&self.name),
            self.outcome.verb(),
            style.paint(
                Role::Dim,
                &format!("{}{}", style.separator(), self.location.label())
            ),
        );
        self.push_details(&mut out, style);
        if let Some(next) = &self.next {
            out.push_str(&format!(
                "\n{} {}\n",
                style.status(Status::Next),
                terminal_text(next)
            ));
        }
        out
    }

    /// The same context shown on stderr while the environment is created or
    /// started, before its progress rows.
    pub(crate) fn render_context(&self, style: Style) -> String {
        let mut out = format!(
            "{}{}\n",
            style.paint(Role::Strong, &terminal_text(&self.name)),
            style.paint(
                Role::Dim,
                &format!("{}{}", style.separator(), self.location.label())
            ),
        );
        self.push_details(&mut out, style);
        out.push('\n');
        out
    }

    fn push_details(&self, out: &mut String, style: Style) {
        if let Some(size) = self.allocation.render(style) {
            out.push_str(&format!("  {}\n", style.paint(Role::Dim, &size)));
        }
        out.push('\n');
        let quiet = |missing: bool, text: String| {
            if missing {
                style.paint(Role::Dim, &text)
            } else {
                text
            }
        };
        let rows = [
            (
                "Credentials:",
                quiet(self.credentials.is_none(), self.credentials.text()),
            ),
            (
                "Secrets:",
                quiet(self.secrets.is_none(), self.secrets.text()),
            ),
            (
                "Network:",
                quiet(!self.network.is_attached(), self.network.text()),
            ),
        ];
        for (label, value) in rows {
            out.push_str(&format!("  {label:<13}{value}\n"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::caps::Charset;

    const PLAIN: Style = Style::new(false, Charset::Unicode);

    fn summary() -> LifecycleSummary {
        LifecycleSummary {
            outcome: Outcome::Started,
            name: "app".to_owned(),
            location: VmLocation::Local,
            allocation: Allocation::local(2, 4096, 40 * GIB),
            credentials: SourceRef::Named {
                placement: SourcePlacement::Platform,
                name: "work".to_owned(),
            },
            secrets: SourceRef::Named {
                placement: SourcePlacement::Platform,
                name: "app-dev".to_owned(),
            },
            network: NetworkRef::Attached {
                mesh: MeshPlacement::Cloud,
                network: "work".to_owned(),
            },
            next: Some("cw --local run claude --in app".to_owned()),
        }
    }

    #[test]
    fn local_allocation_uses_binary_units() {
        let render = |a: Allocation| a.render(PLAIN).unwrap();
        assert_eq!(
            render(Allocation::local(2, 4096, 40 * GIB)),
            "2 vCPU · 4 GiB RAM · 40 GiB disk"
        );
        assert_eq!(
            render(Allocation::local(1, 512, 1536 * MIB)),
            "1 vCPU · 512 MiB RAM · 1.5 GiB disk"
        );
        assert_eq!(
            render(Allocation::local(16, 3000, TIB)),
            "16 vCPU · 3000 MiB RAM · 1 TiB disk"
        );
        assert_eq!(
            render(Allocation::local(4, 16 * 1024, 20 * GIB + 256 * MIB)),
            "4 vCPU · 16 GiB RAM · 20.25 GiB disk"
        );
    }

    #[test]
    fn cloud_allocation_keeps_fractional_cpu() {
        let render = |a: Allocation| a.render(PLAIN).unwrap();
        assert_eq!(
            render(Allocation::cloud(2000, 4096, 40)),
            "2 vCPU · 4 GiB RAM · 40 GiB disk"
        );
        assert_eq!(
            render(Allocation::cloud(500, 512, 10)),
            "0.5 vCPU · 512 MiB RAM · 10 GiB disk"
        );
        assert_eq!(
            render(Allocation::cloud(1250, 6144, 1024)),
            "1.25 vCPU · 6 GiB RAM · 1 TiB disk"
        );
        assert_eq!(
            render(Allocation::cloud(1, 1536, 2)),
            "0.001 vCPU · 1.5 GiB RAM · 2 GiB disk"
        );
    }

    #[test]
    fn unknown_sizes_are_left_out() {
        assert_eq!(Allocation::cloud(0, -1, 0).render(PLAIN), None);
        assert_eq!(Allocation::local(0, 0, 0).render(PLAIN), None);
        assert_eq!(
            Allocation::cloud(2000, 0, 40).render(PLAIN).unwrap(),
            "2 vCPU · 40 GiB disk"
        );
    }

    #[test]
    fn binary_sizes_fall_back_to_exact_smaller_units() {
        assert_eq!(binary_size(1023), "1023 B");
        assert_eq!(binary_size(KIB), "1 KiB");
        assert_eq!(binary_size(GIB + 1), format!("{} B", GIB + 1));
        // About 1.1 GiB, which no binary unit states exactly in two decimals.
        assert_eq!(binary_size(1_181_116_006), "1181116006 B");
    }

    #[test]
    fn started_summary_matches_the_design() {
        assert_eq!(
            summary().render(PLAIN),
            "✓ Environment app started · local VM\n  2 vCPU · 4 GiB RAM · 40 GiB disk\n\n  Credentials: platform:work\n  Secrets:     platform:app-dev\n  Network:     cloud:work\n\n→ cw --local run claude --in app\n"
        );
    }

    #[test]
    fn missing_selections_read_none_and_not_attached() {
        let summary = LifecycleSummary {
            outcome: Outcome::Created,
            location: VmLocation::Cloud,
            allocation: Allocation::cloud(2000, 4096, 40),
            credentials: SourceRef::None,
            secrets: SourceRef::None,
            network: NetworkRef::NotAttached,
            next: None,
            ..summary()
        };
        assert_eq!(
            summary.render(PLAIN),
            "✓ Environment app created · cloud VM\n  2 vCPU · 4 GiB RAM · 40 GiB disk\n\n  Credentials: none\n  Secrets:     none\n  Network:     not attached\n"
        );
    }

    #[test]
    fn unresolved_references_and_local_networks_render_as_references() {
        let summary = LifecycleSummary {
            outcome: Outcome::Restarted,
            credentials: SourceRef::Unresolved(
                "platform:id:856b6b9e-a520-48c7-aab1-8ac915465f28".to_owned(),
            ),
            secrets: SourceRef::Named {
                placement: SourcePlacement::Local,
                name: "app-dev".to_owned(),
            },
            network: NetworkRef::Attached {
                mesh: MeshPlacement::Local,
                network: "lab".to_owned(),
            },
            ..summary()
        };
        let text = summary.render(PLAIN);
        assert!(text.starts_with("✓ Environment app restarted · local VM\n"));
        assert!(text.contains("  Credentials: platform:id:856b6b9e-a520-48c7-aab1-8ac915465f28\n"));
        assert!(text.contains("  Secrets:     local:app-dev\n"));
        assert!(text.contains("  Network:     local:lab\n"));
    }

    #[test]
    fn ascii_without_colour_has_no_unicode_or_escapes() {
        let text = summary().render(Style::new(false, Charset::Ascii));
        assert!(text.is_ascii(), "{text}");
        assert!(!text.contains('\x1b'));
        assert_eq!(
            text,
            "+ Environment app started - local VM\n  2 vCPU - 4 GiB RAM - 40 GiB disk\n\n  Credentials: platform:work\n  Secrets:     platform:app-dev\n  Network:     cloud:work\n\n-> cw --local run claude --in app\n"
        );
    }

    #[test]
    fn colour_marks_outcome_quiet_details_and_next_step() {
        let summary = LifecycleSummary {
            network: NetworkRef::NotAttached,
            ..summary()
        };
        let text = summary.render(Style::new(true, Charset::Unicode));
        assert!(
            text.starts_with("\x1b[32m✓\x1b[0m Environment app started\x1b[2m · local VM\x1b[0m\n")
        );
        assert!(text.contains("  \x1b[2m2 vCPU · 4 GiB RAM · 40 GiB disk\x1b[0m\n"));
        assert!(text.contains("  Network:     \x1b[2mnot attached\x1b[0m\n"));
        assert!(text.contains("  Credentials: platform:work\n"));
        assert!(text.ends_with("\x1b[36m→\x1b[0m cw --local run claude --in app\n"));
    }

    #[test]
    fn server_strings_cannot_drive_the_terminal() {
        let summary = LifecycleSummary {
            name: "app\x1b[2J\r\n".to_owned(),
            credentials: SourceRef::Named {
                placement: SourcePlacement::Platform,
                name: "wo\x1b]52;c;cHduZWQ=\x07rk".to_owned(),
            },
            secrets: SourceRef::Unresolved("platform:id:\x08\x08x".to_owned()),
            network: NetworkRef::Attached {
                mesh: MeshPlacement::Cloud,
                network: "lab\u{9b}31m".to_owned(),
            },
            next: Some("cw run\x1b[A claude".to_owned()),
            ..summary()
        };
        for text in [summary.render(PLAIN), summary.render_context(PLAIN)] {
            assert!(
                !text.chars().any(|c| c.is_control() && c != '\n'),
                "{text:?}"
            );
        }
        let text = summary.render(PLAIN);
        assert!(text.starts_with("✓ Environment app [2J started"));
        assert!(text.contains("Credentials: platform:wo ]52;c;cHduZWQ= rk\n"));
        assert!(text.contains("Secrets:     platform:id: x\n"));
        assert!(text.contains("Network:     cloud:lab 31m\n"));
        assert!(text.contains("→ cw run [A claude\n"));
    }

    #[test]
    fn secret_scopes_join_the_named_project() {
        let secrets = SourceRef::several(vec![
            SourceRef::Named {
                placement: SourcePlacement::Platform,
                name: "app-dev".to_owned(),
            },
            SourceRef::Scope {
                placement: SourcePlacement::Platform,
                scope: "organization secrets",
            },
            SourceRef::None,
            SourceRef::Scope {
                placement: SourcePlacement::Local,
                scope: "personal secrets",
            },
        ]);
        assert_eq!(
            secrets.text(),
            "platform:app-dev, organization secrets (platform), personal secrets (local)"
        );
        assert!(!secrets.is_none());
        assert_eq!(
            SourceRef::several(vec![SourceRef::None, SourceRef::None]),
            SourceRef::None
        );
        let one = SourceRef::Unresolved("local:id:x".to_owned());
        assert_eq!(SourceRef::several(vec![one.clone()]), one);
        assert_eq!(SourceRef::Several(vec![SourceRef::None]).text(), "none");
        assert!(SourceRef::Several(Vec::new()).is_none());
    }

    #[test]
    fn an_accepted_create_is_pending_not_confirmed() {
        let summary = LifecycleSummary {
            outcome: Outcome::Creating,
            location: VmLocation::Cloud,
            next: Some("cw --cloud info app".to_owned()),
            ..summary()
        };
        let text = summary.render(PLAIN);
        assert!(text.starts_with("! Environment app is being created · cloud VM\n"));
        assert!(text.ends_with("→ cw --cloud info app\n"));
        let colour = summary.render(Style::new(true, Charset::Unicode));
        assert!(colour.starts_with("\x1b[33m!\x1b[0m Environment app is being created"));
    }

    #[test]
    fn context_shows_the_same_sources_while_working() {
        assert_eq!(
            summary().render_context(PLAIN),
            "app · local VM\n  2 vCPU · 4 GiB RAM · 40 GiB disk\n\n  Credentials: platform:work\n  Secrets:     platform:app-dev\n  Network:     cloud:work\n\n"
        );
        let colour = summary().render_context(Style::new(true, Charset::Unicode));
        assert!(colour.starts_with("\x1b[1mapp\x1b[0m\x1b[2m · local VM\x1b[0m\n"));
    }
}
