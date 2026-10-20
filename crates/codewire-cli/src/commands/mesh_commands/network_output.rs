//! Text results of the network commands. Every result names the Mesh, its
//! endpoint and the organization it was for; machine (JSON) output keeps
//! its own shapes and is written by the callers.

use crate::commands::progress::terminal_text;
use crate::mesh::{Invite, Network, Node, NodeEnrollment};
use crate::output::{Capabilities, OutputMode, Role, Status, Style};

use super::selection::{MeshKind, NetworkMesh, NetworkSelection};

/// The style for a text result on stdout.
pub(crate) fn stdout_style() -> Style {
    Capabilities::from_process(OutputMode::Text).stdout_style()
}

/// What a network operation reports about its Mesh: kind label, endpoint
/// and organization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MeshContext {
    pub(crate) label: String,
    pub(crate) endpoint: String,
    pub(crate) organization: Option<String>,
}

impl MeshContext {
    pub(crate) fn new(mesh: &NetworkMesh, organization: Option<&str>) -> Self {
        Self {
            label: mesh.label().to_owned(),
            endpoint: mesh.url().to_owned(),
            organization: organization.map(str::to_owned),
        }
    }

    pub(crate) fn of_selection(selection: &NetworkSelection) -> Self {
        Self {
            label: selection.mesh.label().to_owned(),
            endpoint: selection.mesh_url.clone(),
            organization: Some(selection.organization_id.clone()),
        }
    }

    pub(crate) fn render(&self) -> String {
        let mut out = format!(
            "  Mesh          {}\n  Endpoint      {}\n",
            self.label,
            terminal_text(&self.endpoint)
        );
        if let Some(organization) = &self.organization {
            out.push_str(&format!(
                "  Organization  {}\n",
                terminal_text(organization)
            ));
        }
        out
    }
}

fn headline(style: Style, status: Status, text: &str) -> String {
    format!("{} {text}\n", style.status(status))
}

fn next(style: Style, text: &str) -> String {
    format!("{} {text}\n", style.status(Status::Next))
}

fn quiet(style: Style, text: &str) -> String {
    format!("  {}\n", style.paint(Role::Dim, text))
}

/// Why a newly created network was or was not selected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CreateSelection {
    /// `--no-use`.
    Skipped,
    Selected,
    NotSelected(String),
}

pub(crate) fn format_network_created(
    style: Style,
    context: &MeshContext,
    network: &str,
    selection: &CreateSelection,
) -> String {
    let mut out = headline(
        style,
        Status::Done,
        &format!("Network {} created", terminal_text(network)),
    );
    out.push_str(&context.render());
    match selection {
        CreateSelection::Skipped => {}
        CreateSelection::Selected => {
            out.push('\n');
            out.push_str(&headline(
                style,
                Status::Done,
                "Selected for new environments",
            ));
            out.push_str(&quiet(style, "New environments ask before connecting."));
        }
        CreateSelection::NotSelected(reason) => {
            out.push('\n');
            out.push_str(&headline(
                style,
                Status::Attention,
                "Not selected for new environments",
            ));
            out.push_str(&quiet(style, reason));
        }
    }
    out
}

pub(crate) fn format_network_list(
    style: Style,
    mesh: &NetworkMesh,
    context: &MeshContext,
    networks: &[Network],
    selected: Option<&str>,
) -> String {
    if networks.is_empty() {
        let mut out = String::from("No networks yet.\n");
        out.push_str(&context.render());
        out.push('\n');
        out.push_str(&next(
            style,
            &mesh.command(&format!(
                "create NAME --org {}",
                terminal_text(context.organization.as_deref().unwrap_or("ORG"))
            )),
        ));
        return out;
    }
    let names: Vec<String> = networks
        .iter()
        .map(|network| terminal_text(&network.id))
        .collect();
    let width = names
        .iter()
        .map(|name| name.chars().count())
        .max()
        .unwrap_or(0)
        .max(4);
    let mut out = String::from("Networks\n");
    out.push_str(&context.render());
    out.push('\n');
    out.push_str(&format!(
        "  {:<width$}  {:<5}  {:<7}  CREATED\n",
        "NAME", "NODES", "INVITES"
    ));
    let mut marked = false;
    for (network, name) in networks.iter().zip(&names) {
        let is_selected = selected.is_some_and(|selected| selected == network.id);
        marked |= is_selected;
        let mark = if is_selected {
            style.status(Status::Selected)
        } else {
            " ".to_owned()
        };
        out.push_str(&format!(
            "{mark} {name:<width$}  {:<5}  {:<7}  {}\n",
            network.node_count,
            network.invite_count,
            terminal_text(&network.created_at)
        ));
    }
    if marked {
        out.push('\n');
        out.push_str(&quiet(
            style,
            &format!(
                "{} selected for new environments",
                style.glyph(Status::Selected)
            ),
        ));
    }
    out
}

pub(crate) fn format_network_selected(style: Style, selection: &NetworkSelection) -> String {
    let mut out = headline(
        style,
        Status::Done,
        &format!("Selected network {}", terminal_text(&selection.network_id)),
    );
    out.push_str(&MeshContext::of_selection(selection).render());
    out.push('\n');
    out.push_str(&quiet(style, connect_policy(selection.auto_connect)));
    out.push_str(&quiet(
        style,
        "Existing environment attachments are unchanged.",
    ));
    out
}

fn connect_policy(auto_connect: bool) -> &'static str {
    if auto_connect {
        "New environments connect automatically."
    } else {
        "New environments ask before connecting."
    }
}

pub(crate) fn format_network_current(selection: Option<&NetworkSelection>) -> String {
    let Some(selection) = selection else {
        return "No network is selected.\n".to_owned();
    };
    let mut out = format!("{}\n", terminal_text(&selection.network_id));
    out.push_str(&MeshContext::of_selection(selection).render());
    out.push_str(&format!(
        "  New VMs       {}\n",
        if selection.auto_connect {
            "connect automatically"
        } else {
            "ask before connecting"
        }
    ));
    out
}

pub(crate) fn format_nodes(
    style: Style,
    mesh: &NetworkMesh,
    context: &MeshContext,
    network: Option<&str>,
    nodes: &[Node],
) -> String {
    let title = network
        .map(terminal_text)
        .unwrap_or_else(|| "All networks".to_owned());
    if nodes.is_empty() {
        let mut out = match network {
            Some(_) => format!("No nodes enrolled in {title} yet.\n"),
            None => "No nodes enrolled yet.\n".to_owned(),
        };
        out.push_str(&context.render());
        out.push('\n');
        out.push_str(&next(style, "Create a node enrollment:"));
        out.push_str(&format!(
            "  {}\n",
            mesh.command(&format!(
                "enroll create --org {} --network {} --node-name NAME",
                terminal_text(context.organization.as_deref().unwrap_or("ORG")),
                network.map(terminal_text).unwrap_or_else(|| "NAME".into())
            ))
        ));
        return out;
    }
    let show_network = network.is_none() || super::nodes_have_multiple_networks(nodes);
    let rows: Vec<(String, String, &'static str, String)> = nodes
        .iter()
        .map(|node| {
            (
                trimmed(&node.network_id),
                terminal_text(&node.name),
                if node.connected {
                    "reported online"
                } else {
                    "reported offline"
                },
                trimmed(&node.peer_url),
            )
        })
        .collect();
    let network_width = rows
        .iter()
        .map(|row| row.0.chars().count())
        .max()
        .unwrap_or(0)
        .max(7);
    let name_width = rows
        .iter()
        .map(|row| row.1.chars().count())
        .max()
        .unwrap_or(0)
        .max(4);
    let mut out = format!("{title}\n");
    out.push_str(&context.render());
    out.push('\n');
    if show_network {
        out.push_str(&format!(
            "  {:<network_width$}  {:<name_width$}  {:<16}  PEER\n",
            "NETWORK", "NODE", "STATUS"
        ));
    } else {
        out.push_str(&format!(
            "  {:<name_width$}  {:<16}  PEER\n",
            "NODE", "STATUS"
        ));
    }
    for (network, name, status, peer) in &rows {
        let status_text = format!("{status:<16}");
        let status_text = if status.ends_with("online") {
            style.paint(Role::Success, &status_text)
        } else {
            style.paint(Role::Dim, &status_text)
        };
        if show_network {
            out.push_str(&format!(
                "  {network:<network_width$}  {name:<name_width$}  {status_text}  {peer}\n"
            ));
        } else {
            out.push_str(&format!("  {name:<name_width$}  {status_text}  {peer}\n"));
        }
    }
    out.push('\n');
    out.push_str(&quiet(
        style,
        "Every listed node is enrolled. Status is what the node last reported to the Mesh;",
    ));
    out.push_str(&quiet(style, "connectivity was not checked."));
    out
}

fn trimmed(value: &str) -> String {
    match value.trim() {
        "" => "-".to_owned(),
        value => terminal_text(value),
    }
}

pub(crate) fn format_invite(
    style: Style,
    mesh: &NetworkMesh,
    context: &MeshContext,
    invite: &Invite,
) -> String {
    let mut out = headline(
        style,
        Status::Done,
        &format!(
            "Invitation created for {}",
            terminal_text(&invite.network_id)
        ),
    );
    out.push_str(&context.render());
    out.push_str(&format!(
        "  Expires       {}{}one use\n",
        terminal_text(&invite.expires_at),
        style.separator()
    ));
    out.push('\n');
    out.push_str("  Run on the receiving device:\n");
    out.push_str(&format!(
        "  cw network join --mesh-url {} {}\n",
        terminal_text(mesh.url()),
        terminal_text(&invite.invite_code)
    ));
    out.push('\n');
    out.push_str(&quiet(
        style,
        if mesh.kind == Some(MeshKind::Local) {
            "The receiving device must be able to reach this endpoint."
        } else {
            "Keep the invitation private; it can be used once."
        },
    ));
    out
}

pub(crate) fn format_node_enrollment(
    style: Style,
    mesh: &NetworkMesh,
    context: &MeshContext,
    enrollment: &NodeEnrollment,
) -> String {
    let mut out = headline(
        style,
        Status::Done,
        &format!(
            "Node enrollment created for {}",
            terminal_text(&enrollment.network_id)
        ),
    );
    out.push_str(&context.render());
    let node = enrollment.node_name.trim();
    if !node.is_empty() {
        out.push_str(&format!("  Node          {}\n", terminal_text(node)));
    }
    out.push_str(&format!(
        "  Expires       {}{}one use\n",
        terminal_text(&enrollment.expires_at),
        style.separator()
    ));
    out.push('\n');
    out.push_str("  Redeem on the node:\n");
    out.push_str(&format!(
        "  cw network enroll redeem --mesh-url {} {}{}\n",
        terminal_text(mesh.url()),
        terminal_text(&enrollment.enrollment_code),
        if node.is_empty() {
            String::new()
        } else {
            format!(" --node-name {}", terminal_text(node))
        }
    ));
    out
}

pub(crate) fn format_node_enrolled(
    style: Style,
    context: &MeshContext,
    node: &str,
    network: &str,
) -> String {
    let mut out = headline(
        style,
        Status::Done,
        &format!(
            "Node {} enrolled in {}",
            terminal_text(node),
            terminal_text(network)
        ),
    );
    out.push_str(&context.render());
    out.push_str(&format!(
        "  Connectivity  {}\n",
        style.paint(Role::Dim, "not checked")
    ));
    out
}

pub(crate) fn format_node_revoked(
    style: Style,
    context: &MeshContext,
    node: &str,
    network: &str,
) -> String {
    let mut out = headline(
        style,
        Status::Done,
        &format!(
            "Node {} revoked from {}",
            terminal_text(node),
            terminal_text(network)
        ),
    );
    out.push_str(&context.render());
    out
}

pub(crate) fn format_network_joined(
    style: Style,
    context: &MeshContext,
    network: &str,
    select_with: Option<&str>,
) -> String {
    let mut out = headline(
        style,
        Status::Done,
        &format!("Joined network {}", terminal_text(network)),
    );
    out.push_str(&context.render());
    if let Some(command) = select_with {
        out.push('\n');
        out.push_str(&next(
            style,
            &format!("Select it for new environments: {command}"),
        ));
    }
    out
}

/// The confirmation shown before a network is deleted: the exact Mesh,
/// endpoint and organization, the prerequisite and what is removed.
pub(crate) fn format_delete_prompt(context: &MeshContext, network: &str) -> String {
    format!(
        "Delete network {} on {} ({})?\n  Organization: {}. Registered nodes must be revoked first.\n  Removes its invitations, enrollments, groups, policies, stored values, grants and task history.\n  The name cannot be reused.\n",
        terminal_text(network),
        context.label,
        terminal_text(&context.endpoint),
        terminal_text(context.organization.as_deref().unwrap_or("-")),
    )
}

/// How clearing the saved selection went after a confirmed deletion.
#[derive(Debug)]
pub(crate) enum SelectionCleanup {
    /// The selection was another network, Mesh or organization, or absent.
    Untouched,
    Cleared,
    Failed(String),
}

pub(crate) fn format_network_deleted(
    style: Style,
    mesh: &NetworkMesh,
    context: &MeshContext,
    network: &str,
    cleanup: &SelectionCleanup,
) -> String {
    let mut out = headline(
        style,
        Status::Done,
        &format!("Network {} deleted", terminal_text(network)),
    );
    out.push_str(&context.render());
    out.push_str(&quiet(style, "Its name cannot be reused."));
    match cleanup {
        SelectionCleanup::Untouched => {}
        SelectionCleanup::Cleared => {
            out.push_str(&quiet(style, "Its saved selection was cleared."));
        }
        SelectionCleanup::Failed(error) => {
            out.push('\n');
            out.push_str(&headline(
                style,
                Status::Attention,
                "The saved selection could not be cleared",
            ));
            out.push_str(&quiet(style, &terminal_text(error)));
            out.push('\n');
            out.push_str(&next(style, &mesh.command("clear")));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MeshAuthSource, ResolvedMeshConfig};
    use crate::output::Charset;

    fn plain() -> Style {
        Style::new(false, Charset::Unicode)
    }

    fn mesh(kind: Option<MeshKind>, url: &str) -> NetworkMesh {
        NetworkMesh {
            kind,
            resolved: ResolvedMeshConfig::static_token_from(
                url.into(),
                "cw_synthetic",
                MeshAuthSource::Explicit,
            )
            .unwrap(),
            owner_organization: Some("org-demo".into()),
        }
    }

    fn network(id: &str, nodes: i64) -> Network {
        Network {
            id: id.into(),
            org_id: "org-demo".into(),
            created_at: "2026-10-19T12:00:00Z".into(),
            node_count: nodes,
            invite_count: 0,
        }
    }

    #[test]
    fn results_name_the_mesh_endpoint_and_organization() {
        let cloud = mesh(Some(MeshKind::Cloud), "https://mesh.codewire.sh");
        let context = MeshContext::new(&cloud, Some("org-demo"));
        assert_eq!(
            format_network_created(plain(), &context, "work", &CreateSelection::Selected),
            "✓ Network work created\n  Mesh          Codewire Cloud Mesh\n  Endpoint      https://mesh.codewire.sh\n  Organization  org-demo\n\n✓ Selected for new environments\n  New environments ask before connecting.\n"
        );
        let local = mesh(Some(MeshKind::Local), "http://127.0.0.1:18090");
        let context = MeshContext::new(&local, Some("local-org-1"));
        let list = format_network_list(
            plain(),
            &local,
            &context,
            &[network("work", 2), network("staging-long", 0)],
            Some("work"),
        );
        assert!(list.starts_with("Networks\n  Mesh          Local Mesh service\n  Endpoint      http://127.0.0.1:18090\n  Organization  local-org-1\n\n"));
        assert!(list.contains("› work          2      0        2026-10-19T12:00:00Z\n"));
        assert!(list.contains("  staging-long  0      0"));
        assert!(list.ends_with("  › selected for new environments\n"));
    }

    #[test]
    fn empty_and_unselected_lists_stay_neutral() {
        let other = mesh(None, "https://mesh.example.test");
        let context = MeshContext::new(&other, Some("org-demo"));
        let empty = format_network_list(plain(), &other, &context, &[], None);
        assert_eq!(
            empty,
            "No networks yet.\n  Mesh          Mesh service\n  Endpoint      https://mesh.example.test\n  Organization  org-demo\n\n→ cw network create NAME --org org-demo --mesh-url https://mesh.example.test\n"
        );
        let list = format_network_list(plain(), &other, &context, &[network("a", 0)], None);
        assert!(!list.contains("selected for new environments"));
    }

    #[test]
    fn nodes_separate_enrollment_report_and_connectivity() {
        let cloud = mesh(Some(MeshKind::Cloud), "https://mesh.codewire.sh");
        let context = MeshContext::new(&cloud, Some("org-demo"));
        let nodes = [Node {
            network_id: "work".into(),
            name: "laptop".into(),
            peer_url: String::new(),
            connected: true,
        }];
        let text = format_nodes(plain(), &cloud, &context, Some("work"), &nodes);
        assert!(text.starts_with("work\n  Mesh          Codewire Cloud Mesh\n"));
        assert!(text.contains("  NODE    STATUS            PEER\n  laptop  reported online   -\n"));
        assert!(text.contains("connectivity was not checked."));
        let empty = format_nodes(plain(), &cloud, &context, Some("work"), &[]);
        assert!(empty.starts_with("No nodes enrolled in work yet.\n"));
        assert!(empty.contains(
            "cw --cloud network enroll create --org org-demo --network work --node-name NAME"
        ));
    }

    #[test]
    fn deletion_reports_a_failed_selection_cleanup_as_partial() {
        let cloud = mesh(Some(MeshKind::Cloud), "https://mesh.codewire.sh");
        let context = MeshContext::new(&cloud, Some("org-demo"));
        assert_eq!(
            format_delete_prompt(&context, "work"),
            "Delete network work on Codewire Cloud Mesh (https://mesh.codewire.sh)?\n  Organization: org-demo. Registered nodes must be revoked first.\n  Removes its invitations, enrollments, groups, policies, stored values, grants and task history.\n  The name cannot be reused.\n"
        );
        let text = format_network_deleted(
            plain(),
            &cloud,
            &context,
            "work",
            &SelectionCleanup::Failed("permission denied".into()),
        );
        assert!(text.starts_with("✓ Network work deleted\n"));
        assert!(text.contains("! The saved selection could not be cleared\n  permission denied\n"));
        assert!(text.ends_with("→ cw --cloud network clear\n"));
    }

    #[test]
    fn current_selection_names_its_mesh() {
        let selection = NetworkSelection::new(
            MeshKind::Local,
            "http://127.0.0.1:18090",
            "local-org-1",
            "dev",
            true,
        );
        assert_eq!(
            format_network_current(Some(&selection)),
            "dev\n  Mesh          Local Mesh service\n  Endpoint      http://127.0.0.1:18090\n  Organization  local-org-1\n  New VMs       connect automatically\n"
        );
        assert_eq!(format_network_current(None), "No network is selected.\n");
    }
}
