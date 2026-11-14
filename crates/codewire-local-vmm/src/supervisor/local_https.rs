//! The supervisor's side of local HTTPS hostnames (#4316).
//!
//! One task owns the router. After every operation, and every few seconds,
//! it rebuilds the table of hostnames from the running environments'
//! labelled ports, keeps the router listening while any environment has a
//! labelled port, and publishes what it is doing for the RPCs. A stopped
//! environment's hostnames leave the table, so the router refuses them at the
//! handshake; a port that could not be listened on is tried again, so running
//! `sudo cw local-https setup`, or the other program ending, is picked up
//! without a restart.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use codewire_workspace_access::daemon::DaemonSessionClient;
use tokio::sync::{Notify, watch};
use tonic::Status;
use uuid::Uuid;

use super::SupervisorRpc;
use crate::control::v1;
use crate::diagnostic_log::{self, LogField};
use crate::local_https::ca::{CA_CERTIFICATE_FILE, CA_DIRECTORY, LocalCa};
use crate::local_https::choice::{self, PortChoice};
use crate::local_https::{BindError, Route, Router, Routes, hostname};
use crate::supervisor_metadata::{EnvironmentRecord, StoredEnvironmentState};

/// How often the table is rebuilt, and a refused port tried again, when no
/// operation prompts it sooner.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);
/// How long an RPC waits for a reconcile that started after it asked, so
/// what it reports includes an environment just created or a port just
/// chosen.
const FRESH_WAIT: Duration = Duration::from_secs(5);

/// One labelled port of an environment, and its hostname if it makes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LabelledPort {
    pub(super) guest_port: u16,
    pub(super) label: String,
    pub(super) hostname: Option<String>,
}

/// The labelled ports `project` declares for the environment `name`, in
/// guest port order.
pub(super) fn labelled_ports(
    name: &str,
    project: &codewire_project::ProjectSpec,
) -> Vec<LabelledPort> {
    let mut ports: Vec<LabelledPort> = project
        .application_ports
        .iter()
        .filter(|port| !port.label.is_empty())
        .map(|port| LabelledPort {
            guest_port: port.port,
            label: port.label.clone(),
            hostname: hostname(&port.label, name),
        })
        .collect();
    ports.sort_by_key(|port| port.guest_port);
    ports
}

fn stored_labelled_ports(environment: &EnvironmentRecord) -> Vec<LabelledPort> {
    environment
        .project_spec_json
        .as_deref()
        .and_then(|json| serde_json::from_slice::<codewire_project::ProjectSpec>(json).ok())
        .map(|project| labelled_ports(&environment.name, &project))
        .unwrap_or_default()
}

/// Why a create is refused: a labelled port whose hostname another
/// environment already has. A label that makes no valid hostname is no reason:
/// that port simply has no HTTPS URL, and `cw ports` says why. `None` when
/// every hostname is free.
pub(super) fn hostname_refusal<'a>(
    name: &str,
    project: &codewire_project::ProjectSpec,
    others: impl IntoIterator<Item = &'a EnvironmentRecord>,
) -> Option<String> {
    let ports = labelled_ports(name, project);
    for other in others {
        for theirs in stored_labelled_ports(other) {
            if let Some(port) = ports
                .iter()
                .find(|port| port.hostname.is_some() && port.hostname == theirs.hostname)
            {
                return Some(format!(
                    "port {} would be served at https://{}, which {}'s port {} already has; \
                     rename this environment or change the label",
                    port.guest_port,
                    theirs.hostname.unwrap_or_default(),
                    other.name,
                    theirs.guest_port
                ));
            }
        }
    }
    None
}

/// What the router is doing, as the RPCs report it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RouterStatus {
    state: v1::LocalHttpsState,
    port: u16,
    failure: String,
}

impl RouterStatus {
    fn new(state: v1::LocalHttpsState, port: u16) -> Self {
        Self {
            state,
            port,
            failure: String::new(),
        }
    }

    fn name(&self) -> &'static str {
        match self.state {
            v1::LocalHttpsState::Unspecified => "unspecified",
            v1::LocalHttpsState::Unused => "unused",
            v1::LocalHttpsState::Serving => "serving",
            v1::LocalHttpsState::NotPermitted => "not_permitted",
            v1::LocalHttpsState::InUse => "in_use",
            v1::LocalHttpsState::Off => "off",
            v1::LocalHttpsState::Failed => "failed",
        }
    }
}

/// A reconcile's status, and the newest request it began after, so an RPC
/// can wait for a reconcile that saw what it asked about.
#[derive(Clone, Debug)]
struct Published {
    status: RouterStatus,
    answers: u64,
}

/// The RPCs' view of the router task.
pub(super) struct LocalHttpsHandle {
    status: watch::Receiver<Published>,
    requests: Arc<AtomicU64>,
    wake: Arc<Notify>,
}

/// The router task's ends, before it is spawned.
pub(super) struct LocalHttpsTask {
    status: watch::Sender<Published>,
    requests: Arc<AtomicU64>,
    wake: Arc<Notify>,
}

pub(super) fn channel() -> (LocalHttpsHandle, LocalHttpsTask) {
    let (status, receiver) = watch::channel(Published {
        status: RouterStatus::new(
            v1::LocalHttpsState::Unused,
            crate::local_https::DEFAULT_PORT,
        ),
        answers: 0,
    });
    let requests = Arc::new(AtomicU64::new(0));
    let wake = Arc::new(Notify::new());
    (
        LocalHttpsHandle {
            status: receiver,
            requests: requests.clone(),
            wake: wake.clone(),
        },
        LocalHttpsTask {
            status,
            requests,
            wake,
        },
    )
}

impl LocalHttpsTask {
    /// Run the router for as long as the supervisor runs.
    pub(super) fn spawn(self, rpc: SupervisorRpc) {
        drop(tokio::spawn(self.run(rpc)));
    }

    async fn run(self, rpc: SupervisorRpc) {
        let root = rpc.supervisor.core().config.root.clone();
        let routes = Arc::new(SupervisorRoutes {
            rpc: rpc.clone(),
            table: Mutex::default(),
            clients: Mutex::default(),
        });
        let mut operations = rpc.operation_events.subscribe();
        let mut ticks = tokio::time::interval(RECONCILE_INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut serving = Serving::default();
        loop {
            let answers = self.requests.load(Ordering::SeqCst);
            let wanted = routes.rebuild();
            let status = serving.reconcile(&root, &routes, wanted);
            if self.status.borrow().status != status {
                diagnostic_log::record(
                    rpc.supervisor.log.as_deref(),
                    "local_https_state",
                    &[
                        ("state", LogField::Name(status.name())),
                        ("port", LogField::Count(u64::from(status.port))),
                    ],
                );
            }
            self.status.send_replace(Published { status, answers });
            tokio::select! {
                _ = ticks.tick() => {}
                () = self.wake.notified() => {}
                // A lagged or closed channel only means a rebuild is due.
                _ = operations.recv() => {}
            }
        }
    }
}

/// The router and the CA it serves with, while one is wanted.
#[derive(Default)]
struct Serving {
    router: Option<Router>,
    ca: Option<Arc<LocalCa>>,
}

impl Serving {
    fn reconcile(
        &mut self,
        root: &Path,
        routes: &Arc<SupervisorRoutes>,
        wanted: bool,
    ) -> RouterStatus {
        let choice = choice::read(root);
        if !wanted {
            self.router = None;
            return RouterStatus::new(v1::LocalHttpsState::Unused, choice_port(choice));
        }
        let PortChoice::Port(port) = choice else {
            self.router = None;
            return RouterStatus::new(v1::LocalHttpsState::Off, 0);
        };
        if self
            .router
            .as_ref()
            .is_some_and(|router| router.port() == port)
        {
            return RouterStatus::new(v1::LocalHttpsState::Serving, port);
        }
        self.router = None;
        let ca = match &self.ca {
            Some(ca) => ca.clone(),
            None => match LocalCa::load_or_create(root) {
                Ok(ca) => self.ca.insert(Arc::new(ca)).clone(),
                Err(error) => {
                    return RouterStatus {
                        failure: error.to_string(),
                        ..RouterStatus::new(v1::LocalHttpsState::Failed, port)
                    };
                }
            },
        };
        match Router::start(ca, routes.clone(), port) {
            Ok(router) => {
                self.router = Some(router);
                RouterStatus::new(v1::LocalHttpsState::Serving, port)
            }
            Err(BindError::NotPermitted(_)) => {
                RouterStatus::new(v1::LocalHttpsState::NotPermitted, port)
            }
            Err(BindError::InUse(_)) => RouterStatus::new(v1::LocalHttpsState::InUse, port),
            Err(error @ BindError::Other(..)) => RouterStatus {
                failure: error.to_string(),
                ..RouterStatus::new(v1::LocalHttpsState::Failed, port)
            },
        }
    }
}

fn choice_port(choice: PortChoice) -> u16 {
    match choice {
        PortChoice::Port(port) => port,
        PortChoice::Off => 0,
    }
}

/// The hostnames of the running environments, rebuilt by the task, and one
/// daemon client per running environment generation.
struct SupervisorRoutes {
    rpc: SupervisorRpc,
    table: Mutex<HashMap<String, Route>>,
    clients: Mutex<HashMap<Uuid, (u64, DaemonSessionClient)>>,
}

impl SupervisorRoutes {
    /// Rebuild the table; whether any environment, running or not, has a
    /// labelled port. Where two environments' hostnames coincide, as only
    /// ones made before create refused that can, the first name in order
    /// keeps it.
    fn rebuild(&self) -> bool {
        let mut table = HashMap::new();
        let mut wanted = false;
        let mut running = Vec::new();
        {
            let core = self.rpc.supervisor.core();
            for environment in core.state.environments.values() {
                let ports = stored_labelled_ports(environment);
                wanted |= !ports.is_empty();
                if environment.state != StoredEnvironmentState::Running {
                    continue;
                }
                running.push(environment.id);
                for port in ports {
                    if let Some(hostname) = port.hostname {
                        table.entry(hostname).or_insert_with(|| Route {
                            environment_id: environment.id,
                            environment: environment.name.clone(),
                            guest_port: port.guest_port,
                        });
                    }
                }
            }
        }
        *self.table.lock().unwrap_or_else(PoisonError::into_inner) = table;
        self.clients
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|id, _| running.contains(id));
        wanted
    }

    /// The route's environment generation while it runs.
    fn running_generation(&self, route: &Route) -> Option<u64> {
        let core = self.rpc.supervisor.core();
        core.state
            .environments
            .values()
            .find(|environment| {
                environment.id == route.environment_id
                    && environment.state == StoredEnvironmentState::Running
            })
            .map(|environment| environment.generation)
    }
}

impl Routes for SupervisorRoutes {
    fn route(&self, host: &str) -> Option<Route> {
        self.table
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(host)
            .cloned()
    }

    async fn daemon(&self, route: &Route) -> Option<DaemonSessionClient> {
        let generation = self.running_generation(route)?;
        let cached = self
            .clients
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&route.environment_id)
            .filter(|(cached, _)| *cached == generation)
            .map(|(_, client)| client.clone());
        if let Some(client) = cached {
            return Some(client);
        }
        let access = self
            .rpc
            .environment_daemon_access(route.environment_id)
            .await
            .ok()?;
        let client = crate::guest_loopback::connect_daemon_access(access)
            .await
            .ok()?;
        self.clients
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(route.environment_id, (generation, client.clone()));
        Some(client)
    }
}

impl SupervisorRpc {
    /// `GetLocalHttps`: the router's state after a fresh reconcile, and the
    /// named environment's labelled ports.
    pub(super) async fn local_https(&self, name: &str) -> Result<v1::LocalHttps, Status> {
        let status = self.fresh_local_https_status().await;
        let hosts = if name.is_empty() {
            Vec::new()
        } else {
            let core = self.supervisor.core();
            let environment = core
                .state
                .environments
                .get(name)
                .ok_or_else(|| Status::not_found("local environment was not found"))?;
            stored_labelled_ports(environment)
                .into_iter()
                .map(|port| v1::LocalHttpsHost {
                    guest_port: u32::from(port.guest_port),
                    label: port.label,
                    hostname: port.hostname.unwrap_or_default(),
                })
                .collect()
        };
        Ok(v1::LocalHttps {
            state: status.state as i32,
            port: u32::from(status.port),
            ca_certificate_path: self.ca_certificate_path().display().to_string(),
            failure: status.failure,
            hosts,
        })
    }

    /// `SetLocalHttpsPort`: remember the choice; the reconcile that follows
    /// acts on it.
    pub(super) async fn set_local_https_port(&self, port: u32) -> Result<v1::LocalHttps, Status> {
        let choice = match port {
            0 => PortChoice::Off,
            port => PortChoice::Port(
                u16::try_from(port)
                    .map_err(|_| Status::invalid_argument("port must be 1 to 65535"))?,
            ),
        };
        let root = self.supervisor.core().config.root.clone();
        choice::write(&root, choice)
            .map_err(|_| Status::internal("the local HTTPS port choice could not be saved"))?;
        self.local_https("").await
    }

    /// The status of a reconcile that began after this call, or the last
    /// one when none follows in time.
    async fn fresh_local_https_status(&self) -> RouterStatus {
        let request = self.local_https.requests.fetch_add(1, Ordering::SeqCst) + 1;
        self.local_https.wake.notify_one();
        let mut receiver = self.local_https.status.clone();
        // A timeout, or a task that has ended, leaves the last status.
        let _ = tokio::time::timeout(
            FRESH_WAIT,
            receiver.wait_for(|published| published.answers >= request),
        )
        .await;
        receiver.borrow().status.clone()
    }

    fn ca_certificate_path(&self) -> PathBuf {
        self.supervisor
            .core()
            .config
            .root
            .join(CA_DIRECTORY)
            .join(CA_CERTIFICATE_FILE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::tests::project_environment;

    fn project(ports: &[(u16, &str)]) -> codewire_project::ProjectSpec {
        codewire_project::ProjectSpec {
            application_ports: ports
                .iter()
                .map(|(port, label)| codewire_project::ApplicationPort {
                    port: *port,
                    label: (*label).to_owned(),
                    access: String::new(),
                })
                .collect(),
            ..Default::default()
        }
    }

    fn environment(name: &str, ports: &[(u16, &str)]) -> EnvironmentRecord {
        let mut environment = project_environment();
        environment.name = name.to_owned();
        environment.project_spec_json = Some(project(ports).canonical_json().unwrap());
        environment
    }

    #[test]
    fn only_labelled_ports_get_hostnames_in_port_order() {
        let ports = labelled_ports(
            "shop-a",
            &project(&[(5173, "vite"), (8080, ""), (3000, "web")]),
        );
        assert_eq!(
            ports,
            [
                LabelledPort {
                    guest_port: 3000,
                    label: "web".into(),
                    hostname: Some("web-shop-a.cw.localhost".into()),
                },
                LabelledPort {
                    guest_port: 5173,
                    label: "vite".into(),
                    hostname: Some("vite-shop-a.cw.localhost".into()),
                },
            ]
        );
    }

    #[test]
    fn a_create_with_no_labelled_port_is_never_refused() {
        let others = [environment("shop", &[(3000, "web")])];
        for name in ["Shop_A", "shop.a", &"a".repeat(63)] {
            assert_eq!(
                hostname_refusal(name, &project(&[(3000, "")]), &others),
                None
            );
        }
    }

    #[test]
    fn a_label_that_makes_no_hostname_never_refuses_a_create() {
        let others = [environment("shop", &[(3000, "web")])];
        for (name, label) in [
            ("shop_a", "web"),
            ("shop-a", "Web UI"),
            ("shop.a", "web"),
            (&*"a".repeat(63), "web"),
        ] {
            assert_eq!(
                hostname_refusal(name, &project(&[(3000, label)]), &others),
                None,
                "{name} with {label:?}"
            );
            let ports = labelled_ports(name, &project(&[(3000, label)]));
            assert_eq!(ports[0].hostname, None, "{name} with {label:?}");
        }
    }

    #[test]
    fn a_hostname_another_environment_has_is_refused_naming_it() {
        let others = [environment("a", &[(4000, "web-shop")])];
        let refusal = hostname_refusal("shop-a", &project(&[(3000, "web")]), &others).unwrap();
        assert_eq!(
            refusal,
            "port 3000 would be served at https://web-shop-a.cw.localhost, which a's port 4000 \
             already has; rename this environment or change the label"
        );
        assert_eq!(
            hostname_refusal("shop-b", &project(&[(3000, "web")]), &others),
            None
        );
    }
}
