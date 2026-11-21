#![allow(clippy::unwrap_used)]
//! The plugin against a fake kubelet, both on Unix sockets in a scratch
//! directory that stands in for the kubelet's device plugin directory.

use std::future::Future;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::time::Duration;

use codewire_kvm_device_plugin::v1beta1::device_plugin_client::DevicePluginClient;
use codewire_kvm_device_plugin::v1beta1::registration_server::{Registration, RegistrationServer};
use codewire_kvm_device_plugin::v1beta1::{
    AllocateRequest, ContainerAllocateRequest, DeviceSpec, Empty, ListAndWatchResponse,
    RegisterRequest,
};
use codewire_kvm_device_plugin::{Config, Error, KUBELET_SOCKET, PLUGIN_SOCKET, run};
use hyper_util::rt::TokioIo;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::{Channel, Endpoint, Server};
use tonic::{Code, Request, Response, Status, Streaming};

const WAIT: Duration = Duration::from_secs(10);

async fn bounded<T>(what: &str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, future)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

struct FakeKubelet {
    registered: mpsc::UnboundedSender<RegisterRequest>,
    refuse: bool,
}

#[tonic::async_trait]
impl Registration for FakeKubelet {
    async fn register(&self, request: Request<RegisterRequest>) -> Result<Response<Empty>, Status> {
        self.registered.send(request.into_inner()).unwrap();
        if self.refuse {
            return Err(Status::invalid_argument("resource name already taken"));
        }
        Ok(Response::new(Empty {}))
    }
}

fn start_kubelet(dir: &Path, refuse: bool) -> mpsc::UnboundedReceiver<RegisterRequest> {
    let (registered, requests) = mpsc::unbounded_channel();
    let listener = UnixListener::bind(dir.join(KUBELET_SOCKET)).unwrap();
    tokio::spawn(
        Server::builder()
            .add_service(RegistrationServer::new(FakeKubelet { registered, refuse }))
            .serve_with_incoming(UnixListenerStream::new(listener)),
    );
    requests
}

fn start_plugin(
    dir: &Path,
    node_device: &Path,
    devices: u16,
) -> tokio::task::JoinHandle<Result<std::convert::Infallible, Error>> {
    tokio::spawn(run(Config {
        plugin_dir: dir.to_owned(),
        node_device: node_device.to_str().unwrap().to_owned(),
        devices: NonZeroU16::new(devices).unwrap(),
        poll: Duration::from_millis(20),
    }))
}

async fn plugin_client(dir: &Path) -> DevicePluginClient<Channel> {
    let socket: PathBuf = dir.join(PLUGIN_SOCKET);
    let connector = tower::service_fn(move |_| {
        let socket = socket.clone();
        async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(socket).await?)) }
    });
    let channel = bounded(
        "the plugin's socket",
        Endpoint::from_static("http://plugin").connect_with_connector(connector),
    )
    .await
    .unwrap();
    DevicePluginClient::new(channel)
}

async fn next_list(updates: &mut Streaming<ListAndWatchResponse>) -> Vec<(String, String)> {
    let response = bounded("a device list", updates.message())
        .await
        .unwrap()
        .unwrap();
    response
        .devices
        .into_iter()
        .map(|device| (device.id, device.health))
        .collect()
}

fn listed(health: &str, ids: &[&str]) -> Vec<(String, String)> {
    ids.iter()
        .map(|id| ((*id).to_owned(), health.to_owned()))
        .collect()
}

fn allocation(ids: &[&str]) -> AllocateRequest {
    AllocateRequest {
        container_requests: vec![ContainerAllocateRequest {
            devices_ids: ids.iter().map(|id| (*id).to_owned()).collect(),
        }],
    }
}

#[tokio::test]
async fn registers_codewire_kvm_and_hands_out_the_device_read_write() {
    let dir = tempfile::tempdir().unwrap();
    let mut registrations = start_kubelet(dir.path(), false);
    let _plugin = start_plugin(dir.path(), Path::new("/dev/null"), 3);

    let registration = bounded("a registration", registrations.recv())
        .await
        .unwrap();
    assert_eq!(registration.version, "v1beta1");
    assert_eq!(registration.endpoint, "codewire-kvm.sock");
    assert_eq!(registration.resource_name, "codewire.sh/kvm");
    let options = registration.options.unwrap();
    assert!(!options.pre_start_required);
    assert!(!options.get_preferred_allocation_available);

    let mut client = plugin_client(dir.path()).await;
    let mut updates = bounded("ListAndWatch", client.list_and_watch(Empty {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        next_list(&mut updates).await,
        listed("Healthy", &["kvm-0", "kvm-1", "kvm-2"])
    );

    let response = bounded("Allocate", client.allocate(allocation(&["kvm-1"])))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.container_responses.len(), 1);
    let container = &response.container_responses[0];
    assert_eq!(
        container.devices,
        vec![DeviceSpec {
            container_path: "/dev/kvm".to_owned(),
            host_path: "/dev/null".to_owned(),
            permissions: "rw".to_owned(),
        }]
    );
    assert!(container.mounts.is_empty());
    assert!(container.envs.is_empty());
    assert!(container.annotations.is_empty());
    assert!(container.cdi_devices.is_empty());

    let refused = bounded("Allocate", client.allocate(allocation(&["kvm-3"])))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn reports_the_device_unhealthy_until_it_is_a_character_device() {
    let dir = tempfile::tempdir().unwrap();
    let node_device = dir.path().join("kvm");
    let mut registrations = start_kubelet(dir.path(), false);
    let _plugin = start_plugin(dir.path(), &node_device, 2);
    bounded("a registration", registrations.recv())
        .await
        .unwrap();

    let mut client = plugin_client(dir.path()).await;
    let mut updates = bounded("ListAndWatch", client.list_and_watch(Empty {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        next_list(&mut updates).await,
        listed("Unhealthy", &["kvm-0", "kvm-1"])
    );

    std::os::unix::fs::symlink("/dev/null", &node_device).unwrap();
    assert_eq!(
        next_list(&mut updates).await,
        listed("Healthy", &["kvm-0", "kvm-1"])
    );
}

#[tokio::test]
async fn registers_again_when_its_socket_is_removed() {
    let dir = tempfile::tempdir().unwrap();
    let _plugin = start_plugin(dir.path(), Path::new("/dev/null"), 1);
    // The kubelet's socket appears after the plugin starts, as when both
    // start together on a node.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut registrations = start_kubelet(dir.path(), false);
    bounded("a registration", registrations.recv())
        .await
        .unwrap();

    std::fs::remove_file(dir.path().join(PLUGIN_SOCKET)).unwrap();
    let again = bounded("a second registration", registrations.recv())
        .await
        .unwrap();
    assert_eq!(again.resource_name, "codewire.sh/kvm");

    let mut client = plugin_client(dir.path()).await;
    let mut updates = bounded("ListAndWatch", client.list_and_watch(Empty {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(next_list(&mut updates).await, listed("Healthy", &["kvm-0"]));
}

#[tokio::test]
async fn stops_when_the_kubelet_refuses_the_registration() {
    let dir = tempfile::tempdir().unwrap();
    let mut registrations = start_kubelet(dir.path(), true);
    let plugin = start_plugin(dir.path(), Path::new("/dev/null"), 1);
    bounded("a registration", registrations.recv())
        .await
        .unwrap();
    let ended = bounded("the plugin to stop", plugin).await.unwrap();
    assert!(matches!(ended, Err(Error::Refused(_))), "{ended:?}");
}
