//! The device plugin service the kubelet calls on this plugin's socket.

use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::watch;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status};

use crate::CONTAINER_DEVICE;
use crate::v1beta1::device_plugin_server::DevicePlugin;
use crate::v1beta1::{
    AllocateRequest, AllocateResponse, ContainerAllocateResponse, Device, DevicePluginOptions,
    DeviceSpec, Empty, ListAndWatchResponse, PreStartContainerRequest, PreStartContainerResponse,
    PreferredAllocationRequest, PreferredAllocationResponse,
};

/// Whether the node's device can be handed out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Health {
    Healthy,
    Unhealthy,
}

impl Health {
    /// A node device is usable when its path is a character device.
    pub(crate) fn of(device: &Path) -> Self {
        match std::fs::metadata(device) {
            Ok(metadata) if metadata.file_type().is_char_device() => Self::Healthy,
            _ => Self::Unhealthy,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "Healthy",
            Self::Unhealthy => "Unhealthy",
        }
    }
}

/// Every advertised device is the same node device: the count only bounds
/// how many Pods on the node may hold it at once.
pub(crate) struct KvmPlugin {
    ids: Arc<[String]>,
    node_device: String,
    health: watch::Receiver<Health>,
}

impl KvmPlugin {
    pub(crate) fn new(count: u16, node_device: String, health: watch::Receiver<Health>) -> Self {
        let ids = (0..count).map(|index| format!("kvm-{index}")).collect();
        Self {
            ids,
            node_device,
            health,
        }
    }
}

/// The health now, then again each time it changes.
fn health_updates(mut health: watch::Receiver<Health>) -> impl Stream<Item = Health> {
    health.mark_changed();
    futures::stream::unfold(health, |mut health| async move {
        health.changed().await.ok()?;
        let now = *health.borrow_and_update();
        Some((now, health))
    })
}

type DeviceStream = Pin<Box<dyn Stream<Item = Result<ListAndWatchResponse, Status>> + Send>>;

#[tonic::async_trait]
impl DevicePlugin for KvmPlugin {
    async fn get_device_plugin_options(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<DevicePluginOptions>, Status> {
        Ok(Response::new(DevicePluginOptions::default()))
    }

    type ListAndWatchStream = DeviceStream;

    async fn list_and_watch(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::ListAndWatchStream>, Status> {
        let ids = Arc::clone(&self.ids);
        let updates = health_updates(self.health.clone()).map(move |health| {
            let devices = ids
                .iter()
                .map(|id| Device {
                    id: id.clone(),
                    health: health.as_str().to_owned(),
                    topology: None,
                })
                .collect();
            Ok(ListAndWatchResponse { devices })
        });
        Ok(Response::new(Box::pin(updates)))
    }

    async fn get_preferred_allocation(
        &self,
        _request: Request<PreferredAllocationRequest>,
    ) -> Result<Response<PreferredAllocationResponse>, Status> {
        Err(Status::unimplemented(
            "every device is the same; registration does not offer a preference",
        ))
    }

    async fn allocate(
        &self,
        request: Request<AllocateRequest>,
    ) -> Result<Response<AllocateResponse>, Status> {
        let mut container_responses = Vec::new();
        for container in request.into_inner().container_requests {
            if let Some(unknown) = container
                .devices_ids
                .iter()
                .find(|id| !self.ids.contains(id))
            {
                return Err(Status::invalid_argument(format!(
                    "device {unknown:?} is not one this plugin advertised"
                )));
            }
            container_responses.push(ContainerAllocateResponse {
                devices: vec![DeviceSpec {
                    container_path: CONTAINER_DEVICE.to_owned(),
                    host_path: self.node_device.clone(),
                    permissions: "rw".to_owned(),
                }],
                ..ContainerAllocateResponse::default()
            });
        }
        Ok(Response::new(AllocateResponse {
            container_responses,
        }))
    }

    async fn pre_start_container(
        &self,
        _request: Request<PreStartContainerRequest>,
    ) -> Result<Response<PreStartContainerResponse>, Status> {
        Ok(Response::new(PreStartContainerResponse {}))
    }
}
