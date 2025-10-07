// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::io::Result as IoResult;
use std::os::fd::OwnedFd;
use std::path::PathBuf;

use log::{info, warn};
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::bindings::{
    virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1},
    virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC},
};
use virtio_queue::{DescriptorChain, QueueOwnedT};
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap};
use vmm_sys_util::{
    epoll::EventSet,
    eventfd::{EventFd, EFD_NONBLOCK},
};

use crate::DeviceType;

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 2;

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Eq, PartialEq, ThisError)]
/// Errors related to vhost-device-media daemon.
pub enum Error {
    #[error("Failed to handle event, didn't match EPOLLIN")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event")]
    HandleEventUnknown,
    #[error("Descriptor not found")]
    DescriptorNotFound,
    #[error("Failed to send notification")]
    NotificationFailed,
    #[error("Failed to create new EventFd")]
    EventFdFailed,
    #[error("Failed to open {0}: {1}")]
    V4L2DeviceOpen(PathBuf, nix::errno::Errno),
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        std::io::Error::other(e)
    }
}

pub enum DeviceBackend {
    Proxy { fd: OwnedFd },
}

pub struct VhostUserMediaBackend {
    device: DeviceBackend,
    event_idx: bool,
    pub exit_event: EventFd,
    mem: Option<GuestMemoryLoadGuard<GuestMemoryMmap>>,
}

type MediaDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

impl VhostUserMediaBackend {
    pub fn new(device_type: DeviceType) -> Result<Self> {
        let device = match device_type {
            DeviceType::Proxy { device_path } => DeviceBackend::Proxy {
                fd: nix::fcntl::open(&device_path, OFlag::O_RDWR, Mode::S_IRWXU)
                    .map_err(|err| Error::V4L2DeviceOpen(device_path.clone(), err))?,
            },
        };
        Ok(VhostUserMediaBackend {
            device,
            event_idx: false,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?,
            mem: None,
        })
    }

    /// Process the requests in the vring and dispatch replies
    fn process_requests(
        &mut self,
        requests: Vec<MediaDescriptorChain>,
        _vring: &VringRwLock,
    ) -> Result<()> {
        if requests.is_empty() {
            info!("No pending requests");
            return Ok(());
        }

        // Iterate over each request.
        //
        // The layout of the various structures, to be read from and written into the
        // descriptor buffers, is defined in the Virtio specification for each
        // protocol.
        for desc_chain in requests.clone() {
            let descriptors: Vec<_> = desc_chain.clone().collect();

            info!("Request: contains {} descriptors", descriptors.len(),);

            for (i, desc) in descriptors.iter().enumerate() {
                let perm = if desc.is_write_only() {
                    "write only"
                } else {
                    "read only"
                };

                // We now can iterate over the set of descriptors and process the messages.
                // There will be a number of read only descriptors containing
                // messages as defined by the specification. If any replies are
                // needed, the driver should have placed one or more writable
                // descriptors at the end for the device to use to reply.
                info!("Length of the {} descriptor@{} is: {}", perm, i, desc.len());
            }
        }

        Ok(())
    }

    /// Process the requests in the vring and dispatch replies
    fn process_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        // Collect all pending requests
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().clone())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        if self.process_requests(requests, vring).is_ok() {
            // Send notification once all the requests are processed
            vring
                .signal_used_queue()
                .map_err(|_| Error::NotificationFailed)?;
        }

        Ok(())
    }
}

/// VhostUserBackendMut trait methods
impl VhostUserBackendMut for VhostUserMediaBackend {
    type Vring = VringRwLock;
    type Bitmap = ();

    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        // this matches the current libvhost defaults except VHOST_F_LOG_ALL
        (1 << VIRTIO_F_VERSION_1)
            | (1 << VIRTIO_F_NOTIFY_ON_EMPTY)
            | (1 << VIRTIO_RING_F_INDIRECT_DESC)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            // Protocol features are optional and must not be defined unless required and must be
            // accompanied by the supporting PROTOCOL_FEATURES bits in features.
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    fn update_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        self.mem = Some(mem.memory());
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        _thread_id: usize,
    ) -> IoResult<()> {
        if evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        match device_event {
            0 => {
                let vring = &vrings[0];

                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        vring.disable_notification().unwrap();
                        self.process_queue(vring)?;
                        if !vring.enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_queue(vring)?;
                }
            }
            _ => {
                warn!("unhandled device_event: {device_event}");
                return Err(Error::HandleEventUnknown.into());
            }
        }
        Ok(())
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        self.exit_event.try_clone().ok()
    }
}
