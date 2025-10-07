// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

pub mod args;
pub mod backend;
pub mod virtio_media;

use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
    thread::{spawn, JoinHandle},
};

use backend::VhostUserMediaBackend;
use log::error;
use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, ThisError)]
/// Errors related to low level helpers
pub enum Error {
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(backend::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
}

#[derive(PartialEq, Debug)]
pub struct MediaConfiguration {
    pub socket_path: PathBuf,
    pub device_type: DeviceType,
}

#[derive(PartialEq, Debug, Clone)]
pub enum DeviceType {
    Proxy { device_path: PathBuf },
}

pub fn start_backend(config: MediaConfiguration) -> Result<()> {
    let MediaConfiguration {
        socket_path,
        device_type,
    } = config;

    // TODO: open v4l2 device
    // TODO: VIDIOC_QUERYCAP ioctl to get `device_caps` and `card` for config <https://www.kernel.org/doc/html/latest/userspace-api/media/v4l/vidioc-querycap.html#c.V4L.v4l2_capability>
    // TODO: get `device_type` somehow
    // <https://www.kernel.org/doc/html/v4.17/media/kapi/v4l2-dev.html#video-device-registration>

    let handle: JoinHandle<Result<()>> = spawn(move || loop {
        // There isn't much value in complicating code here to return an error from the
        // threads, and so the code uses unwrap() instead. The panic on a thread
        // won't cause trouble to the main() function and should be safe for the
        // daemon.
        let backend = Arc::new(RwLock::new(
            VhostUserMediaBackend::new(device_type.clone())
                .map_err(Error::CouldNotCreateBackend)?,
        ));

        let mut daemon = VhostUserDaemon::new(
            String::from("vhost-device-media-backend"),
            backend,
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .map_err(Error::CouldNotCreateDaemon)?;

        daemon.serve(&socket_path).map_err(Error::ServeFailed)?;
    });

    handle.join().map_err(std::panic::resume_unwind).unwrap()
}
