// VIRTIO RPMB vhost-user backend
//
// Copyright 2023 Linaro Ltd. All Rights Reserved.
// Emmanouil Pitsidianakis <manos.pitsidianakis@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

#![deny(
    /* groups */
    clippy::correctness,
    clippy::suspicious,
    clippy::complexity,
    clippy::perf,
    clippy::style,
    clippy::nursery,
    //* restriction */
    clippy::dbg_macro,
    clippy::rc_buffer,
    clippy::as_underscore,
    clippy::assertions_on_result_states,
    //* pedantic */
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::ptr_as_ptr,
    clippy::bool_to_int_with_if,
    clippy::borrow_as_ptr,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_lossless,
    clippy::cast_ptr_alignment,
    clippy::naive_bytecount
)]
#![allow(
    clippy::significant_drop_in_scrutinee,
    clippy::significant_drop_tightening
)]

use std::{
    convert,
    convert::{TryFrom, TryInto},
    fs::File,
    io::{Error as IoError, ErrorKind as IoErrorKind, Read, Write},
    result,
    sync::{Arc, RwLock},
};

use clap::Parser;
use log::*;
use thiserror::Error as ThisError;
use vhost::{
    vhost_user,
    vhost_user::{
        message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures},
        Listener,
    },
};
use vhost_user_backend::{VhostUserBackendMut, VhostUserDaemon, VringRwLock, VringT};
use virtio_bindings::bindings::{
    virtio_config::VIRTIO_F_VERSION_1,
    virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC},
};
use virtio_queue::{DescriptorChain, QueueOwnedT};
use vm_memory::{
    ByteValued, Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap,
};
use vmm_sys_util::{
    epoll::EventSet,
    eventfd::{EventFd, EFD_NONBLOCK},
};

mod io;
use io::*;

const QUEUE_SIZE: usize = 1024;

pub type Result<T> = std::result::Result<T, VuRpmbError>;
type RpmbDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

#[derive(Debug, Eq, PartialEq, ThisError)]
/// Errors related to vhost-device-rpmb daemon.
pub enum VuRpmbError {
    #[error("Descriptor not found")]
    DescriptorNotFound,
    #[error("Notification send failed")]
    SendNotificationFailed,
    #[error("Can't create eventfd")]
    EventFdError,
    #[error("Failed to handle event")]
    HandleEventNotEpollIn,
    #[error("Unknown device event")]
    HandleEventUnknownEvent,
    #[error("Key already set")]
    KeyAlreadySet,
    #[error("Key not set")]
    KeyNotSet,
    #[error("Received unexpected write only descriptor at index {0}")]
    UnexpectedWriteOnlyDescriptor(usize),
    #[error("Received unexpected readable descriptor at index {0}")]
    UnexpectedReadableDescriptor(usize),
    #[error("Invalid descriptor count {0}")]
    UnexpectedDescriptorCount(usize),
    #[error("Invalid descriptor size, expected: {0}, found: {1}")]
    UnexpectedDescriptorSize(usize, u32),
    #[error("Failed to access rpmb source")]
    UnexpectedRpmbSourceAccessError,
    #[error("Failed to read from the rpmb source")]
    UnexpectedRpmbSourceError,
    #[error("rpmb source file doesn't exists or can't be accessed")]
    AccessRpmbSourceFile,
    #[error("Key size {0} is smaller than {1}")]
    InvalidKeySize(u64, u64),
    #[error("Wrong socket count: {0}")]
    InvalidSocketCount(u32),
    #[error("Descriptor write failed")]
    DescriptorWriteFailed,
}

impl convert::From<VuRpmbError> for IoError {
    fn from(e: VuRpmbError) -> Self {
        Self::new(IoErrorKind::Other, e)
    }
}

pub struct VuRpmbBackend {
    event_idx: bool,
    config: VuRpmbConfig,
    virtio_config: VirtioRpmbConfig,
    flash_image: Vec<u8>,
    key: Key,
    pub exit_event: EventFd,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    last_result: LastResult,
    write_counter: u32,
}

impl VuRpmbBackend {
    /// Create a new virtio rpmb device.
    pub fn new(config: VuRpmbConfig) -> std::result::Result<Self, IoError> {
        let mut ret = Self {
            event_idx: false,
            config,
            virtio_config: VirtioRpmbConfig::default(),
            flash_image: vec![],
            key: Key::new(),
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| VuRpmbError::EventFdError)?,
            mem: None,
            last_result: LastResult::None,
            write_counter: 0,
        };
        ret.load_flash_image()?.set_key()?;

        Ok(ret)
    }

    #[allow(clippy::cognitive_complexity)]
    pub fn process_requests(
        &mut self,
        requests: Vec<RpmbDescriptorChain>,
        vring: &VringRwLock,
    ) -> Result<bool> {
        if requests.is_empty() {
            return Ok(true);
        }

        for desc_chain in requests {
            let descriptors: Vec<_> = desc_chain.clone().collect();

            if descriptors.len() != 1 {
                return Err(VuRpmbError::UnexpectedDescriptorCount(descriptors.len()));
            }

            let descriptor = descriptors[0];
            let _to_read = descriptor.len() as usize;

            if descriptor.is_write_only() {
                return Err(VuRpmbError::UnexpectedWriteOnlyDescriptor(0));
            }

            if descriptor.len() as usize != std::mem::size_of::<VirtioRpmbFrame>() {
                return Err(VuRpmbError::UnexpectedDescriptorSize(
                    std::mem::size_of::<VirtioRpmbFrame>(),
                    descriptor.len(),
                ));
            }

            let frame: VirtioRpmbFrame = desc_chain
                .memory()
                .read_obj::<VirtioRpmbFrame>(descriptor.addr())
                .map_err(|_| VuRpmbError::UnexpectedRpmbSourceError)?;
            let mut resp: VirtioRpmbFrame = VirtioRpmbFrame {
                nonce: frame.nonce,
                ..VirtioRpmbFrame::default()
            };
            // Frame is packed and block_count is unaligned, so copy it to a local variable
            // instead of referencing it which is undefined behaviour.
            let block_count: u16 = frame.block_count.into();
            let write_counter: u32 = frame.write_counter.into();
            let offset: u64 = u64::from(u16::from(frame.address)) * RPMB_BLOCK_SIZE;
            // TODO: handle unwrap()
            let req = RpmbRequestKind::try_from(frame.req_resp).unwrap();
            let result: RpmbOpResult = match req {
                RpmbRequestKind::ProgramKey => {
                    if block_count != 1_u16 {
                        log::debug!(
                            "weird block count in frame for ProgramKey request: {}",
                            block_count
                        );
                        RpmbOpResult::GeneralFailure
                    } else if self.key.set(frame.key_mac).is_err() {
                        RpmbOpResult::WriteFailure
                    } else if let Err(err) = self.save_key() {
                        log::error!("Could not save new key to file: {}", err);
                        RpmbOpResult::GeneralFailure
                    } else {
                        RpmbOpResult::Ok
                    }
                }
                // allow 0 (NONCONF)
                RpmbRequestKind::GetWriteCounter if block_count > 1 => {
                    log::debug!("GetWriteCounter: invalid block count {}", block_count);
                    RpmbOpResult::GeneralFailure
                }
                RpmbRequestKind::GetWriteCounter => match self.key.get() {
                    Ok(_) => {
                        resp.write_counter = self.write_counter.into();
                        RpmbOpResult::Ok
                    }
                    Err(_) => {
                        log::debug!("GetWriteCounter: no key programmed");
                        RpmbOpResult::NoAuthKey
                    }
                },
                // Run the checks from:
                // 5.12.6.1.3 Device Requirements: Device Operation: Data Write
                RpmbRequestKind::DataWrite if self.key.get().is_err() => {
                    log::warn!("DataWrite: no key programmed");
                    RpmbOpResult::NoAuthKey
                }
                RpmbRequestKind::DataWrite
                    if block_count == 0 || block_count > self.virtio_config.max_wr_cnt().into() =>
                {
                    log::debug!("DataWrite: invalid block_count {}", block_count);
                    RpmbOpResult::GeneralFailure
                }
                RpmbRequestKind::DataWrite
                    if offset > u64::from(self.virtio_config.capacity()) * (128 * KiB) =>
                {
                    log::debug!("DataWrite: offset over virtio_config capacity");
                    RpmbOpResult::AddrFailure
                }
                RpmbRequestKind::DataWrite if !self.verify_mac(&frame) => RpmbOpResult::AuthFailure,
                RpmbRequestKind::DataWrite if write_counter != self.write_counter => {
                    RpmbOpResult::CountFailure
                }
                RpmbRequestKind::DataWrite => {
                    let offset = 0;
                    self.write_counter += 1;
                    // TODO
                    for _i in 0..block_count {
                        self.flash_image[offset..][..RPMB_BLOCK_SIZE as usize]
                            .copy_from_slice(&resp.data);
                    }

                    RpmbOpResult::Ok
                }
                // Run the checks from:
                // 5.12.6.1.4 Device Requirements: Device Operation: Data Read
                RpmbRequestKind::DataRead if block_count != 1 => {
                    // Despite the configuration, the specification only allows for reading one
                    // block at a time: "If block count has not been set to 1 then
                    // VIRTIO_RPMB_RES_GENERAL_FAILURE SHOULD be responded as result."
                    log::debug!("DataRead: invalid block count {} != 1", block_count);
                    RpmbOpResult::GeneralFailure
                }
                RpmbRequestKind::DataRead
                    if offset > u64::from(self.virtio_config.capacity()) * (128 * KiB) =>
                {
                    log::debug!("DataRead: offset over virtio_config capacity");
                    RpmbOpResult::AddrFailure
                }
                RpmbRequestKind::DataRead => {
                    resp.req_resp = RpmbResponseKind::DataRead.into();
                    resp.address = frame.address;
                    resp.block_count = 1.into();
                    let offset: usize =
                        u16::from(frame.address) as usize * RPMB_BLOCK_SIZE as usize;
                    log::debug!("reading block from offset {}", offset);
                    resp.data
                        .copy_from_slice(&self.flash_image[offset..][..RPMB_BLOCK_SIZE as usize]);
                    RpmbOpResult::Ok
                }
                RpmbRequestKind::ResultRead => match self.last_result {
                    LastResult::None => RpmbOpResult::GeneralFailure,
                    LastResult::ProgramKey { result } => {
                        resp.result = result.into();
                        resp.req_resp = RpmbRequestKind::ProgramKey.into();
                        self.last_result = LastResult::None;
                        RpmbOpResult::Ok
                    }
                    LastResult::DataWrite { result, address } => {
                        resp.result = result.into();
                        resp.req_resp = RpmbRequestKind::DataWrite.into();
                        resp.write_counter = self.write_counter.into();
                        resp.address = address;
                        self.last_result = LastResult::None;
                        RpmbOpResult::Ok
                    }
                },
            };
            self.last_result = (&frame, req, result).into();

            // calculate MAC
            self.update_mac(&mut resp);

            desc_chain
                .memory()
                .write_obj(resp, descriptor.addr())
                .map_err(|_| VuRpmbError::DescriptorWriteFailed)?;

            if let Err(err) = vring.add_used(
                desc_chain.head_index(),
                std::mem::size_of::<VirtioRpmbFrame>() as u32,
            ) {
                log::warn!("Couldn't return used descriptors to the ring: {}", err);
            }
        }

        Ok(true)
    }

    /// Process the requests in the vring and dispatch replies
    fn process_queue(&mut self, vring: &VringRwLock) -> Result<bool> {
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|_| VuRpmbError::DescriptorNotFound)?
            .collect();

        if self.process_requests(requests, vring)? {
            // Send notification once all the requests are processed
            vring
                .signal_used_queue()
                .map_err(|_| VuRpmbError::SendNotificationFailed)?;
        }

        Ok(true)
    }

    /// Load flash image from path.
    fn load_flash_image(&mut self) -> std::result::Result<&mut Self, IoError> {
        let stat = match std::fs::metadata(&self.config.flash_path) {
            Ok(s) => s,
            Err(err) => {
                error!(
                    "Could not access the flash image file at given location {}: {}",
                    self.config.flash_path.display(),
                    err
                );
                return Err(err);
            }
        };
        if stat.len() > crate::MAX_RPMB_SIZE {
            warn!(
                "{} is larger ({} bytes) than the maximum supported size ({} bytes).",
                self.config.flash_path.display(),
                stat.len(),
                crate::MAX_RPMB_SIZE
            );
        }
        self.flash_image.clear();
        self.flash_image.reserve(stat.len().try_into().unwrap());
        self.virtio_config = VirtioRpmbConfig::new(std::cmp::min(crate::MAX_RPMB_SIZE, stat.len()));

        File::options()
            .write(false)
            .create(false)
            .read(true)
            .open(&self.config.flash_path)?
            .read_to_end(&mut self.flash_image)?;

        Ok(self)
    }

    /// Set key from path.
    pub fn set_key(&mut self) -> std::result::Result<&mut Self, IoError> {
        let stat = match std::fs::metadata(&self.config.key_path) {
            Ok(s) => s,
            Err(err) => {
                return if self.config.key_set {
                    error!(
                        "Could not access the key file at given location {}: {}",
                        self.config.key_path.display(),
                        err
                    );
                    Err(err)
                } else {
                    Ok(self)
                };
            }
        };
        match stat.len().cmp(&RPMB_KEY_MAC_SIZE) {
            std::cmp::Ordering::Less => {
                return Err(VuRpmbError::InvalidKeySize(stat.len(), RPMB_KEY_MAC_SIZE).into());
            }
            std::cmp::Ordering::Greater => {
                // being too big isn't fatal, we just ignore the excess
                warn!(
                    "Key file is bigger than expected size {} by {} bytes, ignoring the excess.",
                    RPMB_KEY_MAC_SIZE,
                    stat.len() - RPMB_KEY_MAC_SIZE
                );
            }
            std::cmp::Ordering::Equal => {}
        }

        let mut key = [0; RPMB_KEY_MAC_SIZE as usize];

        File::options()
            .write(false)
            .create(false)
            .read(true)
            .open(&self.config.key_path)?
            .read_exact(&mut key)?;
        if let Err(err) = self.key.set(key) {
            if self.config.key_set {
                // Forward error to caller, key should stay set.
                return Err(err.into());
            }
            self.key = Key::new_with(key);
        }
        Ok(self)
    }

    /// Save key to key path.
    pub fn save_key(&mut self) -> std::result::Result<&mut Self, IoError> {
        let key = self.key.get()?;
        debug_assert_eq!(
            key.len(),
            RPMB_KEY_MAC_SIZE as usize,
            "Set key length {} is not equal to RPMB_KEY_MAC_SIZE (= {})",
            key.len(),
            RPMB_KEY_MAC_SIZE
        );

        File::options()
            .write(true)
            .create(true)
            .read(false)
            .open(&self.config.key_path)?
            .write_all(&key)?;
        Ok(self)
    }

    pub fn update_mac(&self, frame: &mut VirtioRpmbFrame) {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        // From the specification:
        //
        //   The MAC is calculated using HMAC SHA-256. It takes
        //   as input a key and a message. The key used for the MAC calculation
        //   is always the 256-bit RPMB authentication key. The message used as
        //   input to the MAC calculation is the concatenation of the fields in
        //   the RPMB frames excluding stuff bytes and the MAC itself.
        let mut mac = HmacSha256::new_from_slice(&self.key.get().unwrap())
            .expect("HMAC can take key of any size");

        mac.update(&frame.data);
        let result = mac.finalize();
        frame.key_mac.copy_from_slice(&result.into_bytes());
    }

    pub fn verify_mac(&self, frame: &VirtioRpmbFrame) -> bool {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&self.key.get().unwrap())
            .expect("HMAC can take key of any size");

        mac.update(&frame.data);
        // `verify_slice` will return `Ok(())` if code is correct, `Err(MacError)`
        // otherwise
        mac.verify_slice(&frame.key_mac).is_ok()
    }
}

/// VhostUserBackend trait methods
impl VhostUserBackendMut for VuRpmbBackend {
    type Vring = VringRwLock;
    type Bitmap = ();

    fn num_queues(&self) -> usize {
        VHOST_USER_RPMB_MAX_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        // this matches the current libvhost defaults except VHOST_F_LOG_ALL
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        self.virtio_config
            .as_slice()
            .iter()
            .skip(offset as usize)
            .take(size as usize)
            .cloned()
            .collect()
    }

    fn set_config(&mut self, _offset: u32, _buf: &[u8]) -> std::result::Result<(), std::io::Error> {
        panic!("Access to configuration space is not supported.");
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    fn update_memory(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> result::Result<(), IoError> {
        self.mem = Some(mem);
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        _thread_id: usize,
    ) -> result::Result<(), IoError> {
        if evset != EventSet::IN {
            return Err(VuRpmbError::HandleEventNotEpollIn.into());
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
                warn!("unhandled device_event: {}", device_event);
                return Err(VuRpmbError::HandleEventUnknownEvent.into());
            }
        }
        Ok(())
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        self.exit_event.try_clone().ok()
    }
}

#[derive(Clone, Parser, Debug, PartialEq, Eq)]
#[clap(author, version, about, long_about = None)]
pub struct RpmbArgs {
    /// Location of vhost-user Unix domain socket.
    #[clap(short, long)]
    pub socket_path: std::path::PathBuf,
    /// Path to the backing store for the flash image, can be up to 32Mb in
    /// size.
    #[clap(short, long)]
    pub flash_path: std::path::PathBuf,
    /// Path to the backing store for the key of 32 bytes.
    #[clap(short, long)]
    pub key_path: std::path::PathBuf,
    /// Treat the value of key-path as set meaning the key cannot be
    /// reprogrammed by the guest.
    #[clap(long)]
    pub key_set: bool,
    /// Set the initial value of the devices write count. It is
    /// incremented by each write operation.
    #[clap(short, long)]
    pub initial_counter: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VuRpmbConfig {
    /// Location of vhost-user Unix domain socket.
    pub socket_path: std::path::PathBuf,
    /// Path to the backing store for the flash image, can be up to 32Mb in
    /// size.
    pub flash_path: std::path::PathBuf,
    /// Path to the backing store for the key of 32 bytes.
    pub key_path: std::path::PathBuf,
    /// Treat the value of key-path as set meaning the key cannot be
    /// reprogrammed by the guest.
    pub key_set: bool,
    /// Set the initial value of the devices write count. It is
    /// incremented by each write operation.
    pub initial_counter: u32,
}

impl TryFrom<RpmbArgs> for VuRpmbConfig {
    type Error = VuRpmbError;

    fn try_from(
        RpmbArgs {
            socket_path,
            flash_path,
            key_path,
            key_set,
            initial_counter,
        }: RpmbArgs,
    ) -> Result<Self> {
        Ok(Self {
            socket_path,
            flash_path,
            key_path,
            key_set,
            initial_counter,
        })
    }
}

pub fn start_backend(config: VuRpmbConfig) -> Result<()> {
    let socket_path = config.socket_path.clone();
    let vu_rpmb_backend = Arc::new(RwLock::new(VuRpmbBackend::new(config).unwrap()));

    let mut daemon = VhostUserDaemon::new(
        String::from("vhost-device-rpmb"),
        Arc::clone(&vu_rpmb_backend),
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .unwrap();

    let listener = Listener::new(socket_path, true).unwrap();
    daemon.start(listener).unwrap();

    match daemon.wait() {
        Ok(()) => {
            info!("Stopping cleanly.");
        }
        Err(vhost_user_backend::Error::HandleRequest(vhost_user::Error::PartialMessage)) => {
            info!(
                "vhost-user connection closed with partial message. If the VM is shutting down, \
                 this is expected behaviour; otherwise, it might be a bug."
            );
        }
        Err(e) => {
            warn!("Error running daemon: {:?}", e);
        }
    }

    // No matter the result, we need to shut down the worker thread.
    vu_rpmb_backend
        .read()
        .unwrap()
        .exit_event
        .write(1)
        .expect("Shutting down worker thread");

    Ok(())
}

/*
#[cfg(test)]
mod tests {

    use virtio_bindings::bindings::virtio_ring::VRING_DESC_F_NEXT;
    use virtio_queue::{mock::MockSplitQueue, Descriptor, Queue};
    use vm_memory::{Address, GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    use super::*;

    fn build_desc_chain(count: u16) -> RpmbDescriptorChain {
        let mem = &GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let vq = MockSplitQueue::new(mem, 16);

        // Create a descriptor chain with @count descriptors.
        for i in 0..count {
            let desc = Descriptor::new(
                u64::from(0x100 * (i + 1)),
                0x200,
                VRING_DESC_F_NEXT as u16,
                i + 1,
            );
            vq.desc_table().store(i, desc).unwrap();
        }

        // Put the descriptor index 0 in the first available ring position.
        mem.write_obj(0u16, vq.avail_addr().unchecked_add(4))
            .unwrap();

        // Set `avail_idx` to 1.
        mem.write_obj(1u16, vq.avail_addr().unchecked_add(2))
            .unwrap();

        // Create descriptor chain from pre-filled memory
        vq.create_queue::<Queue>()
            .unwrap()
            .iter(GuestMemoryAtomic::new(mem.clone()).memory())
            .unwrap()
            .next()
            .unwrap()
    }

    #[test]
    fn verify_chain_descriptors() {
        env_logger::init();
        let tmp_dir = tempdir().unwrap();

        let socket_path = tmp_dir.path().join("rpmb.sock");
        let key_path = tmp_dir.path().join("key");
        let mut key_file = File::create(&key_path).unwrap();
        key_file.write_all(&(0..32).collect::<Vec<u8>>()).unwrap();
        let flash_path = tmp_dir.path().join("flash.img");
        let mut flash_file = File::create(&flash_path).unwrap();
        flash_file
            .write_all(&vec![0; crate::MAX_RPMB_SIZE as usize])
            .unwrap();

        let mut backend = VuRpmbBackend::new(VuRpmbConfig {
            socket_path,
            key_path,
            flash_path,
            key_set: false,
            initial_counter: 0,
        })
        .unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );

        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        let desc_chain = build_desc_chain(1);
        tmp_dir.close().unwrap();
    }
}
*/
