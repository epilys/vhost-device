// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
use vm_memory::{ByteValued, Le32};

/// Virtio Media Configuration
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
#[doc(alias = "virtio_media_config")]
pub struct VirtioMediaConfig {
    pub device_caps: Le32,
    pub device_type: Le32,
    pub card: [u8; 32],
}

unsafe impl ByteValued for VirtioMediaConfig {}

pub const VIRTIO_MEDIA_CMD_OPEN: u32 = 1;
pub const VIRTIO_MEDIA_CMD_CLOSE: u32 = 2;
pub const VIRTIO_MEDIA_CMD_IOCTL: u32 = 3;
pub const VIRTIO_MEDIA_CMD_MMAP: u32 = 4;
pub const VIRTIO_MEDIA_CMD_MUNMAP: u32 = 5;

/// Header for all virtio commands from the driver to the device on the `commandq`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
#[doc(alias = "virtio_media_cmd_header")]
pub struct VirtioMediaCmdHeader {
    pub cmd: Le32,
    pub _reserved: Le32,
}

unsafe impl ByteValued for VirtioMediaCmdHeader {}

/// Header for all virtio responses from the device to the driver on the `commandq`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
#[doc(alias = "virtio_media_resp_header")]
pub struct VirtioMediaRespHeader {
    pub status: Le32,
    pub _reserved: Le32,
}

unsafe impl ByteValued for VirtioMediaRespHeader {}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
#[doc(alias = "v4l2_memory")]
enum V4l2Memory {
    Mmap = 1,
    UserPtr = 2,
    Dmabuf = 4,
}

#[doc(alias = "virtio_media_memory")]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub enum VirtioMediaMemory {
    #[doc(alias = "VIRTIO_MEDIA_MMAP")]
    Mmap = V4l2Memory::Mmap as _,
    #[doc(alias = "VIRTIO_MEDIA_SHARED_PAGES")]
    SharedPages = V4l2Memory::UserPtr as _,
    #[doc(alias = "VIRTIO_MEDIA_OBJECT")]
    Object = V4l2Memory::Dmabuf as _,
}
