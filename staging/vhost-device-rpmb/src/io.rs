// VIRTIO RPMB vhost-user backend
//
// Copyright 2023 Linaro Ltd. All Rights Reserved.
// Emmanouil Pitsidianakis <manos.pitsidianakis@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{convert::TryInto, sync::OnceLock};

use data_encoding::HEXUPPER;
use vm_memory::{Be16, Be32, ByteValued};

// These structures are defined in the specification
#[allow(non_upper_case_globals)]
pub const KiB: u64 = 1 << 10;
pub const MAX_RPMB_SIZE: u64 = KiB * 128 * 128;
pub const RPMB_KEY_MAC_SIZE: u64 = 32;
pub const RPMB_BLOCK_SIZE: u64 = 256;
pub const VHOST_USER_RPMB_MAX_QUEUES: usize = 1;

pub type KeySlice = [u8; RPMB_KEY_MAC_SIZE as usize];

#[repr(transparent)]
pub struct Key(OnceLock<KeySlice>);

impl Key {
    pub const fn new() -> Self {
        Self(OnceLock::new())
    }

    pub fn new_with(val: KeySlice) -> Self {
        Self(val.into())
    }

    pub fn set(&mut self, val: KeySlice) -> Result<(), crate::VuRpmbError> {
        self.0
            .set(val)
            .map_err(|_| crate::VuRpmbError::KeyAlreadySet)
    }

    pub fn get(&self) -> Result<KeySlice, crate::VuRpmbError> {
        self.0.get().cloned().ok_or(crate::VuRpmbError::KeyNotSet)
    }
}

impl Default for Key {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut ret = fmt.debug_tuple(stringify!(Key));
        if let Some(bytes) = self.0.get() {
            ret.field(&format_args!("{}", HEXUPPER.encode(bytes.as_slice())))
        } else {
            ret.field(&"uninitialized")
        }
        .finish()
    }
}

impl std::fmt::Display for Key {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Some(bytes) = self.0.get() {
            write!(fmt, "{}", HEXUPPER.encode(bytes.as_slice()))
        } else {
            write!(fmt, "uninitialized")
        }
    }
}

macro_rules! impl_try_from_int {
    ($t:ty, $i:ty, $($var:tt),+) => {
        impl std::convert::TryFrom<$i> for $t {
            type Error = crate::VuRpmbError;

            fn try_from(val: $i) -> Result<Self, Self::Error> {
                Ok(match val {
                    $(v if v == Self::$var as u16 => Self::$var),*,
                      _ => return Err(Self::Error::UnexpectedRpmbSourceError),
                })
            }
        }
    };
}

/// RPMB Request Types
#[derive(Debug, Copy, Clone)]
pub enum RpmbRequestKind {
    #[doc(alias = "VIRTIO_RPMB_REQ_PROGRAM_KEY")]
    ProgramKey = 0x0001,
    #[doc(alias = "VIRTIO_RPMB_REQ_GET_WRITE COUNTER")]
    GetWriteCounter = 0x0002,
    #[doc(alias = "VIRTIO_RPMB_REQ_DATA_WRITE")]
    DataWrite = 0x0003,
    #[doc(alias = "VIRTIO_RPMB_REQ_DATA_READ")]
    DataRead = 0x0004,
    #[doc(alias = "VIRTIO_RPMB_REQ_RESULT_READ")]
    ResultRead = 0x0005,
}

impl_try_from_int!(
    RpmbRequestKind,
    Be16,
    ProgramKey,
    GetWriteCounter,
    DataWrite,
    DataRead,
    ResultRead
);
impl_try_from_int!(
    RpmbRequestKind,
    u16,
    ProgramKey,
    GetWriteCounter,
    DataWrite,
    DataRead,
    ResultRead
);

impl From<RpmbRequestKind> for u16 {
    fn from(r: RpmbRequestKind) -> Self {
        r as Self
    }
}

impl From<RpmbRequestKind> for Be16 {
    fn from(r: RpmbRequestKind) -> Self {
        (r as u16).into()
    }
}

/// RPMB Response Types
#[derive(Debug, Copy, Clone)]
pub enum RpmbResponseKind {
    #[doc(alias = "VIRTIO_RPMB_RESP_PROGRAM_KEY")]
    ProgramKey = 0x0100,
    #[doc(alias = "VIRTIO_RPMB_RESP_GET_COUNTER")]
    GetCounter = 0x0200,
    #[doc(alias = "VIRTIO_RPMB_RESP_DATA_WRITE")]
    DataWrite = 0x0300,
    #[doc(alias = "VIRTIO_RPMB_RESP_DATA_READ")]
    DataRead = 0x0400,
}

impl_try_from_int!(
    RpmbResponseKind,
    Be16,
    ProgramKey,
    GetCounter,
    DataWrite,
    DataRead
);
impl_try_from_int!(
    RpmbResponseKind,
    u16,
    ProgramKey,
    GetCounter,
    DataWrite,
    DataRead
);

impl From<RpmbResponseKind> for u16 {
    fn from(r: RpmbResponseKind) -> Self {
        r as Self
    }
}

impl From<RpmbResponseKind> for Be16 {
    fn from(r: RpmbResponseKind) -> Self {
        (r as u16).into()
    }
}

// RPMB Operation Results
#[derive(Debug, Copy, Clone)]
pub enum RpmbOpResult {
    #[doc(alias = "VIRTIO_RPMB_RES_OK")]
    Ok = 0x0000,
    #[doc(alias = "VIRTIO_RPMB_RES_GENERAL_FAILURE")]
    GeneralFailure = 0x0001,
    #[doc(alias = "VIRTIO_RPMB_RES_AUTH_FAILURE")]
    AuthFailure = 0x0002,
    #[doc(alias = "VIRTIO_RPMB_RES_COUNT_FAILURE")]
    CountFailure = 0x0003,
    #[doc(alias = "VIRTIO_RPMB_RES_ADDR_FAILURE")]
    AddrFailure = 0x0004,
    #[doc(alias = "VIRTIO_RPMB_RES_WRITE_FAILURE")]
    WriteFailure = 0x0005,
    #[doc(alias = "VIRTIO_RPMB_RES_READ_FAILURE")]
    ReadFailure = 0x0006,
    #[doc(alias = "VIRTIO_RPMB_RES_NO_AUTH_KEY")]
    NoAuthKey = 0x0007,
    #[doc(alias = "VIRTIO_RPMB_RES_WRITE_COUNTER_EXPIRED")]
    WriteCounterExpired = 0x0080,
}

impl From<RpmbOpResult> for u16 {
    fn from(r: RpmbOpResult) -> Self {
        r as Self
    }
}

impl From<RpmbOpResult> for Be16 {
    fn from(r: RpmbOpResult) -> Self {
        (r as u16).into()
    }
}

#[doc(alias = "virtio_rpmb_config")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct VirtioRpmbConfig {
    capacity: u8,
    max_wr_cnt: u8,
    max_rd_cnt: u8,
}

impl Default for VirtioRpmbConfig {
    fn default() -> Self {
        Self::new(128 * KiB)
    }
}

impl VirtioRpmbConfig {
    pub fn new(map_size: u64) -> Self {
        Self {
            capacity: (map_size / (128 * KiB))
                .try_into()
                .expect("map_size is too big"),
            max_wr_cnt: 1,
            max_rd_cnt: 1,
        }
    }

    #[inline]
    pub const fn capacity(&self) -> u8 {
        self.capacity
    }

    #[inline]
    pub const fn max_wr_cnt(&self) -> u8 {
        self.max_wr_cnt
    }

    #[inline]
    #[allow(dead_code)]
    pub const fn max_rd_cnt(&self) -> u8 {
        self.max_rd_cnt
    }
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioRpmbConfig {}

/// This is based on the JDEC standard and not the currently not
/// up-streamed NVME standard.
#[doc(alias = "virtio_rpmb_frame")]
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct VirtioRpmbFrame {
    pub stuff: [u8; 196],
    pub key_mac: [u8; RPMB_KEY_MAC_SIZE as usize],
    pub data: [u8; RPMB_BLOCK_SIZE as usize],
    pub nonce: [u8; 16],
    /* remaining fields are big-endian */
    pub write_counter: Be32,
    pub address: Be16,
    pub block_count: Be16,
    pub result: Be16,
    pub req_resp: Be16,
}

impl Default for VirtioRpmbFrame {
    fn default() -> Self {
        Self {
            stuff: [0; 196],
            key_mac: [0; RPMB_KEY_MAC_SIZE as usize],
            data: [0; RPMB_BLOCK_SIZE as usize],
            nonce: [0; 16],
            write_counter: 0.into(),
            address: 0.into(),
            block_count: 0.into(),
            result: 0.into(),
            req_resp: 0.into(),
        }
    }
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioRpmbFrame {}

#[derive(Debug, Default)]
pub enum LastResult {
    #[default]
    None,
    ProgramKey {
        result: RpmbOpResult,
    },
    DataWrite {
        result: RpmbOpResult,
        address: Be16,
    },
}

impl From<(&VirtioRpmbFrame, RpmbRequestKind, RpmbOpResult)> for LastResult {
    fn from((frame, req, result): (&VirtioRpmbFrame, RpmbRequestKind, RpmbOpResult)) -> Self {
        match req {
            RpmbRequestKind::ProgramKey => Self::ProgramKey { result },
            RpmbRequestKind::DataWrite => Self::DataWrite {
                result,

                address: frame.address,
            },
            _ => Self::None,
        }
    }
}

//* refer to util/iov.c */
//static size_t vrpmb_iov_size(const struct iovec *iov,
//                             const unsigned int iov_cnt)
//{
//    size_t len;
//    unsigned int i;
//
//    len = 0;
//    for (i = 0; i < iov_cnt; i++) {
//        len += iov[i].iov_len;
//    }
//    return len;
//}
//
//
//static size_t vrpmb_iov_to_buf(const struct iovec *iov, const unsigned int
// iov_cnt,                               size_t offset, void *buf, size_t
// bytes)
//{
//    size_t done;
//    unsigned int i;
//    for (i = 0, done = 0; (offset || done < bytes) && i < iov_cnt; i++) {
//        if (offset < iov[i].iov_len) {
//            size_t len = MIN(iov[i].iov_len - offset, bytes - done);
//            memcpy(buf + done, iov[i].iov_base + offset, len);
//            done += len;
//            offset = 0;
//        } else {
//            offset -= iov[i].iov_len;
//        }
//    }
//    assert(offset == 0);
//    return done;
//}
//
//static size_t vrpmb_iov_from_buf(const struct iovec *iov, unsigned int
// iov_cnt,                                 size_t offset, const void *buf,
// size_t bytes)
//{
//    size_t done;
//    unsigned int i;
//    for (i = 0, done = 0; (offset || done < bytes) && i < iov_cnt; i++) {
//        if (offset < iov[i].iov_len) {
//            size_t len = MIN(iov[i].iov_len - offset, bytes - done);
//            memcpy(iov[i].iov_base + offset, buf + done, len);
//            done += len;
//            offset = 0;
//        } else {
//            offset -= iov[i].iov_len;
//        }
//    }
//    assert(offset == 0);
//    return done;
//}
//
//static void vrpmb_panic(VuDev *dev, const char *msg)
//{
//    g_critical("%s\n", msg);
//    exit(EXIT_FAILURE);
//}
//
//static const uint64_t vurpmb_features =
//    1ull << VIRTIO_F_VERSION_1 |
//    1ull << VIRTIO_RING_F_INDIRECT_DESC |
//    1ull << VIRTIO_RING_F_EVENT_IDX |
//    1ull << VHOST_USER_F_PROTOCOL_FEATURES;
//
//static uint64_t vrpmb_get_features(VuDev *dev)
//{
//    g_info("%s: 0x%"PRIx64, __func__, vurpmb_features);
//    return vurpmb_features;
//}
//
//static void vrpmb_set_features(VuDev *dev, uint64_t features)
//{
//    uint64_t missing_features = features & ~vurpmb_features;
//
//    if (missing_features) {
//        g_autoptr(GString) s = g_string_new("Requested unhandled feature");
//        g_string_append_printf(s, " 0x%" PRIx64, missing_features);
//        g_info("%s: %s", __func__, s->str);
//    }
//}
//
//static uint64_t vrpmb_get_protocol_features(VuDev *dev)
//{
//    const uint64_t proto_features = 1ull << VHOST_USER_PROTOCOL_F_CONFIG;
//    g_info("%s: %" PRIx64, __func__, proto_features);
//    return proto_features;
//}
//
//
//*
// * The configuration of the device is static and set when we start the
// * daemon.
// */
//static int
//vrpmb_get_config(VuDev *dev, uint8_t *config, uint32_t len)
//{
//    VuRpmb *r = container_of(dev, VuRpmb, dev.parent);
//    g_return_val_if_fail(len <= sizeof(struct virtio_rpmb_config), -1);
//    memcpy(config, &r->virtio_config, len);
//
//    g_info("%s: done", __func__);
//    return 0;
//}
//
//static int
//vrpmb_set_config(VuDev *dev, const uint8_t *data,
//                 uint32_t offset, uint32_t size,
//                 uint32_t flags)
//{
//    /* ignore */
//    return 0;
//}
//
//*
// * vrpmb_update_mac_in_frame:
// *
// * From the spec:
// * The MAC is calculated using HMAC SHA-256. It takes
// * as input a key and a message. The key used for the MAC calculation
// * is always the 256-bit RPMB authentication key. The message used as
// * input to the MAC calculation is the concatenation of the fields in
// * the RPMB frames excluding stuff bytes and the MAC itself.
// *
// * The code to do this has been lifted from the optee supplicant code
// * which itself uses a 3 clause BSD chunk of code.
// */
//
//static const int rpmb_frame_dlen = (sizeof(struct virtio_rpmb_frame) -
//                                    offsetof(struct virtio_rpmb_frame, data));
//
//static void vrpmb_update_mac_in_frame(VuRpmb *r, struct virtio_rpmb_frame
// *frm)
//{
//    hmac_sha256_ctx ctx;
//
//    hmac_sha256_init(&ctx, r->key, RPMB_KEY_MAC_SIZE);
//    hmac_sha256_update(&ctx, frm->data, rpmb_frame_dlen);
//    hmac_sha256_final(&ctx, &frm->key_mac[0], 32);
//}
//
//static bool vrpmb_verify_mac_in_frame(VuRpmb *r, struct virtio_rpmb_frame
// *frm)
//{
//    hmac_sha256_ctx ctx;
//    uint8_t calculated_mac[RPMB_KEY_MAC_SIZE];
//
//    hmac_sha256_init(&ctx, r->key, RPMB_KEY_MAC_SIZE);
//    hmac_sha256_update(&ctx, frm->data, rpmb_frame_dlen);
//    hmac_sha256_final(&ctx, calculated_mac, RPMB_KEY_MAC_SIZE);
//
//    return memcmp(calculated_mac, frm->key_mac, RPMB_KEY_MAC_SIZE) == 0;
//}
//
//*
// * Handlers for individual control messages
// */
//
//*
// * vrpmb_handle_program_key:
// *
// * Program the device with our key. The spec is a little hazzy on if
// * we respond straight away or we wait for the user to send a
// * VIRTIO_RPMB_REQ_RESULT_READ request.
// */
//static void vrpmb_handle_program_key(VuDev *dev, struct virtio_rpmb_frame
// *frame)
//{
//    VuRpmb *r = container_of(dev, VuRpmb, dev.parent);
//
//    /*
//     * Run the checks from:
//     * 5.12.6.1.1 Device Requirements: Device Operation: Program Key
//     */
//    r->last_reqresp = VIRTIO_RPMB_RESP_PROGRAM_KEY;
//
//    /* Fail if already programmed */
//    if (r->key) {
//        g_debug("key already programmed");
//        r->last_result = VIRTIO_RPMB_RES_WRITE_FAILURE;
//    } else if (be16toh(frame->block_count) != 1) {
//        g_debug("weird block counts (%d)", frame->block_count);
//        r->last_result = VIRTIO_RPMB_RES_GENERAL_FAILURE;
//    } else {
//        r->key = g_memdup(&frame->key_mac[0], RPMB_KEY_MAC_SIZE);
//        r->last_result = VIRTIO_RPMB_RES_OK;
//        if (key_path) {
//            GError *err = NULL;
//            if (!g_file_set_contents(key_path, (char *) r->key,
//                                     RPMB_KEY_MAC_SIZE, &err)) {
//                g_warning("%s: unable to persist key data to %s: %s",
//                          __func__, key_path, err->message);
//                g_error_free(err);
//            }
//        }
//    }
//
//
//    g_info("%s: req_resp = %x, result = %x", __func__,
//           r->last_reqresp, r->last_result);
//    return;
//}
//
// *
// * vrpmb_handle_get_write_counter:
// *
// * We respond straight away with re-using the frame as sent.
// */
//static struct virtio_rpmb_frame *
//vrpmb_handle_get_write_counter(VuDev *dev, struct virtio_rpmb_frame *frame)
//{
//    VuRpmb *r = container_of(dev, VuRpmb, dev.parent);
//    struct virtio_rpmb_frame *resp = g_new0(struct virtio_rpmb_frame, 1);
//
//    /*
//     * Run the checks from:
//     * 5.12.6.1.2 Device Requirements: Device Operation: Get Write Counter
//     */
//
//    resp->req_resp = htobe16(VIRTIO_RPMB_RESP_GET_COUNTER);
//    if (!r->key) {
//        g_debug("no key programmed");
//        resp->result = htobe16(VIRTIO_RPMB_RES_NO_AUTH_KEY);
//        return resp;
//    } else if (be16toh(frame->block_count) > 1) { /* allow 0 (NONCONF) */
//        g_debug("invalid block count (%d)", be16toh(frame->block_count));
//        resp->result = htobe16(VIRTIO_RPMB_RES_GENERAL_FAILURE);
//    } else {
//        resp->write_counter = htobe32(r->write_count);
//    }
//    /* copy nonce */
//    memcpy(&resp->nonce, &frame->nonce, sizeof(frame->nonce));
//
//    /* calculate MAC */
//    vrpmb_update_mac_in_frame(r, resp);
//
//    return resp;
//}
//
// /*
// * vrpmb_handle_write:
// *
// * We will report the success/fail on receipt of
// * VIRTIO_RPMB_REQ_RESULT_READ. Returns the number of extra frames
// * processed in the request.
// */
//static int vrpmb_handle_write(VuDev *dev, struct virtio_rpmb_frame *frame)
//{
//    VuRpmb *r = container_of(dev, VuRpmb, dev.parent);
//    int extra_frames = 0;
//    uint16_t block_count = be16toh(frame->block_count);
//    uint32_t write_counter = be32toh(frame->write_counter);
//    size_t offset;
//
//    r->last_reqresp = VIRTIO_RPMB_RESP_DATA_WRITE;
//    r->last_address = be16toh(frame->address);
//    offset =  r->last_address * RPMB_BLOCK_SIZE;
//
//    /*
//     * Run the checks from:
//     * 5.12.6.1.3 Device Requirements: Device Operation: Data Write
//     */
//    if (!r->key) {
//        g_warning("no key programmed");
//        r->last_result = VIRTIO_RPMB_RES_NO_AUTH_KEY;
//    } else if (block_count == 0 ||
//               block_count > r->virtio_config.max_wr_cnt) {
//        r->last_result = VIRTIO_RPMB_RES_GENERAL_FAILURE;
//    } else if (false /* what does an expired write counter mean? */) {
//        r->last_result = VIRTIO_RPMB_RES_WRITE_COUNTER_EXPIRED;
//    } else if (offset > (r->virtio_config.capacity * (128 * KiB))) {
//        r->last_result = VIRTIO_RPMB_RES_ADDR_FAILURE;
//    } else if (!vrpmb_verify_mac_in_frame(r, frame)) {
//        r->last_result = VIRTIO_RPMB_RES_AUTH_FAILURE;
//    } else if (write_counter != r->write_count) {
//        r->last_result = VIRTIO_RPMB_RES_COUNT_FAILURE;
//    } else {
//        int i;
//        /* At this point we have a valid authenticated write request
//         * so the counter can incremented and we can attempt to
//         * update the backing device.
//         */
//        r->write_count++;
//        for (i = 0; i < block_count; i++) {
//            void *blk = r->flash_map + offset;
//            g_debug("%s: writing block %d", __func__, i);
//            if (mprotect(blk, RPMB_BLOCK_SIZE, PROT_WRITE) != 0) {
//                r->last_result =  VIRTIO_RPMB_RES_WRITE_FAILURE;
//                break;
//            }
//            memcpy(blk, frame[i].data, RPMB_BLOCK_SIZE);
//            if (msync(blk, RPMB_BLOCK_SIZE, MS_SYNC) != 0) {
//                g_warning("%s: failed to sync update", __func__);
//                r->last_result = VIRTIO_RPMB_RES_WRITE_FAILURE;
//                break;
//            }
//            if (mprotect(blk, RPMB_BLOCK_SIZE, PROT_READ) != 0) {
//                g_warning("%s: failed to re-apply read protection", __func__);
//                r->last_result = VIRTIO_RPMB_RES_GENERAL_FAILURE;
//                break;
//            }
//            offset += RPMB_BLOCK_SIZE;
//        }
//        r->last_result = VIRTIO_RPMB_RES_OK;
//        extra_frames = i - 1;
//    }
//
//    g_info("%s: %s (%x, %d extra frames processed), write_count=%d", __func__,
//           r->last_result == VIRTIO_RPMB_RES_OK ? "successful":"failed",
//           r->last_result, extra_frames, r->write_count);
//
//    return extra_frames;
//}
//
// /*
// * vrpmb_handle_read:
// *
// * Unlike the write operation we return a frame with the result of the
// * read here. While the config specifies a maximum read count the spec
// * is limited to a single read at a time.
// */
//static struct virtio_rpmb_frame *
//vrpmb_handle_read(VuDev *dev, struct virtio_rpmb_frame *frame)
//{
//    VuRpmb *r = container_of(dev, VuRpmb, dev.parent);
//    size_t offset = be16toh(frame->address) * RPMB_BLOCK_SIZE;
//    uint16_t block_count = be16toh(frame->block_count);
//    struct virtio_rpmb_frame *resp = g_new0(struct virtio_rpmb_frame, 1);
//
//    resp->req_resp = htobe16(VIRTIO_RPMB_RESP_DATA_READ);
//    resp->address = frame->address;
//    resp->block_count = htobe16(1);
//
//    /*
//     * Run the checks from:
//     * 5.12.6.1.4 Device Requirements: Device Operation: Data Read
//     */
//    if (!r->key) {
//        g_warning("no key programmed");
//        resp->result = htobe16(VIRTIO_RPMB_RES_NO_AUTH_KEY);
//    } else if (block_count != 1) {
//        /*
//         * Despite the config the spec only allows for reading one
//         * block at a time: "If block count has not been set to 1 then
//         * VIRTIO_RPMB_RES_GENERAL_FAILURE SHOULD be responded as
//         * result."
//         */
//        resp->result = htobe16(VIRTIO_RPMB_RES_GENERAL_FAILURE);
//    } else if (offset > (r->virtio_config.capacity * (128 * KiB))) {
//        resp->result = htobe16(VIRTIO_RPMB_RES_ADDR_FAILURE);
//    } else {
//        void *blk = r->flash_map + offset;
//        g_debug("%s: reading block from %p (%zu)", __func__, blk, offset);
//        memcpy(resp->data, blk, RPMB_BLOCK_SIZE);
//        resp->result = htobe16(VIRTIO_RPMB_RES_OK);
//    }
//
//    /* Final housekeeping, copy nonce and calculate MAC */
//    memcpy(&resp->nonce, &frame->nonce, sizeof(frame->nonce));
//    vrpmb_update_mac_in_frame(r, resp);
//
//    return resp;
//}
//
// /*
// * Return the result of the last message. This is only valid if the
// * previous message was VIRTIO_RPMB_REQ_PROGRAM_KEY or
// * VIRTIO_RPMB_REQ_DATA_WRITE.
// *
// * The frame should be freed once sent.
// */
//static struct virtio_rpmb_frame * vrpmb_handle_result_read(VuDev *dev)
//{
//    VuRpmb *r = container_of(dev, VuRpmb, dev.parent);
//    struct virtio_rpmb_frame *resp = g_new0(struct virtio_rpmb_frame, 1);
//
//    g_info("%s: for request:%x result:%x", __func__,
//           r->last_reqresp, r->last_result);
//
//    if (r->last_reqresp == VIRTIO_RPMB_RESP_PROGRAM_KEY) {
//        resp->result = htobe16(r->last_result);
//        resp->req_resp = htobe16(r->last_reqresp);
//    } else if (r->last_reqresp == VIRTIO_RPMB_RESP_DATA_WRITE) {
//        resp->result = htobe16(r->last_result);
//        resp->req_resp = htobe16(r->last_reqresp);
//        resp->write_counter = htobe32(r->write_count);
//        resp->address = htobe16(r->last_address);
//    } else {
//        resp->result = htobe16(VIRTIO_RPMB_RES_GENERAL_FAILURE);
//    }
//
//    /* calculate HMAC */
//    if (!r->key) {
//        resp->result = htobe16(VIRTIO_RPMB_RES_GENERAL_FAILURE);
//    } else {
//        vrpmb_update_mac_in_frame(r, resp);
//    }
//
//    g_info("%s: result = %x req_resp = %x", __func__,
//           be16toh(resp->result),
//           be16toh(resp->req_resp));
//    return resp;
//}
//
//static void fmt_bytes(GString *s, uint8_t *bytes, int len)
//{
//    int i;
//    for (i = 0; i < len; i++) {
//        if (i % 16 == 0) {
//            g_string_append_c(s, '\n');
//        }
//        g_string_append_printf(s, "%x ", bytes[i]);
//    }
//}
//
//static void vrpmb_dump_frame(struct virtio_rpmb_frame *frame)
//{
//    g_autoptr(GString) s = g_string_new("frame: ");
//
//    g_string_append_printf(s, " %p\n", frame);
//    g_string_append_printf(s, "key_mac:");
//    fmt_bytes(s, (uint8_t *) &frame->key_mac[0], 32);
//    g_string_append_printf(s, "\ndata:");
//    fmt_bytes(s, (uint8_t *) &frame->data, 256);
//    g_string_append_printf(s, "\nnonce:");
//    fmt_bytes(s, (uint8_t *) &frame->nonce, 16);
//    g_string_append_printf(s, "\nwrite_counter: %d\n",
//                           be32toh(frame->write_counter));
//    g_string_append_printf(s, "address: %#04x\n", be16toh(frame->address));
//    g_string_append_printf(s, "block_count: %d\n",
// be16toh(frame->block_count));    g_string_append_printf(s, "result: %d\n",
// be16toh(frame->result));    g_string_append_printf(s, "req_resp: %d\n",
// be16toh(frame->req_resp));
//
//    g_debug("%s: %s\n", __func__, s->str);
//}
//
