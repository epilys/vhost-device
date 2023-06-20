// VIRTIO RPMB vhost-user backend
//
// Copyright 2023 Linaro Ltd. All Rights Reserved.
// Emmanouil Pitsidianakis <manos.pitsidianakis@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::convert::TryFrom;

use clap::Parser;
use vhost_user_rpmb::*;

fn main() -> Result<()> {
    env_logger::init();
    let config = VuRpmbConfig::try_from(RpmbArgs::parse()).unwrap();

    loop {
        start_backend(config.clone()).unwrap();
    }
}
