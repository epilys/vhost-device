// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::process::exit;

use clap::Parser;
use vhost_device_media::{
    args::{Command, MediaArgs},
    start_backend, DeviceType, MediaConfiguration,
};

fn main() {
    env_logger::init();

    let MediaArgs {
        socket_path,
        command,
    } = MediaArgs::parse();
    let device_type = match command {
        Command::Proxy { device_path } => DeviceType::Proxy { device_path },
    };
    let config = MediaConfiguration {
        socket_path,
        device_type,
    };
    if let Err(err) = start_backend(config) {
        log::error!("{err}");
        exit(1);
    }
}
