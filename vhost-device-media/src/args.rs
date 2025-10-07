// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
//! An arguments type for the binary interface of this library.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct MediaArgs {
    /// Location of vhost-user Unix domain socket.
    #[clap(short, long, value_name = "SOCKET")]
    pub socket_path: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Proxy an existing V4L2 device.
    Proxy {
        #[clap(value_name = "DEVICE")]
        device_path: PathBuf,
    },
}
