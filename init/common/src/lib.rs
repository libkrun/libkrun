// SPDX-License-Identifier: Apache-2.0
//
//! Types shared between the host side of libkrun (`libkrun_init`) and the
//! guest init binary (`krun-init`).
//!
//! The contract between the two is private to libkrun: both sides ship
//! together, so the wire format in [`control`] may change at any time.

pub mod control;

#[cfg(feature = "client")]
pub mod client;

#[cfg(all(feature = "server", target_os = "linux"))]
pub mod server;
