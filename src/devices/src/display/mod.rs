// Copyright 2026, Red Hat Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Common display utilities for device implementations.
//!
//! This module provides display-related functionality that can be shared
//! across different device types (virtio-gpu, vhost-user-gpu, etc.).

pub mod edid;
pub mod types;

#[cfg(any(feature = "gpu", feature = "vhost-user"))]
pub mod display_backend;

pub use edid::EdidInfo;
pub use types::{DisplayInfo, DisplayInfoEdid, EdidParams, MAX_DISPLAYS, PhysicalSize};

#[cfg(any(feature = "gpu", feature = "vhost-user"))]
pub use display_backend::NoopDisplayBackend;
