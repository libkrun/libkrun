// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows Hypervisor Platform (WHP) VMM backend.
//!
//! This module is the Windows analogue of `linux/` (KVM) and `macos/` (HVF): it
//! provides the `Vm`/`Vcpu` integration layer that the rest of the VMM drives,
//! backed by the low-level `krun-whp` wrappers in `src/whp`.
//!
//! Status: compile-target scaffold. The channel/threading plumbing mirrors the
//! other backends; the WHP-specific register configuration and exit handling are
//! wired against the `whp` crate API but have **not** been verified against a real
//! Windows host with the Windows Hypervisor Platform enabled. Items that need
//! such a host to validate are marked with `TODO(whp-host)`.

pub mod lazy_mem;
pub(crate) mod snapshot_memory;
pub mod vstate;
