// Copyright 2026 The libkrun Authors.
// SPDX-License-Identifier: Apache-2.0

//! Interrupt line allocation shared by all device managers of a VM.

use std::fmt;
use std::sync::{Arc, Mutex};

/// No more IRQs are available.
#[derive(Debug, PartialEq, Eq)]
pub struct IrqsExhausted;

impl fmt::Display for IrqsExhausted {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "no more IRQs are available")
    }
}

#[derive(Debug)]
struct IrqRange {
    /// Next IRQ to hand out, `None` once the range is exhausted.
    next: Option<u32>,
    /// Last IRQ (inclusive) that may be handed out.
    last: u32,
}

/// Hands out interrupt lines from a fixed range.
///
/// Every device manager that needs an IRQ (MMIO, PCI INTx) must draw it from
/// the same allocator, otherwise two devices end up sharing a line. Clones
/// share the same state.
#[derive(Clone, Debug)]
pub struct IrqAllocator {
    range: Arc<Mutex<IrqRange>>,
}

impl IrqAllocator {
    /// Create an allocator handing out the IRQs `first..=last`.
    pub fn new(first: u32, last: u32) -> Self {
        Self {
            range: Arc::new(Mutex::new(IrqRange {
                next: (first <= last).then_some(first),
                last,
            })),
        }
    }

    /// Allocate the next free IRQ.
    pub fn alloc(&self) -> Result<u32, IrqsExhausted> {
        let mut range = self.range.lock().expect("Poisoned IRQ allocator lock");
        let irq = range.next.ok_or(IrqsExhausted)?;
        range.next = (irq < range.last).then(|| irq + 1);
        Ok(irq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_sequential() {
        let irqs = IrqAllocator::new(5, 7);
        assert_eq!(irqs.alloc(), Ok(5));
        assert_eq!(irqs.alloc(), Ok(6));
        assert_eq!(irqs.alloc(), Ok(7));
    }

    #[test]
    fn test_alloc_exhausted() {
        let irqs = IrqAllocator::new(5, 6);
        irqs.alloc().unwrap();
        irqs.alloc().unwrap();
        assert_eq!(irqs.alloc(), Err(IrqsExhausted));
        // Stays exhausted.
        assert_eq!(irqs.alloc(), Err(IrqsExhausted));
    }

    #[test]
    fn test_alloc_single_irq_range() {
        let irqs = IrqAllocator::new(9, 9);
        assert_eq!(irqs.alloc(), Ok(9));
        assert_eq!(irqs.alloc(), Err(IrqsExhausted));
    }

    #[test]
    fn test_alloc_empty_range() {
        let irqs = IrqAllocator::new(8, 7);
        assert_eq!(irqs.alloc(), Err(IrqsExhausted));
    }

    #[test]
    fn test_alloc_does_not_wrap_at_u32_max() {
        let irqs = IrqAllocator::new(u32::MAX - 1, u32::MAX);
        assert_eq!(irqs.alloc(), Ok(u32::MAX - 1));
        assert_eq!(irqs.alloc(), Ok(u32::MAX));
        assert_eq!(irqs.alloc(), Err(IrqsExhausted));
    }

    #[test]
    fn test_clones_share_state() {
        let mmio = IrqAllocator::new(5, 23);
        let pci = mmio.clone();
        assert_eq!(mmio.alloc(), Ok(5));
        assert_eq!(pci.alloc(), Ok(6));
        assert_eq!(mmio.alloc(), Ok(7));
        assert_eq!(pci.alloc(), Ok(8));
    }

    #[test]
    fn test_error_message() {
        assert_eq!(format!("{IrqsExhausted}"), "no more IRQs are available");
    }
}
