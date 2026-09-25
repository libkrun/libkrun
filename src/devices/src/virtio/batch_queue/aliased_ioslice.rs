//! Utilities Vectored I/O (iovec) type, where the underlying memory can be aliased into many slices.
use libc::{c_void, iovec};
use std::marker::PhantomData;
use std::ptr;
use vm_memory::VolatileSlice;

/// Common interface for iovec wrappers.
pub trait AnyIoSlice: Copy {
    /// Returns a copy of the underlying `libc::iovec`.
    fn to_iovec(&self) -> iovec;

    /// Returns a mutable reference to the underlying `libc::iovec`.
    /// # Safety
    /// The caller must not invalidate the iovec invariants: after mutation,
    /// `iov_base` and `iov_len` must still describe a valid memory region.
    unsafe fn as_iovec_mut(&mut self) -> &mut iovec;

    fn len(&self) -> usize {
        self.to_iovec().iov_len
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Set the length field of the underlying iovec.
    ///
    /// # Safety
    /// The caller must ensure that the underlying allocation is at least
    /// `new_len` bytes from the current base pointer.
    unsafe fn set_len(&mut self, new_len: usize) {
        unsafe { self.as_iovec_mut() }.iov_len = new_len;
    }

    /// Shorten the length field. Panics if `new_len > self.len()`.
    fn shorten(&mut self, new_len: usize) {
        assert!(
            new_len <= self.len(),
            "shorten: new_len {new_len} > current len {}",
            self.len()
        );
        // Safety: shrinking is always valid — the allocation is at least as large as the original length.
        unsafe { self.set_len(new_len) };
    }

    /// Skip `n` bytes from the front: advances the base pointer and shrinks
    /// the length accordingly.
    ///
    /// # Panics
    /// Panics if `n > self.len()`.
    fn advance(&mut self, n: usize) {
        // Safety: we own `&mut self`, so mutating the iovec fields is valid.
        let raw = unsafe { self.as_iovec_mut() };
        raw.iov_len = raw
            .iov_len
            .checked_sub(n)
            .expect("advance past end of iovec");
        raw.iov_base = (raw.iov_base as *mut u8).wrapping_add(n) as *mut c_void;
    }

    /// Copies data from a standard Rust slice into this buffer.
    ///
    /// Uses `ptr::copy` (memmove) because `src` is a shared `&[u8]` that
    /// could alias the same guest memory region.
    fn write(&mut self, src: &[u8]) -> usize {
        let iov = self.to_iovec();
        let count = std::cmp::min(iov.iov_len, src.len());
        unsafe {
            ptr::copy(src.as_ptr(), iov.iov_base as *mut u8, count);
        }
        count
    }

    // -- Slice operations (need mutable slice access / return sub-slices) ----

    /// Returns a pointer to the iovec array for FFI (writev/readv/sendmmsg).
    fn as_iovec_ptr(iovecs: &[Self]) -> *const iovec
    where
        Self: Sized,
    {
        iovecs.as_ptr() as *const iovec
    }

    /// Consumes `n` bytes from the front of the iovec slice by advancing base
    /// pointers. Returns the remaining (non-consumed) sub-slice.
    fn advance_slices(iovecs: &mut [Self], mut n: usize) -> &mut [Self]
    where
        Self: Sized,
    {
        let mut skip = 0;
        for iov in iovecs.iter_mut() {
            let len = iov.len();
            if n < len {
                iov.advance(n);
                break;
            } else {
                n -= len;
                skip += 1;
            }
        }
        &mut iovecs[skip..]
    }

    /// Truncates the iovec slice to at most `n` total bytes.
    /// Returns the prefix sub-slice that fits within the byte limit.
    fn truncate_slices(iovecs: &mut [Self], mut n: usize) -> &mut [Self]
    where
        Self: Sized,
    {
        let mut keep = 0;
        for iov in iovecs.iter_mut() {
            let len = iov.len();
            if n <= len {
                iov.shorten(n);
                keep += 1;
                break;
            } else {
                n -= len;
                keep += 1;
            }
        }
        &mut iovecs[..keep]
    }

    // -- Iterator operations -----------------------------------------------

    /// Total byte length across all iovecs.
    fn total_len(iovecs: impl Iterator<Item = Self>) -> usize
    where
        Self: Sized,
    {
        iovecs.map(|s| s.len()).sum()
    }

    /// Scatter-write `data` across iovecs, filling each buffer in order.
    /// Returns the total number of bytes written.
    fn scatter_write(iovecs: impl Iterator<Item = Self>, data: &[u8]) -> usize
    where
        Self: Sized,
    {
        let mut written = 0;
        for mut iov in iovecs {
            let remaining = data.len() - written;
            if remaining == 0 {
                break;
            }
            let take = remaining.min(iov.len());
            iov.write(&data[written..written + take]);
            written += take;
        }
        written
    }

    /// Returns an iterator that skips the first `skip` bytes from an iovec
    /// iterator. Partially-consumed iovecs are yielded with adjusted
    /// base/length; fully-consumed ones are yielded empty (filtered by
    /// `IovecAppender::push`).
    fn skip_bytes<I>(iter: I, skip: usize) -> impl Iterator<Item = Self>
    where
        I: Iterator<Item = Self>,
        Self: Sized,
    {
        let mut remaining = skip;
        iter.map(move |mut iov| {
            if remaining != 0 {
                let n = remaining.min(iov.len());
                iov.advance(n);
                remaining -= n;
            }
            iov
        })
    }

    /// Returns an iterator that writes `prefix` bytes into the front of
    /// iovecs, then yields each iovec advanced past the written portion.
    fn write_prefix<'p, I>(iter: I, prefix: &'p [u8]) -> impl Iterator<Item = Self> + 'p
    where
        I: Iterator<Item = Self> + 'p,
        Self: Sized + 'p,
    {
        let mut offset = 0usize;
        iter.map(move |mut iov| {
            if offset < prefix.len() {
                let written = iov.write(&prefix[offset..]);
                offset += written;
                iov.advance(written);
            }
            iov
        })
    }
}

/// A transparent wrapper around `libc::iovec` pointing to readable memory.
///
/// # Layout
/// `#[repr(transparent)]` over `libc::iovec`, binary-compatible with C
/// vectored I/O functions.
///
/// # Safety and Aliasing
/// Unlike `std::io::IoSlice`, this type acts like a raw pointer descriptor.
/// Multiple instances may point to overlapping memory regions,provided
/// the underlying memory remains valid for lifetime `'a`.
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct AliasedIoSlice<'a> {
    iov: iovec,
    _marker: PhantomData<&'a ()>,
}

impl AnyIoSlice for AliasedIoSlice<'_> {
    fn to_iovec(&self) -> iovec {
        self.iov
    }
    unsafe fn as_iovec_mut(&mut self) -> &mut iovec {
        &mut self.iov
    }
}

impl<'a> AliasedIoSlice<'a> {
    /// Creates a `VolatileIoSlice` from a raw pointer and length.
    ///
    /// # Safety
    /// The caller must ensure that it is safe to read `len` bytes starting
    /// at `ptr` for the duration of the lifetime `'a`.
    pub unsafe fn from_raw(ptr: *const u8, len: usize) -> Self {
        Self {
            iov: iovec {
                iov_base: ptr as *mut c_void,
                iov_len: len,
            },
            _marker: PhantomData,
        }
    }

    /// Create from a `VolatileSlice`.
    ///
    /// # Safety
    /// The `VolatileSlice` pointer is reinterpreted without provenance
    /// tracking. The caller must ensure the memory stays valid.
    pub unsafe fn from_slice(v: &VolatileSlice<'a>) -> Self {
        // SAFETY: Caller guarantees memory validity per function contract.
        unsafe { Self::from_raw(v.ptr_guard().as_ptr(), v.len()) }
    }

    /// Returns a const pointer to the underlying buffer.
    pub fn as_ptr(&self) -> *const u8 {
        self.iov.iov_base as *const u8
    }

    /// Copies data from this volatile buffer into a standard Rust slice.
    pub fn read(&self, dst: &mut [u8]) -> usize {
        let count = std::cmp::min(self.len(), dst.len());
        // SAFETY: `dst` is a unique `&mut [u8]`, so the borrow checker
        // guarantees it cannot overlap with the source memory being read
        // through our pointer.
        unsafe {
            ptr::copy_nonoverlapping(self.as_ptr(), dst.as_mut_ptr(), count);
        }
        count
    }
}

impl<'a> From<VolatileSlice<'a>> for AliasedIoSlice<'a> {
    fn from(v: VolatileSlice<'a>) -> Self {
        unsafe { Self::from_slice(&v) }
    }
}

/// A transparent wrapper around `libc::iovec` pointing to writable memory.
///
/// # Layout
/// `#[repr(transparent)]` over `libc::iovec`, binary-compatible with C
/// vectored I/O functions.
///
/// # Safety and Aliasing
/// Unlike `std::io::IoSliceMut`, this type acts like a raw pointer descriptor.
/// Multiple instances may safely point to overlapping memory regions,
/// provided the underlying memory remains valid for lifetime `'a`. This
/// type allows aliasing that would be UB with standard Rust mutable slices.
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct AliasedIoSliceMut<'a> {
    iov: iovec,
    _marker: PhantomData<&'a ()>,
}

impl AnyIoSlice for AliasedIoSliceMut<'_> {
    fn to_iovec(&self) -> iovec {
        self.iov
    }
    unsafe fn as_iovec_mut(&mut self) -> &mut iovec {
        &mut self.iov
    }
}

impl<'a> AliasedIoSliceMut<'a> {
    /// Creates a `IoVecMut` from a raw pointer and length.
    ///
    /// # Safety
    /// The caller must ensure `ptr` is valid for `len` bytes for the
    /// duration of the lifetime `'a`.
    pub unsafe fn from_raw(ptr: *mut u8, len: usize) -> Self {
        Self {
            iov: iovec {
                iov_base: ptr as *mut c_void,
                iov_len: len,
            },
            _marker: PhantomData,
        }
    }

    /// Create from a `VolatileSlice`.
    ///
    /// # Safety
    /// The `VolatileSlice` pointer is reinterpreted without provenance
    /// tracking. The caller must ensure the memory stays valid.
    pub unsafe fn from_slice(v: &VolatileSlice<'a>) -> Self {
        // SAFETY: Caller guarantees memory validity per function contract.
        unsafe { Self::from_raw(v.ptr_guard_mut().as_ptr(), v.len()) }
    }

    /// Create from a mutable slice.
    ///
    /// # Safety
    /// See [`from_raw`](Self::from_raw).
    pub unsafe fn from_slice_mut(buf: &'a mut [u8]) -> Self {
        // SAFETY: Caller guarantees memory validity per function contract.
        unsafe { Self::from_raw(buf.as_mut_ptr(), buf.len()) }
    }
}

impl<'a> From<VolatileSlice<'a>> for AliasedIoSliceMut<'a> {
    fn from(v: VolatileSlice<'a>) -> Self {
        unsafe { Self::from_slice(&v) }
    }
}

/// A `#[repr(transparent)]` iovec wrapper with no lifetime parameter.
///
/// Used for storage in containers where the pointer validity is more compex and managed
/// by the container rather than each slice directly.
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct RawAliasedIoSlice {
    iov: iovec,
}

impl AnyIoSlice for RawAliasedIoSlice {
    fn to_iovec(&self) -> iovec {
        self.iov
    }

    unsafe fn as_iovec_mut(&mut self) -> &mut iovec {
        &mut self.iov
    }
}

impl RawAliasedIoSlice {
    /// Create a zeroed (null-pointer, zero-length) iovec.
    pub fn zeroed() -> Self {
        Self {
            iov: iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            },
        }
    }

    /// Erase the lifetime from any iovec wrapper, storing just the raw iovec.
    ///
    /// # Safety
    /// The caller must ensure the pointed-to memory remains valid for as
    /// long as this `RawAliasedIoSlice` is used.
    pub unsafe fn from_any(v: impl AnyIoSlice) -> Self {
        Self { iov: v.to_iovec() }
    }

    /// Reinterpret as a readable `AliasedIoSlice` with the given lifetime.
    ///
    /// # Safety
    /// The caller must ensure the memory region is valid for reads
    /// for the duration of lifetime `'a`.
    pub unsafe fn as_ioslice<'a>(&self) -> AliasedIoSlice<'a> {
        AliasedIoSlice {
            iov: self.iov,
            _marker: PhantomData,
        }
    }

    /// Reinterpret as a writable `AliasedIoSliceMut` with the given lifetime.
    ///
    /// # Safety
    /// The caller must ensure the memory region is valid for writes
    /// for the duration of lifetime `'a`.
    pub unsafe fn as_ioslice_mut<'a>(&self) -> AliasedIoSliceMut<'a> {
        AliasedIoSliceMut {
            iov: self.iov,
            _marker: PhantomData,
        }
    }
}
