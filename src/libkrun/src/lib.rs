pub mod api;
pub use api::*;

ffier::generate_bridge!(
    local = __ffier_krun_metadata,
    schema_output = "../../target/ffier-krun.json"
);

#[doc(hidden)]
pub mod reexports {
    pub use devices::virtio::TsiFlags;
    #[cfg(feature = "net")]
    pub use devices::virtio::net::device::VirtioNetBackend;
    pub use devices::virtio::port_io;
}

#[cfg(feature = "net")]
pub const COMPAT_NET_FEATURES: u32 = (1 << 0)  // CSUM
    | (1 << 1)  // GUEST_CSUM
    | (1 << 7)  // GUEST_TSO4
    | (1 << 10) // GUEST_UFO
    | (1 << 11) // HOST_TSO4
    | (1 << 14); // HOST_UFO

#[allow(dead_code)]
mod builder;
