use super::export_bitflags;

export_bitflags! {
    bitflags::bitflags! {
        /// Build-time capabilities enabled in this libkrun binary.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct BuildCapabilityFlags: u32 {
            const BLK = 0x0001;
            const NET = 0x0002;
            const GPU = 0x0004;
            const INPUT = 0x0008;
            const VHOST_USER = 0x0010;
            const VIRGL_RESOURCE_MAP2 = 0x0020;
            const AWS_NITRO = 0x0040;
            const TEE = 0x0080;
            const AMD_SEV = 0x0100;
            const TDX = 0x0200;
            const TIMESYNC = 0x0400;
        }
    }
}

/// Return the build-time capabilities enabled in this libkrun binary.
#[cfg_attr(feature = "ffi", ffier::export)]
pub fn build_capability_flags() -> BuildCapabilityFlags {
    let flags = BuildCapabilityFlags::empty();

    #[cfg(feature = "blk")]
    let flags = flags | BuildCapabilityFlags::BLK;
    #[cfg(feature = "net")]
    let flags = flags | BuildCapabilityFlags::NET;
    #[cfg(feature = "gpu")]
    let flags = flags | BuildCapabilityFlags::GPU;
    #[cfg(feature = "input")]
    let flags = flags | BuildCapabilityFlags::INPUT;
    #[cfg(all(feature = "vhost-user", target_os = "linux"))]
    let flags = flags | BuildCapabilityFlags::VHOST_USER;
    #[cfg(feature = "virgl_resource_map2")]
    let flags = flags | BuildCapabilityFlags::VIRGL_RESOURCE_MAP2;
    #[cfg(feature = "aws-nitro")]
    let flags = flags | BuildCapabilityFlags::AWS_NITRO;
    #[cfg(feature = "tee")]
    let flags = flags | BuildCapabilityFlags::TEE;
    #[cfg(feature = "amd-sev")]
    let flags = flags | BuildCapabilityFlags::AMD_SEV;
    #[cfg(feature = "tdx")]
    let flags = flags | BuildCapabilityFlags::TDX;
    #[cfg(feature = "timesync")]
    let flags = flags | BuildCapabilityFlags::TIMESYNC;

    flags
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected_build_capability_flags() -> BuildCapabilityFlags {
        let flags = BuildCapabilityFlags::empty();

        #[cfg(feature = "blk")]
        let flags = flags | BuildCapabilityFlags::BLK;
        #[cfg(feature = "net")]
        let flags = flags | BuildCapabilityFlags::NET;
        #[cfg(feature = "gpu")]
        let flags = flags | BuildCapabilityFlags::GPU;
        #[cfg(feature = "input")]
        let flags = flags | BuildCapabilityFlags::INPUT;
        #[cfg(all(feature = "vhost-user", target_os = "linux"))]
        let flags = flags | BuildCapabilityFlags::VHOST_USER;
        #[cfg(feature = "virgl_resource_map2")]
        let flags = flags | BuildCapabilityFlags::VIRGL_RESOURCE_MAP2;
        #[cfg(feature = "aws-nitro")]
        let flags = flags | BuildCapabilityFlags::AWS_NITRO;
        #[cfg(feature = "tee")]
        let flags = flags | BuildCapabilityFlags::TEE;
        #[cfg(feature = "amd-sev")]
        let flags = flags | BuildCapabilityFlags::AMD_SEV;
        #[cfg(feature = "tdx")]
        let flags = flags | BuildCapabilityFlags::TDX;
        #[cfg(feature = "timesync")]
        let flags = flags | BuildCapabilityFlags::TIMESYNC;

        flags
    }

    #[test]
    fn reports_enabled_cargo_features() {
        assert_eq!(build_capability_flags(), expected_build_capability_flags());
    }
}
