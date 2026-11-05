use macros::host;

pub struct TestBuildCapabilities;

#[host]
mod host {
    use super::*;
    use crate::{Test, TestSetup};

    fn required_flags() -> krun::BuildCapabilityFlags {
        krun::BuildCapabilityFlags::BLK | krun::BuildCapabilityFlags::NET
    }

    #[cfg(feature = "dynamic-linking")]
    fn require_build_capability_symbols() -> anyhow::Result<()> {
        crate::common::load_libkrun();
        krun::require(None, &[krun::Symbol::KrunBuildCapabilityFlags])
            .map_err(|err| anyhow::anyhow!("failed to load build capability symbol: {err}"))
    }

    impl Test for TestBuildCapabilities {
        fn start_vm(self: Box<Self>, _test_setup: TestSetup) -> anyhow::Result<()> {
            #[cfg(feature = "dynamic-linking")]
            require_build_capability_symbols()?;

            let flags = krun::build_capability_flags();
            let required_flags = required_flags();
            if !flags.contains(required_flags) {
                anyhow::bail!(
                    "expected build capabilities to include {required_flags:?}, got {flags:?}"
                );
            }

            println!("OK");
            Ok(())
        }
    }
}
