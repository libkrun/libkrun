pub static INIT_BINARY: &[u8] = include_bytes!(env!("KRUN_INIT_BINARY_PATH"));

pub mod config;
pub(crate) mod init_schema;
pub(crate) mod oci_schema;
pub use config::{ApplyError, Builder, Config, ConfigError, INIT_PATH};
pub use init_schema::Mount;

#[cfg(feature = "ffi")]
ffier::library_definition!("krun_init",
    library_tag = 2,
    primitives_prefix = "krun",
    trait ffier::builtins::PushStr = 1,
    trait ffier::builtins::Error = 2,
    crate::config::ConfigError = 3,
    crate::config::Config = 4,
    crate::config::Builder = 5,
    crate::config::ApplyError = 6,
    Error for crate::config::ConfigError,
    Error for crate::config::ApplyError,
);

#[cfg(feature = "ffi")]
ffier::generate_bridge!(
    local = __ffier_krun_init_metadata,
    schema_output = "../../target/ffier-krun_init.json"
);
