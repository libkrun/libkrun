pub mod error;
pub mod logging;

pub use error::{DetailedError, Error};
pub use logging::{LogLevel, LogStyle, LogTarget, init_log};

ffier::library_definition!("krun", library_tag = 1,
    primitives_prefix = "krun",
    crate::api::error::Error = 1,
    trait ffier_builtins::PushStr = 12,
    trait ffier_builtins::Error = 13,
    Error for crate::api::error::Error,
    enum crate::api::logging::LogLevel,
    enum crate::api::logging::LogStyle,
    enum crate::api::logging::LogTarget,
    fn crate::api::logging::init_log,
);
