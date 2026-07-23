use std::fmt;

#[derive(Clone, Copy, Debug, ffier::FfiError)]
#[non_exhaustive]
pub enum Error {
    // Configuration (100-199)
    #[ffier(code = 100)]
    InvalidParam(),
    #[ffier(code = 101)]
    DuplicateDevice(),
    #[ffier(code = 102)]
    DeviceLimitExceeded(),
    #[ffier(code = 103)]
    MissingConfig(),
    #[ffier(code = 104)]
    ConflictingConfig(),
    #[ffier(code = 105)]
    OutOfRange(),

    // Resources (200-299)
    #[ffier(code = 200)]
    FileNotFound(),
    #[ffier(code = 201)]
    PermissionDenied(),
    #[ffier(code = 202)]
    ResourceAlloc(),
    #[ffier(code = 203)]
    BadFd(),

    // Devices (300-399)
    #[ffier(code = 300)]
    BackendUnavailable(),
    #[ffier(code = 301, message = "feature not enabled in this build")]
    FeatureDisabled(),
    #[ffier(code = 302)]
    DiskFormatError(),

    // Runtime (400-499)
    #[ffier(code = 400)]
    AlreadyStarted(),
    #[ffier(code = 401)]
    ValidationFailed(),
    #[ffier(code = 402)]
    HypervisorError(),
    #[ffier(code = 403)]
    BootError(),

    // Internal (900-999)
    #[ffier(code = 900)]
    Internal(),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

#[derive(Debug)]
pub struct DetailedError {
    pub code: Error,
    pub context: Option<String>,
}

impl DetailedError {
    pub fn new(code: Error, context: impl Into<String>) -> Self {
        Self {
            code,
            context: Some(context.into()),
        }
    }
}

impl fmt::Display for DetailedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.code)?;
        if let Some(ctx) = &self.context {
            write!(f, ": {ctx}")?;
        }
        Ok(())
    }
}

impl std::error::Error for DetailedError {}

impl From<Error> for DetailedError {
    fn from(code: Error) -> Self {
        Self {
            code,
            context: None,
        }
    }
}
