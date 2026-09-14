#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::NetWorker;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::NetWorker;
