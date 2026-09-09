#[cfg(target_os = "linux")]
use std::mem::transmute;
#[cfg(target_os = "linux")]
use std::os::raw::{c_int, c_void};
#[cfg(all(test, target_os = "linux"))]
use std::ptr::null_mut;
#[cfg(target_os = "linux")]
use std::sync::LazyLock;

#[cfg(target_os = "linux")]
use rutabaga_gfx::{RutabagaError, RutabagaResult};

#[cfg(target_os = "linux")]
type ResourceMapFixed = unsafe extern "C" fn(u32, *mut c_void) -> c_int;

#[cfg(target_os = "linux")]
static RESOURCE_MAP_FIXED: LazyLock<Option<ResourceMapFixed>> =
    LazyLock::new(resolve_resource_map_fixed);

#[cfg(target_os = "linux")]
fn resolve_resource_map_fixed() -> Option<ResourceMapFixed> {
    resolve_resource_map_fixed_with(|name| unsafe { libc::dlsym(libc::RTLD_DEFAULT, name) })
}

#[cfg(target_os = "linux")]
fn resolve_resource_map_fixed_with(
    resolve: impl FnOnce(*const libc::c_char) -> *mut c_void,
) -> Option<ResourceMapFixed> {
    let symbol = resolve(c"virgl_renderer_resource_map_fixed".as_ptr());
    if symbol.is_null() {
        None
    } else {
        Some(unsafe { transmute::<*mut c_void, ResourceMapFixed>(symbol) })
    }
}

pub fn supports_virgl_renderer_resource_map_fixed() -> bool {
    #[cfg(target_os = "linux")]
    return RESOURCE_MAP_FIXED.is_some();

    #[cfg(not(target_os = "linux"))]
    false
}

#[cfg(target_os = "linux")]
pub(super) fn resource_map_fixed(resource_id: u32, addr: u64) -> RutabagaResult<()> {
    call_resource_map_fixed(*RESOURCE_MAP_FIXED, resource_id, addr)
}

#[cfg(target_os = "linux")]
fn call_resource_map_fixed(
    function: Option<ResourceMapFixed>,
    resource_id: u32,
    addr: u64,
) -> RutabagaResult<()> {
    let function = function.ok_or(RutabagaError::Unsupported)?;
    let ret = unsafe { function(resource_id, addr as *mut c_void) };
    if ret != 0 {
        return Err(RutabagaError::MappingFailed(ret));
    }

    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    unsafe extern "C" fn map_success(_resource_id: u32, _addr: *mut c_void) -> c_int {
        0
    }

    unsafe extern "C" fn map_failure(_resource_id: u32, _addr: *mut c_void) -> c_int {
        -libc::EINVAL
    }

    #[test]
    fn resource_map_fixed_symbol_is_detected() {
        let function = resolve_resource_map_fixed_with(|_| map_success as *const () as *mut c_void);
        assert!(function.is_some());
    }

    #[test]
    fn resource_map_fixed_symbol_can_be_missing() {
        let function = resolve_resource_map_fixed_with(|_| null_mut());
        assert!(function.is_none());
    }

    #[test]
    fn resource_map_fixed_succeeds() {
        assert!(call_resource_map_fixed(Some(map_success), 1, 0x1000).is_ok());
    }

    #[test]
    fn resource_map_fixed_propagates_error() {
        match call_resource_map_fixed(Some(map_failure), 1, 0x1000) {
            Err(RutabagaError::MappingFailed(code)) => assert_eq!(code, -libc::EINVAL),
            result => panic!("unexpected result: {result:?}"),
        }
    }
}
