// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! gfxstream: Handles 3D virtio-gpu hypercalls using gfxstream.
//!
//! External code found at <https://android.googlesource.com/device/generic/vulkan-cereal/>.

#![cfg(feature = "gfxstream")]

use std::convert::TryInto;
use std::io::IoSliceMut;
use std::mem::size_of;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_uint;
use std::os::raw::c_void;
use std::panic::catch_unwind;
use std::process::abort;
use std::ptr::null;
use std::ptr::null_mut;
use std::sync::Arc;

use crate::generated::virgl_renderer_bindings::iovec;
use crate::generated::virgl_renderer_bindings::virgl_box;
use crate::generated::virgl_renderer_bindings::virgl_renderer_resource_create_args;
use crate::renderer_utils::*;
use crate::rutabaga_core::RutabagaComponent;
use crate::rutabaga_core::RutabagaContext;
use crate::rutabaga_core::RutabagaResource;
#[cfg(target_os = "macos")]
use crate::rutabaga_os::AsRawDescriptor;
use crate::rutabaga_os::FromRawDescriptor;
use crate::rutabaga_os::IntoRawDescriptor;
use crate::rutabaga_os::RawDescriptor;
use crate::rutabaga_os::SafeDescriptor;
use crate::rutabaga_utils::*;

// See `virtgpu-gfxstream-renderer.h` for definitions
const STREAM_RENDERER_PARAM_NULL: u64 = 0;
const STREAM_RENDERER_PARAM_USER_DATA: u64 = 1;
const STREAM_RENDERER_PARAM_RENDERER_FLAGS: u64 = 2;
const STREAM_RENDERER_PARAM_FENCE_CALLBACK: u64 = 3;
const STREAM_RENDERER_PARAM_WIN0_WIDTH: u64 = 4;
const STREAM_RENDERER_PARAM_WIN0_HEIGHT: u64 = 5;
const STREAM_RENDERER_PARAM_DEBUG_CALLBACK: u64 = 6;

const STREAM_RENDERER_MAX_PARAMS: usize = 6;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct stream_renderer_param {
    key: u64,
    value: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct stream_renderer_handle {
    pub os_handle: i64,
    pub handle_type: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct stream_renderer_vulkan_info {
    pub memory_index: u32,
    pub device_uuid: [u8; 16],
    pub driver_uuid: [u8; 16],
}

#[repr(C)]
pub struct stream_renderer_command {
    pub ctx_id: u32,
    pub cmd_size: u32,
    pub cmd: *const u8,
    pub num_in_fences: u32,
    pub in_fence_descriptors: *const u64,
}

#[allow(non_camel_case_types)]
pub type stream_renderer_create_blob = ResourceCreateBlob;

#[allow(non_camel_case_types)]
pub type stream_renderer_resource_create_args = virgl_renderer_resource_create_args;

#[allow(non_camel_case_types)]
pub type stream_renderer_box = virgl_box;

#[allow(non_camel_case_types)]
pub type stream_renderer_fence = RutabagaFence;

#[allow(non_camel_case_types)]
pub type stream_renderer_debug = RutabagaDebug;

unsafe extern "C" {
    // Entry point for the stream renderer.
    fn stream_renderer_init(
        stream_renderer_params: *mut stream_renderer_param,
        num_params: u64,
    ) -> c_int;

    // Shutdown entry point for the renderer.
    fn stream_renderer_teardown();

    // virtio-gpu-3d ioctl functions (begin)

    // In gfxstream, the resource create/transfer ioctls correspond to creating buffers for API
    // forwarding and the notification of new API calls forwarded by the guest, unless they
    // correspond to minigbm resource targets (PIPE_TEXTURE_2D), in which case they create globally
    // visible shared GL textures to support gralloc.
    fn stream_renderer_resource_create(
        args: *mut stream_renderer_resource_create_args,
        iov: *mut iovec,
        num_iovs: u32,
    ) -> c_int;

    fn stream_renderer_resource_unref(res_handle: u32);
    fn stream_renderer_context_destroy(handle: u32);
    fn stream_renderer_transfer_read_iov(
        handle: u32,
        ctx_id: u32,
        level: u32,
        stride: u32,
        layer_stride: u32,
        box_: *mut stream_renderer_box,
        offset: u64,
        iov: *mut iovec,
        iovec_cnt: c_int,
    ) -> c_int;
    fn stream_renderer_transfer_write_iov(
        handle: u32,
        ctx_id: u32,
        level: c_int,
        stride: u32,
        layer_stride: u32,
        box_: *mut stream_renderer_box,
        offset: u64,
        iovec: *mut iovec,
        iovec_cnt: c_uint,
    ) -> c_int;
    fn stream_renderer_submit_cmd(cmd: *const stream_renderer_command) -> c_int;
    fn stream_renderer_resource_attach_iov(
        res_handle: c_int,
        iov: *mut iovec,
        num_iovs: c_int,
    ) -> c_int;
    fn stream_renderer_resource_detach_iov(
        res_handle: c_int,
        iov: *mut *mut iovec,
        num_iovs: *mut c_int,
    );
    fn stream_renderer_create_fence(fence: *const stream_renderer_fence) -> c_int;
    fn stream_renderer_ctx_attach_resource(ctx_id: c_int, res_handle: c_int);
    fn stream_renderer_ctx_detach_resource(ctx_id: c_int, res_handle: c_int);
    fn stream_renderer_get_cap_set(set: u32, max_ver: *mut u32, max_size: *mut u32);
    fn stream_renderer_fill_caps(set: u32, version: u32, caps: *mut c_void);

    fn stream_renderer_flush(res_handle: u32);
    fn stream_renderer_create_blob(
        ctx_id: u32,
        res_handle: u32,
        create_blob: *const stream_renderer_create_blob,
        iovecs: *const iovec,
        num_iovs: u32,
        handle: *const stream_renderer_handle,
    ) -> c_int;

    fn stream_renderer_export_blob(res_handle: u32, handle: *mut stream_renderer_handle) -> c_int;
    fn stream_renderer_resource_map(
        res_handle: u32,
        map: *mut *mut c_void,
        out_size: *mut u64,
    ) -> c_int;
    fn stream_renderer_resource_unmap(res_handle: u32) -> c_int;
    fn stream_renderer_resource_map_info(res_handle: u32, map_info: *mut u32) -> c_int;
    fn stream_renderer_vulkan_info(
        res_handle: u32,
        vulkan_info: *mut stream_renderer_vulkan_info,
    ) -> c_int;
    fn stream_renderer_context_create(
        handle: u32,
        nlen: u32,
        name: *const c_char,
        context_init: u32,
    ) -> c_int;
}

/// The virtio-gpu backend state tracker which supports accelerated rendering.
pub struct Gfxstream {
    /// Cookie used by Gfxstream, should be held as long as the renderer is alive.
    _cookie: Box<RutabagaCookie>,
}

struct GfxstreamContext {
    ctx_id: u32,
    fence_handler: RutabagaFenceHandler,
}

impl RutabagaContext for GfxstreamContext {
    fn submit_cmd(&mut self, commands: &mut [u8], fence_ids: &[u64]) -> RutabagaResult<()> {
        if !fence_ids.is_empty() {
            return Err(RutabagaError::Unsupported);
        }

        if commands.len() % size_of::<u32>() != 0 {
            return Err(RutabagaError::InvalidCommandSize(commands.len()));
        }

        let ret = unsafe {
            let cmd = stream_renderer_command {
                ctx_id: self.ctx_id,
                cmd_size: commands.len().try_into()?,
                cmd: commands.as_mut_ptr(),
                num_in_fences: 0,
                in_fence_descriptors: null(),
            };

            stream_renderer_submit_cmd(&cmd as *const stream_renderer_command)
        };
        ret_to_res(ret)
    }

    fn attach(&mut self, resource: &mut RutabagaResource) {
        // The context id and resource id must be valid because the respective instances ensure
        // their lifetime.
        unsafe {
            stream_renderer_ctx_attach_resource(self.ctx_id as i32, resource.resource_id as i32);
        }
    }

    fn detach(&mut self, resource: &RutabagaResource) {
        // The context id and resource id must be valid because the respective instances ensure
        // their lifetime.
        unsafe {
            stream_renderer_ctx_detach_resource(self.ctx_id as i32, resource.resource_id as i32);
        }
    }

    fn component_type(&self) -> RutabagaComponentType {
        RutabagaComponentType::Gfxstream
    }

    fn context_create_fence(&mut self, fence: RutabagaFence) -> RutabagaResult<()> {
        if fence.ring_idx as u32 == 1 {
            self.fence_handler.call(fence);
            return Ok(());
        }

        // Safe because RutabagaFences and stream_renderer_fence are ABI identical
        let ret = unsafe { stream_renderer_create_fence(&fence as *const stream_renderer_fence) };

        ret_to_res(ret)
    }
}

impl Drop for GfxstreamContext {
    fn drop(&mut self) {
        // The context is safe to destroy because nothing else can be referencing it.
        unsafe {
            stream_renderer_context_destroy(self.ctx_id);
        }
    }
}

extern "C" fn write_context_fence(cookie: *mut c_void, fence: *const RutabagaFence) {
    catch_unwind(|| {
        assert!(!cookie.is_null());
        let cookie = unsafe { &*(cookie as *mut RutabagaCookie) };
        if let Some(handler) = &cookie.fence_handler {
            // We trust gfxstream not give a dangling pointer
            unsafe { handler.call(*fence) };
        }
    })
    .unwrap_or_else(|_| abort())
}

extern "C" fn gfxstream_debug_callback(cookie: *mut c_void, debug: *const stream_renderer_debug) {
    catch_unwind(|| {
        assert!(!cookie.is_null());
        let cookie = unsafe { &*(cookie as *mut RutabagaCookie) };
        if let Some(handler) = &cookie.debug_handler {
            // We trust gfxstream not give a dangling pointer
            unsafe { handler.call(*debug) };
        }
    })
    .unwrap_or_else(|_| abort())
}

impl Gfxstream {
    pub fn init(
        display_width: u32,
        display_height: u32,
        gfxstream_flags: GfxstreamFlags,
        fence_handler: RutabagaFenceHandler,
        debug_handler: Option<RutabagaDebugHandler>,
    ) -> RutabagaResult<Box<dyn RutabagaComponent>> {
        let use_debug = debug_handler.is_some();
        let mut cookie = Box::new(RutabagaCookie {
            render_server_fd: None,
            fence_handler: Some(fence_handler),
            debug_handler,
        });

        let mut stream_renderer_params: [stream_renderer_param; STREAM_RENDERER_MAX_PARAMS] = [
            stream_renderer_param {
                key: STREAM_RENDERER_PARAM_USER_DATA,
                // Safe as cookie outlives the stream renderer (stream_renderer_teardown called
                // at Gfxstream Drop)
                value: &mut *cookie as *mut RutabagaCookie as u64,
            },
            stream_renderer_param {
                key: STREAM_RENDERER_PARAM_RENDERER_FLAGS,
                value: gfxstream_flags.into(),
            },
            stream_renderer_param {
                key: STREAM_RENDERER_PARAM_FENCE_CALLBACK,
                value: write_context_fence as usize as u64,
            },
            stream_renderer_param {
                key: STREAM_RENDERER_PARAM_WIN0_WIDTH,
                value: display_width as u64,
            },
            stream_renderer_param {
                key: STREAM_RENDERER_PARAM_WIN0_HEIGHT,
                value: display_height as u64,
            },
            if use_debug {
                stream_renderer_param {
                    key: STREAM_RENDERER_PARAM_DEBUG_CALLBACK,
                    value: gfxstream_debug_callback as usize as u64,
                }
            } else {
                stream_renderer_param {
                    key: STREAM_RENDERER_PARAM_NULL,
                    value: 0,
                }
            },
        ];

        unsafe {
            ret_to_res(stream_renderer_init(
                stream_renderer_params.as_mut_ptr(),
                stream_renderer_params.len() as u64,
            ))?;
        }

        Ok(Box::new(Gfxstream { _cookie: cookie }))
    }

    fn map_info(&self, resource_id: u32) -> RutabagaResult<u32> {
        let mut map_info = 0;
        // Safe because `map_info` is a local stack variable owned by us.
        let ret = unsafe { stream_renderer_resource_map_info(resource_id, &mut map_info) };
        ret_to_res(ret)?;

        Ok(map_info | RUTABAGA_MAP_ACCESS_RW)
    }

    fn vulkan_info(&self, resource_id: u32) -> RutabagaResult<VulkanInfo> {
        let mut vulkan_info: stream_renderer_vulkan_info = Default::default();
        // Safe because `vulkan_info` is a local stack variable owned by us.
        let ret = unsafe { stream_renderer_vulkan_info(resource_id, &mut vulkan_info) };
        ret_to_res(ret)?;

        Ok(VulkanInfo {
            memory_idx: vulkan_info.memory_index,
            device_id: DeviceId {
                device_uuid: vulkan_info.device_uuid,
                driver_uuid: vulkan_info.driver_uuid,
            },
        })
    }

    fn export_blob(&self, resource_id: u32) -> RutabagaResult<Arc<RutabagaHandle>> {
        let mut stream_handle: stream_renderer_handle = Default::default();
        let ret = unsafe { stream_renderer_export_blob(resource_id, &mut stream_handle) };
        ret_to_res(ret)?;

        // Safe because the handle was just returned by a successful gfxstream call so it must be
        // valid and owned by us.
        let raw_descriptor = stream_handle.os_handle as RawDescriptor;
        let handle = unsafe { SafeDescriptor::from_raw_descriptor(raw_descriptor) };

        Ok(Arc::new(RutabagaHandle {
            os_handle: handle,
            handle_type: stream_handle.handle_type,
        }))
    }
}

impl Drop for Gfxstream {
    fn drop(&mut self) {
        // SAFETY: Safe because Gfxstream was succesfully initialized.
        unsafe {
            stream_renderer_teardown();
        }
    }
}

impl RutabagaComponent for Gfxstream {
    fn get_capset_info(&self, capset_id: u32) -> (u32, u32) {
        let mut version = 0;
        let mut size = 0;
        // Safe because gfxstream is initialized by now and properly size stack variables are
        // used for the pointers.
        unsafe {
            stream_renderer_get_cap_set(capset_id, &mut version, &mut size);
        }
        (version, size)
    }

    fn get_capset(&self, capset_id: u32, version: u32) -> Vec<u8> {
        let (_, max_size) = self.get_capset_info(capset_id);
        let mut buf = vec![0u8; max_size as usize];
        // Safe because gfxstream is initialized by now and the given buffer is sized properly
        // for the given cap id/version.
        unsafe {
            stream_renderer_fill_caps(capset_id, version, buf.as_mut_ptr() as *mut c_void);
        }

        buf
    }

    fn create_fence(&mut self, fence: RutabagaFence) -> RutabagaResult<()> {
        // Safe because RutabagaFences and stream_renderer_fence are ABI identical
        let ret = unsafe { stream_renderer_create_fence(&fence as *const stream_renderer_fence) };
        ret_to_res(ret)
    }

    fn create_3d(
        &self,
        resource_id: u32,
        resource_create_3d: ResourceCreate3D,
    ) -> RutabagaResult<RutabagaResource> {
        let mut args = virgl_renderer_resource_create_args {
            handle: resource_id,
            target: resource_create_3d.target,
            format: resource_create_3d.format,
            bind: resource_create_3d.bind,
            width: resource_create_3d.width,
            height: resource_create_3d.height,
            depth: resource_create_3d.depth,
            array_size: resource_create_3d.array_size,
            last_level: resource_create_3d.last_level,
            nr_samples: resource_create_3d.nr_samples,
            flags: resource_create_3d.flags,
        };

        // Safe because gfxstream is initialized by now, and the return value is checked before
        // returning a new resource. The backing buffers are not supplied with this call.
        let ret = unsafe { stream_renderer_resource_create(&mut args, null_mut(), 0) };
        ret_to_res(ret)?;

        Ok(RutabagaResource {
            resource_id,
            handle: None,
            blob: false,
            blob_mem: 0,
            blob_flags: 0,
            map_info: None,
            #[cfg(target_os = "macos")]
            map_ptr: None,
            info_2d: None,
            info_3d: None,
            vulkan_info: None,
            backing_iovecs: None,
            component_mask: 1 << (RutabagaComponentType::Gfxstream as u8),
            size: 0,
            mapping: None,
        })
    }

    fn attach_backing(
        &self,
        resource_id: u32,
        vecs: &mut Vec<RutabagaIovec>,
    ) -> RutabagaResult<()> {
        let ret = unsafe {
            stream_renderer_resource_attach_iov(
                resource_id as i32,
                vecs.as_mut_ptr() as *mut iovec,
                vecs.len() as i32,
            )
        };
        ret_to_res(ret)
    }

    fn detach_backing(&self, resource_id: u32) {
        unsafe {
            stream_renderer_resource_detach_iov(
                resource_id as i32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
        }
    }

    fn unref_resource(&self, resource_id: u32) {
        // The resource is safe to unreference destroy because no user of these bindings can still
        // be holding a reference.
        unsafe {
            stream_renderer_resource_unref(resource_id);
        }
    }

    fn transfer_write(
        &self,
        ctx_id: u32,
        resource: &mut RutabagaResource,
        transfer: Transfer3D,
    ) -> RutabagaResult<()> {
        if transfer.is_empty() {
            return Ok(());
        }

        let mut transfer_box = VirglBox {
            x: transfer.x,
            y: transfer.y,
            z: transfer.z,
            w: transfer.w,
            h: transfer.h,
            d: transfer.d,
        };

        // Safe because only stack variables of the appropriate type are used.
        let ret = unsafe {
            stream_renderer_transfer_write_iov(
                resource.resource_id,
                ctx_id,
                transfer.level as i32,
                transfer.stride,
                transfer.layer_stride,
                &mut transfer_box as *mut VirglBox as *mut stream_renderer_box,
                transfer.offset,
                null_mut(),
                0,
            )
        };
        ret_to_res(ret)
    }

    fn transfer_read(
        &self,
        ctx_id: u32,
        resource: &mut RutabagaResource,
        transfer: Transfer3D,
        buf: Option<IoSliceMut>,
    ) -> RutabagaResult<()> {
        if transfer.is_empty() {
            return Ok(());
        }

        let mut transfer_box = VirglBox {
            x: transfer.x,
            y: transfer.y,
            z: transfer.z,
            w: transfer.w,
            h: transfer.h,
            d: transfer.d,
        };

        let mut iov = RutabagaIovec {
            base: null_mut(),
            len: 0,
        };

        let (iovecs, num_iovecs) = match buf {
            Some(mut buf) => {
                iov.base = buf.as_mut_ptr() as *mut c_void;
                iov.len = buf.len();
                (&mut iov as *mut RutabagaIovec as *mut iovec, 1)
            }
            None => (null_mut(), 0),
        };

        // Safe because only stack variables of the appropriate type are used.
        let ret = unsafe {
            stream_renderer_transfer_read_iov(
                resource.resource_id,
                ctx_id,
                transfer.level,
                transfer.stride,
                transfer.layer_stride,
                &mut transfer_box as *mut VirglBox as *mut stream_renderer_box,
                transfer.offset,
                iovecs,
                num_iovecs,
            )
        };
        ret_to_res(ret)
    }

    fn resource_flush(&self, resource: &mut RutabagaResource) -> RutabagaResult<()> {
        unsafe {
            stream_renderer_flush(resource.resource_id);
        }
        Ok(())
    }

    fn create_blob(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        resource_create_blob: ResourceCreateBlob,
        mut iovec_opt: Option<Vec<RutabagaIovec>>,
        handle_opt: Option<RutabagaHandle>,
    ) -> RutabagaResult<RutabagaResource> {
        let mut iovec_ptr = null_mut();
        let mut num_iovecs = 0;
        if let Some(ref mut iovecs) = iovec_opt {
            iovec_ptr = iovecs.as_mut_ptr();
            num_iovecs = iovecs.len() as u32;
        }

        let mut handle_ptr = null();
        let mut stream_handle: stream_renderer_handle = Default::default();
        if let Some(handle) = handle_opt {
            stream_handle.handle_type = handle.handle_type;
            stream_handle.os_handle = handle.os_handle.into_raw_descriptor() as i64;
            handle_ptr = &stream_handle;
        }

        let ret = unsafe {
            stream_renderer_create_blob(
                ctx_id,
                resource_id,
                &resource_create_blob as *const stream_renderer_create_blob,
                iovec_ptr as *const iovec,
                num_iovecs,
                handle_ptr as *const stream_renderer_handle,
            )
        };

        ret_to_res(ret)?;

        // NOTE: `export_blob()` goes through gfxstream's `releaseHandle()`,
        // which is a one-shot `std::exchange(mFd, invalid)` on the host side;
        // calling it twice would hand back an invalid descriptor on the second
        // call. Compute the handle once and derive `map_ptr` from it below so
        // the same descriptor backs both fields.
        let handle = self.export_blob(resource_id).ok();

        // The macOS mapping path (RESOURCE_MAP_BLOB -> hypervisor mapping)
        // needs a host pointer for the resource, matching what the
        // virglrenderer component provides via
        // virgl_renderer_resource_get_map_ptr():
        //  - SHM-backed blobs: map the exported descriptor.
        //  - blobs without an exportable descriptor (e.g. host-visible
        //    VkDeviceMemory, which MoltenVK cannot export): fall back to
        //    gfxstream's own mapping, a vkMapMemory wrapper it keeps alive
        //    for the resource's lifetime.
        // Blobs that support neither stay unmapped (None), as before.
        #[cfg(target_os = "macos")]
        let map_ptr = {
            let shm_ptr = handle.as_ref().and_then(|h| {
                if h.handle_type == RUTABAGA_MEM_HANDLE_TYPE_SHM {
                    let addr = unsafe {
                        libc::mmap(
                            null_mut(),
                            resource_create_blob.size as usize,
                            libc::PROT_READ | libc::PROT_WRITE,
                            libc::MAP_SHARED,
                            h.os_handle.as_raw_descriptor(),
                            0,
                        )
                    };
                    if addr == libc::MAP_FAILED {
                        None
                    } else {
                        Some(addr as u64)
                    }
                } else {
                    None
                }
            });
            shm_ptr.or_else(|| {
                let mut map: *mut c_void = null_mut();
                let mut size: u64 = 0;
                let ret =
                    unsafe { stream_renderer_resource_map(resource_id, &mut map, &mut size) };
                if ret == 0 && !map.is_null() {
                    Some(map as u64)
                } else {
                    None
                }
            })
        };

        Ok(RutabagaResource {
            resource_id,
            handle,
            blob: true,
            blob_mem: resource_create_blob.blob_mem,
            blob_flags: resource_create_blob.blob_flags,
            map_info: self.map_info(resource_id).ok(),
            #[cfg(target_os = "macos")]
            map_ptr,
            info_2d: None,
            info_3d: None,
            vulkan_info: self.vulkan_info(resource_id).ok(),
            backing_iovecs: iovec_opt,
            component_mask: 1 << (RutabagaComponentType::Gfxstream as u8),
            size: resource_create_blob.size,
            mapping: None,
        })
    }

    fn map(&self, resource_id: u32) -> RutabagaResult<RutabagaMapping> {
        let mut map: *mut c_void = null_mut();
        let mut size: u64 = 0;

        // Safe because the Stream renderer wraps and validates use of vkMapMemory.
        let ret = unsafe { stream_renderer_resource_map(resource_id, &mut map, &mut size) };
        if ret != 0 {
            return Err(RutabagaError::MappingFailed(ret));
        }
        Ok(RutabagaMapping {
            ptr: map as u64,
            size,
        })
    }

    fn unmap(&self, resource_id: u32) -> RutabagaResult<()> {
        let ret = unsafe { stream_renderer_resource_unmap(resource_id) };
        ret_to_res(ret)
    }

    fn create_context(
        &self,
        ctx_id: u32,
        context_init: u32,
        context_name: Option<&str>,
        fence_handler: RutabagaFenceHandler,
    ) -> RutabagaResult<Box<dyn RutabagaContext>> {
        let mut name: &str = "gpu_renderer";
        if let Some(name_string) = context_name.filter(|s| !s.is_empty()) {
            name = name_string;
        }

        // Safe because gfxstream is initialized by now and the context name is statically
        // allocated. The return value is checked before returning a new context.
        let ret = unsafe {
            stream_renderer_context_create(
                ctx_id,
                name.len() as u32,
                name.as_ptr() as *const c_char,
                context_init,
            )
        };
        ret_to_res(ret)?;
        Ok(Box::new(GfxstreamContext {
            ctx_id,
            fence_handler,
        }))
    }
}
