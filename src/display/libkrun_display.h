#ifndef _LIBKRUN_DISPLAY_H
#define _LIBKRUN_DISPLAY_H

#include <inttypes.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// The display backend encountered an internal error
#define KRUN_DISPLAY_ERR_INTERNAL -1
#define KRUN_DISPLAY_ERR_METHOD_UNSUPPORTED -2
#define KRUN_DISPLAY_ERR_INVALID_SCANOUT_ID -3
#define KRUN_DISPLAY_ERR_INVALID_PARAM -4
#define KRUN_DISPLAY_ERR_OUT_OF_BUFFERS -5

// Same as VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM
#define KRUN_DISPLAY_FORMAT_B8G8R8A8_UNORM 1
// Same as VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM
#define KRUN_DISPLAY_FORMAT_B8G8R8X8_UNORM 2
// Same as VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM
#define KRUN_DISPLAY_FORMAT_A8R8G8B8_UNORM 3
// Same as VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM
#define KRUN_DISPLAY_FORMAT_X8R8G8B8_UNORM 4
// Same as VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM
#define KRUN_DISPLAY_FORMAT_R8G8B8A8_UNORM 67
// Same as VIRTIO_GPU_PIXEL_FORMAT_X8B8G8R8_UNORM
#define KRUN_DISPLAY_FORMAT_X8B8G8R8_UNORM 68
// Same as VIRTIO_GPU_PIXEL_FORMAT_A8B8G8R8_UNORM
#define KRUN_DISPLAY_FORMAT_A8B8G8R8_UNORM 121
// Same as VIRTIO_GPU_PIXEL_FORMAT_R8G8B8X8_UNORM
#define KRUN_DISPLAY_FORMAT_R8G8B8X8_UNORM 134

/**
 * Indicates support for basic framebuffer operations.
 * If supported, the implementation must provide `disable_scanout`, `configure_scanout`, `alloc_frame`,
 * and `present_frame`.
 */
#define KRUN_DISPLAY_FEATURE_BASIC_FRAMEBUFFER 1

/**
 * Indicates support for zero-copy DMABUF display.
 * If supported, the implementation must provide `disable_scanout`, `import_dmabuf`, `unref_dmabuf`,
 * `configure_scanout_dmabuf`, and `present_dmabuf`.
 */
#define KRUN_DISPLAY_FEATURE_DMABUF_CONSUMER 2

/**
 * Called to create a display instance.
 *
 * Arguments:
 *  "instance"    - (Output) pointer to userdata which can be used to represents this/self argument.
 *                  Implementation may set it to any value (even NULL)
 *  "userdata"    - userdata specified in the `krun_display_backend` instance
 *  "reserved"    - reserved/unused for now
 *
 * Returns:
 *  Zero on success or a negative error code (KRUN_DISPLAY_ERR_*) otherwise.
 */
typedef int32_t (*krun_display_create_fn)(void **instance, const void *userdata, const void *reserved);

/**
 * Called to destroy the display instance.
 *
 * Arguments:
 *  "instance"    - userdata set by `krun_display_create`, represents this/self argument
 *
 * Returns:
 *  Zero on success or a negative error code (KRUN_DISPLAY_ERR_*) otherwise.
 */
typedef int32_t (*krun_display_destroy_fn)(void *instance);

/**
 * Configures or reconfigures a display scanout.
 *
 * Arguments:
 *  "instance"       - userdata set by `krun_display_create`, represents this/self argument
 *  "scanout_id"     - The identifier of the scanout to configure.
 *  "display_width"  - The original width of the display in pixels.
 *  "display_height" - The original height of the display in pixels.
 *  "width"          - The width of the configured scanout in pixels.
 *  "height"         - The height of the configured scanout in pixels.
 *  "format"         - The pixel format for the scanout (see KRUN_DISPLAY_FORMAT_* constants).
 *
 * Returns:
 *  Zero on success or a negative error code (KRUN_DISPLAY_ERR_*) otherwise.
 */
typedef int32_t (*krun_display_configure_scanout_fn)(void *instance,
    uint32_t scanout_id,
    uint32_t display_width,
    uint32_t display_height,
    uint32_t width,
    uint32_t height,
    uint32_t format);

/**
 * Disables a display scanout.
 *
 * Arguments:
 *  "instance"    - userdata set by `krun_display_create`, represents this/self argument
 *  "scanout_id"  - The identifier of the scanout to disable.
 *
 * Returns:
 *  Zero on success or a negative error code (KRUN_DISPLAY_ERR_*) otherwise.
 */
typedef int32_t (*krun_display_disable_scanout_fn)(void *instance, uint32_t scanout_id);

/**
 * Allocates a new frame for a specified scanout.
 * This function provides a direct pointer to the frame's buffer.
 * The caller is responsible for writing pixel data into this buffer.
 *
 * Arguments:
 *  "instance"    - userdata set by `krun_display_create`, represents this/self argument
 *  "scanout_id"  - The identifier of the scanout for which to allocate the frame.
 *  "buffer"      - (Output) A pointer to a pointer that will be set to the address
 *                  of the allocated frame's memory. The memory pointed to
 *                  by *buffer must be writable by the caller.
 * "buffer_size"  -  (Output) The size of the allocated buffer. This is mostly a sanity check, because the size
 *                   is already determined by krun_display_configure_scanout.
 *
 * Returns:
 *  The "frame_id" of the allocated frame or a negative error code (KRUN_DISPLAY_ERR_*) otherwise.
 */
typedef int32_t (*krun_display_alloc_frame_fn)(void *instance, uint32_t scanout_id, uint8_t **buffer, size_t *buffer_size);

struct krun_rect {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
};

/**
 * Presents a previously allocated frame to the display.
 * After this call, the `frame_id` is considered consumed or "deallocated"
 * from the user's perspective. The user must call `krun_display_alloc_frame`
 * again to obtain a new valid frame for the next rendering cycle.
 * The content of the buffer associated with the `frame_id` should not be
 * modified after this call.
 *
 * Arguments:
 *  "instance"        - userdata set by `krun_display_create`, represents this/self argument
 *  "scanout_id"      - The identifier of the scanout on which to present the frame.
 *  "frame_id"        - The identifier of the frame to present, previously obtained from `krun_display_alloc_frame`.
* "damage_area"       - (Optional) Optimization hint describing the area that has changed since the last call to
 *                      present_frame. If NULL, the entire frame is assumed to be damaged.
 *
 * Returns:
 * Zero on success or a negative error or a negative error code (KRUN_DISPLAY_ERR_*) otherwise.
 */
typedef int32_t (*krun_display_present_frame_fn)(void *instance, uint32_t scanout_id, uint32_t frame_id, const struct krun_rect* damage_area);

/**
 * DMABUF export descriptor for zero-copy GPU memory sharing.
 */
struct krun_display_dmabuf_export {
    int32_t  dmabuf_fds[4];     // File descriptors for each plane
    uint32_t n_planes;           // Number of planes (1-4)
    uint32_t width;              // Width in pixels
    uint32_t height;             // Height in pixels
    uint32_t fourcc;             // DRM fourcc format code
    uint64_t modifier;           // DRM format modifier
    uint32_t strides[4];         // Stride for each plane
    uint32_t offsets[4];         // Offset for each plane
};

/**
 * Import a DMABUF for zero-copy display.
 *
 * Arguments:
 *  "instance"       - userdata set by `krun_display_create`
 *  "dmabuf_export"  - DMABUF descriptor to import
 *
 * Returns:
 *  DMABUF ID (>= 0) on success or a negative error code (KRUN_DISPLAY_ERR_*) otherwise.
 */
typedef int32_t (*krun_display_import_dmabuf_fn)(void *instance, const struct krun_display_dmabuf_export *dmabuf_export);

/**
 * Release a reference to a DMABUF.
 *
 * Arguments:
 *  "instance"   - userdata set by `krun_display_create`
 *  "dmabuf_id"  - DMABUF ID returned by import_dmabuf
 *
 * Returns:
 *  Zero on success or a negative error code (KRUN_DISPLAY_ERR_*) otherwise.
 */
typedef int32_t (*krun_display_unref_dmabuf_fn)(void *instance, uint32_t dmabuf_id);

/**
 * Configure a scanout to use a DMABUF.
 *
 * Arguments:
 *  "instance"       - userdata set by `krun_display_create`
 *  "scanout_id"     - The identifier of the scanout
 *  "display_width"  - The original width of the display
 *  "display_height" - The original height of the display
 *  "dmabuf_id"      - DMABUF ID returned by import_dmabuf
 *  "src_rect"       - (Optional) Source rectangle to display
 *
 * Returns:
 *  Zero on success or a negative error code (KRUN_DISPLAY_ERR_*) otherwise.
 */
typedef int32_t (*krun_display_configure_scanout_dmabuf_fn)(void *instance, uint32_t scanout_id, uint32_t display_width, uint32_t display_height, uint32_t dmabuf_id, const struct krun_rect *src_rect);

/**
 * Present a DMABUF scanout.
 *
 * Arguments:
 *  "instance"    - userdata set by `krun_display_create`
 *  "scanout_id"  - The identifier of the scanout
 *  "damage_area" - (Optional) Damage rectangle
 *
 * Returns:
 *  Zero on success or a negative error code (KRUN_DISPLAY_ERR_*) otherwise.
 */
typedef int32_t (*krun_display_present_dmabuf_fn)(void *instance, uint32_t scanout_id, const struct krun_rect *damage_area);

/**
 * Defines the set of callbacks for a display implementation.
 * This structure holds function pointers that a display backend implements to integrate with the libkrun.
 *
 * This is modeled as an object, an object instance is created using the `create` function and destroyed using `destroy`.
 * It is possible for the `create` function to be null in this case, the pointer to the object instance will be null
 * in the methods.
 *
 * The gpu device instantiates the display backend using the krun_display_create in a specific thread. All further calls
 * to the display backend will be called from the same thread. Note that the display methods should not block for a long
 * time otherwise this will negatively impact performance of the emulated GPU device.
 *
 * See krun_display_* function pointer typedef definitions for descriptions of individual methods.
 * In the future more methods may be added, depending on which KRUN_DISPLAY_FEATURE_* flags are passed to
 * krun_set_display_backend. The user of the library *MUST* zero initialize this struct to make all (future) unset
 * fields NULL.
 */
struct krun_display_basic_framebuffer_vtable {
    krun_display_destroy_fn             destroy; // (optional)
    krun_display_disable_scanout_fn     disable_scanout; // Required by KRUN_DISPLAY_FEATURE_BASIC_FRAMEBUFFER
    krun_display_configure_scanout_fn   configure_scanout; // Required by KRUN_DISPLAY_FEATURE_BASIC_FRAMEBUFFER
    krun_display_alloc_frame_fn         alloc_frame; // Required by KRUN_DISPLAY_FEATURE_BASIC_FRAMEBUFFER
    krun_display_present_frame_fn       present_frame; // Required by KRUN_DISPLAY_FEATURE_BASIC_FRAMEBUFFER
    // DMABUF extension methods (optional, only required if KRUN_DISPLAY_FEATURE_DMABUF_CONSUMER is set)
    krun_display_import_dmabuf_fn              import_dmabuf; // Required by KRUN_DISPLAY_FEATURE_DMABUF_CONSUMER
    krun_display_unref_dmabuf_fn               unref_dmabuf; // Required by KRUN_DISPLAY_FEATURE_DMABUF_CONSUMER
    krun_display_configure_scanout_dmabuf_fn   configure_scanout_dmabuf; // Required by KRUN_DISPLAY_FEATURE_DMABUF_CONSUMER
    krun_display_present_dmabuf_fn             present_dmabuf; // Required by KRUN_DISPLAY_FEATURE_DMABUF_CONSUMER
};

struct krun_display_dmabuf_vtable {
    krun_display_destroy_fn                    destroy; // (optional)
    krun_display_disable_scanout_fn            disable_scanout; // Required by KRUN_DISPLAY_FEATURE_DMABUF_CONSUMER
    krun_display_import_dmabuf_fn              import_dmabuf; // Required by KRUN_DISPLAY_FEATURE_DMABUF_CONSUMER
    krun_display_unref_dmabuf_fn               unref_dmabuf; // Required by KRUN_DISPLAY_FEATURE_DMABUF_CONSUMER
    krun_display_configure_scanout_dmabuf_fn   configure_scanout_dmabuf; // Required by KRUN_DISPLAY_FEATURE_DMABUF_CONSUMER
    krun_display_present_dmabuf_fn             present_dmabuf; // Required by KRUN_DISPLAY_FEATURE_DMABUF_CONSUMER
};

union krun_display_vtable {
    struct krun_display_basic_framebuffer_vtable basic_framebuffer;
    struct krun_display_dmabuf_vtable dmabuf;
};

struct krun_display_backend {
    uint64_t features;
    void *create_userdata; // (optional)
    krun_display_create_fn create; // (optional)
    union krun_display_vtable vtable;
};

#ifdef __cplusplus
}
#endif

#endif // _LIBKRUN_DISPLAY_H
