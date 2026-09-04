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
/* The backend shows the guest's pointer itself: the guest hands over the pointer image and its
 * position instead of drawing a software pointer into every frame. */
#define KRUN_DISPLAY_FEATURE_CURSOR 2

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
/**
 * Replace the pointer image for a scanout. `bgra` holds `width * height` pixels, 4 bytes each in
 * B,G,R,A order with straight alpha, and the pointer hot spot is at (`hot_x`, `hot_y`). A width or
 * height of 0 hides the pointer. The pixels are only valid during the call.
 */
typedef int32_t (*krun_display_set_cursor_fn)(void *instance, uint32_t scanout_id, uint32_t width,
                                              uint32_t height, uint32_t hot_x, uint32_t hot_y,
                                              const uint8_t *bgra, size_t bgra_size);

/**
 * Move the pointer: (`x`, `y`) is where the hot spot now sits on the scanout.
 */
typedef int32_t (*krun_display_move_cursor_fn)(void *instance, uint32_t scanout_id, uint32_t x, uint32_t y);

struct krun_display_basic_framebuffer_vtable {
    krun_display_destroy_fn             destroy; // (optional)
    krun_display_disable_scanout_fn     disable_scanout; // Required by KRUN_DISPLAY_FEATURE_BASIC_FRAMEBUFFER
    krun_display_configure_scanout_fn   configure_scanout; // Required by KRUN_DISPLAY_FEATURE_BASIC_FRAMEBUFFER
    krun_display_alloc_frame_fn         alloc_frame; // Required by KRUN_DISPLAY_FEATURE_BASIC_FRAMEBUFFER
    krun_display_present_frame_fn       present_frame; // Required by KRUN_DISPLAY_FEATURE_BASIC_FRAMEBUFFER
};

union krun_display_vtable {
    struct krun_display_basic_framebuffer_vtable basic_framebuffer;
};

struct krun_display_cursor_vtable {
    krun_display_set_cursor_fn          set_cursor; // Required by KRUN_DISPLAY_FEATURE_CURSOR
    krun_display_move_cursor_fn         move_cursor; // Required by KRUN_DISPLAY_FEATURE_CURSOR
};

struct krun_display_backend {
    uint64_t features;
    void *create_userdata; // (optional)
    krun_display_create_fn create; // (optional)
    union krun_display_vtable vtable;
    struct krun_display_cursor_vtable cursor; // Read only when KRUN_DISPLAY_FEATURE_CURSOR is set
};

#ifdef __cplusplus
}
#endif

#endif // _LIBKRUN_DISPLAY_H
