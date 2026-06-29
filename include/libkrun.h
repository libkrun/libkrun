#ifndef _LIBKRUN_H
#define _LIBKRUN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>

#define KRUN_LOG_TARGET_DEFAULT -1

#define KRUN_LOG_LEVEL_OFF 0
#define KRUN_LOG_LEVEL_ERROR 1
#define KRUN_LOG_LEVEL_WARN 2
#define KRUN_LOG_LEVEL_INFO 3
#define KRUN_LOG_LEVEL_DEBUG 4
#define KRUN_LOG_LEVEL_TRACE 5

#define KRUN_LOG_STYLE_AUTO 0
#define KRUN_LOG_STYLE_ALWAYS 1
#define KRUN_LOG_STYLE_NEVER 2

#define KRUN_LOG_OPTION_NO_ENV 1

/**
 * Initializes logging for the library.
 *
 * Arguments:
 *  "target_fd" - File descriptor to write log to. Note that using a file descriptor pointing to a regular file on
 *                filesystem might slow down the VM.
 *                Use KRUN_LOG_TARGET_DEFAULT to use the default target for log output (stderr).
 *
 *  "level"     - Level is an integer specifying the level of verbosity, higher number means more verbose log.
 *                The log levels are described by the constants: KRUN_LOG_LEVEL_{OFF, ERROR, WARN, INFO, DEBUG, TRACE}
 *
 *  "style"     - Enable/disable usage of terminal escape sequences (to display colors)
 *                One of: KRUN_LOG_STYLE_{AUTO, ALWAYS, NEVER}.
 *
 *  "options"   - Bitmask of logging options, use 0 for default options.
 *                KRUN_LOG_OPTION_NO_ENV to disallow environment variables to override these settings.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_init_log(int target_fd, uint32_t level, uint32_t style, uint32_t options);

/**
 * Creates a configuration context.
 *
 * Returns:
 *  The context ID on success or a negative error number on failure.
 */
int32_t krun_create_ctx();

/**
 * Frees an existing configuration context.
 *
 * Arguments:
 *  "ctx_id" - the configuration context ID.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_free_ctx(uint32_t ctx_id);

/**
 * Sets the basic configuration parameters for the microVM.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "num_vcpus" - the number of vCPUs.
 *  "ram_mib"   - the amount of RAM in MiB.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_vm_config(uint32_t ctx_id, uint8_t num_vcpus, uint32_t ram_mib);

/**
 * The virtiofs tag used for the root filesystem. Can be used with krun_add_virtiofs*
 * for more control over root filesystem parameters (e.g. read-only, DAX window size).
 */
#define KRUN_FS_ROOT_TAG "/dev/root"



/**
 * Adds a disk image to be used as a general partition for the microVM. The only supported image
 * format is "raw".
 *
 * This function deliberately only handles images in the Raw format, because it doesn't allow
 * specifying an image format, and probing an image's format is dangerous. For more information,
 * see the security note on `krun_add_disk2`, which allows opening non-Raw images.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "block_id"  - a null-terminated string representing the partition.
 *  "disk_path" - a null-terminated string representing the path leading to the disk image.
 *  "read_only" - whether the mount should be read-only. Required if the caller does not have
 *                write permissions (for disk images in /usr/share).
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_add_disk(uint32_t ctx_id, const char *block_id, const char *disk_path, bool read_only);

/* Supported disk image formats */
#define KRUN_DISK_FORMAT_RAW 0
#define KRUN_DISK_FORMAT_QCOW2 1
/* Note: Only supports FLAT/ZERO formats without delta links */
#define KRUN_DISK_FORMAT_VMDK 2

/**
 * Adds a disk image to be used as a general partition for the microVM. The supported
 * image formats are: "raw" and "qcow2".
 *
 * SECURITY NOTE:
 * Non-Raw images can reference other files, which libkrun will automatically open, and to which the
 * guest will have access. Libkrun should therefore never be asked to open an image in a non-Raw
 * format when it doesn't come from a fully trustworthy source.
 *
 * Consequently, probing an image's format is quite dangerous and to be avoided if at all possible,
 * which is why libkrun provides no facilities for doing so. If it's not clear what format an image
 * has, it may also not be clear whether it can be trusted to not reference files to which the guest
 * shouldn't have access.
 *
 * If probing absolutely can't be avoided, it must only be done on images that are fully trusted, i.e.
 * before a potentially untrusted guest had write access to it. Specifically, consider that a guest has
 * full access to all of a Raw image, and can therefore turn it into a file in an arbitrary format, for
 * example, into a Qcow2 image, referencing and granting a malicious guest access to arbitrary files.
 * To hand a Raw image to an untrusted and potentially malicious guest, and then to re-probe it after
 * the guest was able to write to it (when it can no longer be trusted), would therefore be a severe
 * security vulnerability.
 *
 * Therefore, after having probed a yet fully trusted image once, the result must be remembered so the
 * image will from then on always be opened in the format that was detected originally. When adhering
 * to this, a guest can write anything they want to a Raw image, it's always going to be opened as a
 * Raw image, preventing the security vulnerability outlined above.
 *
 * However, if at all possible, the image format should be explicitly selected based on knowledge
 * obtained separately from the pure image data, for example by the user.
 *
 * Arguments:
 *  "ctx_id"      - the configuration context ID.
 *  "block_id"    - a null-terminated string representing the partition.
 *  "disk_path"   - a null-terminated string representing the path leading to the disk image.
 *  "disk_format" - the disk image format (i.e. KRUN_DISK_FORMAT_{RAW, QCOW2})
 *  "read_only"   - whether the mount should be read-only. Required if the caller does not have
 *                  write permissions (for disk images in /usr/share).
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_add_disk2(uint32_t ctx_id,
                       const char *block_id,
                       const char *disk_path,
                       uint32_t disk_format,
                       bool read_only);


/* Supported sync modes */

/**
 * Ignore VIRTIO_BLK_F_FLUSH.
 * WARNING: may lead to loss of data 
 */ 
#define KRUN_SYNC_NONE 0
/**
 * Honor VIRTIO_BLK_F_FLUSH requests, but relax strict hardware syncing on macOS.
 * This is the recommended mode.
 *
 * On macOS this flushes the OS buffers, but does not ask the drive to flush
 * its buffered data, which significantly improves performance. 
 * On Linux this is the same as full sync.
 */
#define KRUN_SYNC_RELAXED 1
/** 
 * Honor VIRTIO_BLK_F_FLUSH, strictly flushing buffers to physical disk.
 */
#define KRUN_SYNC_FULL 2

/**
 * Adds a disk image to be used as a general partition for the microVM.
 *
 * SECURITY NOTE:
 * See the security note for `krun_add_disk2`.
 *
 * Arguments:
 *  "ctx_id"      - the configuration context ID.
 *  "block_id"    - a null-terminated string representing the partition.
 *  "disk_path"   - a null-terminated string representing the path leading to the disk image.
 *  "disk_format" - the disk image format (i.e. KRUN_DISK_FORMAT_{RAW, QCOW2})
 *  "read_only"   - whether the mount should be read-only. Required if the caller does not have
 *                  write permissions (for disk images in /usr/share).
 *  "direct_io"   - whether to bypass the host caches.
 *  "sync_mode"   - whether to enable VIRTIO_BLK_F_FLUSH. On macOS, an additional relaxed sync
 *                  mode is available, which is enabled by default, and will not ask the drive
 *                  to flush its buffered data.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
 int32_t krun_add_disk3(uint32_t ctx_id,
                       const char *block_id,
                       const char *disk_path,
                       uint32_t disk_format,
                       bool read_only,
                       bool direct_io,
                       uint32_t sync_mode);

/**
 * Adds an independent virtio-fs device pointing to a host's directory with a tag.
 *
 * Arguments:
 *  "ctx_id"         - the configuration context ID.
 *  "c_tag"          - tag to identify the filesystem in the guest.
 *  "c_path"         - full path to the directory in the host to be exposed to the guest.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_add_virtiofs(uint32_t ctx_id,
                          const char *c_tag,
                          const char *c_path);

/**
 * Adds an independent virtio-fs device pointing to a host's directory with a tag. This
 * variant allows specifying the size of the DAX window.
 *
 * Arguments:
 *  "ctx_id"         - the configuration context ID.
 *  "c_tag"          - tag to identify the filesystem in the guest.
 *  "c_path"         - full path to the directory in the host to be exposed to the guest.
 *  "shm_size"       - size of the DAX SHM window in bytes.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_add_virtiofs2(uint32_t ctx_id,
                           const char *c_tag,
                           const char *c_path,
                           uint64_t shm_size);

/**
 * Adds an independent virtio-fs device pointing to a host's directory with a tag. This
 * variant allows specifying the size of the DAX window and a read-only flag.
 *
 * Arguments:
 *  "ctx_id"         - the configuration context ID.
 *  "c_tag"          - tag to identify the filesystem in the guest.
 *  "c_path"         - full path to the directory in the host to be exposed to the guest.
 *  "shm_size"       - size of the DAX SHM window in bytes.
 *  "read_only"      - if true, the filesystem will be exposed as read-only to the guest.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_add_virtiofs3(uint32_t ctx_id,
                           const char *c_tag,
                           const char *c_path,
                           uint64_t shm_size,
                           bool read_only);

/* Send the VFKIT magic after establishing the connection,
   as required by gvproxy in vfkit mode. */
#define NET_FLAG_VFKIT (1 << 0)
#define NET_FLAG_DHCP_CLIENT (1 << 1)

/* TSI (Transparent Socket Impersonation) feature flags for vsock */
#define KRUN_TSI_HIJACK_INET  (1 << 0)
#define KRUN_TSI_HIJACK_UNIX  (1 << 1)

/* Taken from uapi/linux/virtio_net.h */
#define NET_FEATURE_CSUM 1 << 0
#define NET_FEATURE_GUEST_CSUM 1 << 1
#define NET_FEATURE_GUEST_TSO4 1 << 7
#define NET_FEATURE_GUEST_TSO6 1 << 8
#define NET_FEATURE_GUEST_UFO 1 << 10
#define NET_FEATURE_HOST_TSO4 1 << 11
#define NET_FEATURE_HOST_TSO6 1 << 12
#define NET_FEATURE_HOST_UFO 1 << 14

/* These are the default features used by krun_add_net_unixstream and krun_add_net_unixgram. */
#define COMPAT_NET_FEATURES NET_FEATURE_CSUM | NET_FEATURE_GUEST_CSUM | \
                            NET_FEATURE_GUEST_TSO4 | NET_FEATURE_GUEST_UFO | \
                            NET_FEATURE_HOST_TSO4 | NET_FEATURE_HOST_UFO
/**
 * Adds an independent virtio-net device connected to a
 * unixstream-based userspace network proxy, such as passt or
 * socket_vmnet.
 *
 * The "krun_add_net_*" functions can be called multiple times for
 * adding multiple virtio-net devices. In the guest the interfaces
 * will appear in the same order as they are added (that is, the
 * first added interface will be "eth0", the second "eth1"...)
 *
 * If no network interface is added, libkrun will automatically
 * enable the TSI backend.
 *
 * Arguments:
 *  "ctx_id"   - the configuration context ID.
 *  "c_path"   - a null-terminated string representing the path
 *               for the unixstream socket where the userspace
 *               network proxy is listening. Must be NULL if "fd"
 *               is not -1.
 *  "fd"       - a file descriptor for an already open unixstream
 *               connection to the userspace network proxy. Must
 *               be -1 if "c_path" is not NULL.
 *  "c_mac"    - MAC address as an array of 6 uint8_t entries.
 *  "features" - virtio-net features for the network interface.
 *  "flags"    - generic flags for the network interface.
 *
 * Notes:
 * The arguments "c_path" and "fd" are mutually exclusive. If using
 * "fd", the socket must be already initialized and configured as
 * the userspace network proxy requires.
 * If no network devices are added, networking uses the TSI backend.
 * This function should be called before krun_set_port_map.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_add_net_unixstream(uint32_t ctx_id,
                                const char *c_path,
                                int fd,
                                uint8_t *const c_mac,
                                uint32_t features,
                                uint32_t flags);

/**
 * Adds an independent virtio-net device with a unixgram-based
 * backend, such as gvproxy or vmnet-helper.
 *
 * The "krun_add_net_*" functions can be called multiple times for
 * adding multiple virtio-net devices. In the guest the interfaces
 * will appear in the same order as they are added (that is, the
 * first added interface will be "eth0", the second "eth1"...)
 *
 * If no network interface is added, libkrun will automatically
 * enable the TSI backend.
 *
 * Arguments:
 *  "ctx_id"   - the configuration context ID.
 *  "c_path"   - a null-terminated string representing the path
 *               for the unixstream socket where the userspace
 *               network proxy is listening. Must be NULL if "fd"
 *               is not -1.
 *  "fd"       - a file descriptor for an already open unixstream
 *               connection to the userspace network proxy. Must
 *               be -1 if "c_path" is not NULL.
 *  "c_mac"    - MAC address as an array of 6 uint8_t entries.
 *  "features" - virtio-net features for the network interface.
 *  "flags"    - generic flags for the network interface.
 *
 * Notes:
 * The arguments "c_path" and "fd" are mutually exclusive. If using
 * "fd", the socket must be already initialized and configured as
 * the userspace network proxy requires.
 * If no network devices are added, networking uses the TSI backend.
 * This function should be called before krun_set_port_map.
 * If using gvproxy in vfkit mode, NET_FLAG_VFKIT must be passed in
 * "flags" when using "c_path" to indicate the connection endpoint.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_add_net_unixgram(uint32_t ctx_id,
                              const char *c_path,
                              int fd,
                              uint8_t *const c_mac,
                              uint32_t features,
                              uint32_t flags);

/**
 * Adds an independent virtio-net device with the tap backend.
 * Call to this function disables TSI backend.

 * The "krun_add_net_*" functions can be called multiple times for
 * adding multiple virtio-net devices. In the guest the interfaces
 * will appear in the same order as they are added (that is, the
 * first added interface will be "eth0", the second "eth1"...)
 *
 * Arguments:
 *  "ctx_id"      - the configuration context ID.
 *  "c_tap_name"  - a null-terminated string representing the tap
 *                  device name.
 *  "c_mac"       - MAC address as an array of 6 uint8_t entries.
 *  "features"    - virtio-net features for the network interface.
 *  "flags"       - generic flags for the network interface.
 *
 * Notes:
 * If no network devices are added, networking uses the TSI backend.
 * This function should be called before krun_set_port_map.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_add_net_tap(uint32_t ctx_id,
                         char *c_tap_name,
                         uint8_t *const c_mac,
                         uint32_t features,
                         uint32_t flags);

/**
 * Configures a map of host to guest TCP ports for the microVM.
 *
 * Arguments:
 *  "ctx_id"   - the configuration context ID.
 *  "port_map" - an array of string pointers with format "host_port:guest_port"
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 *  Documented errors:
 *       -ENOTSUP when passt networking is used
 *
 * Notes:
 *  Passing NULL (or not calling this function) as "port_map" has a different meaning than
 *  passing an empty array. The first one will instruct libkrun to attempt to expose all
 *  listening ports in the guest to the host, while the second means that no port from
 *  the guest will be exposed to host.
 *
 *  Exposed ports will only become accessible by their "host_port" in the guest too. This
 *  means that for a map such as "8080:80", applications running inside the guest will also
 *  need to access the service through the "8080" port.
 *
 * If passt networking mode is used, port mapping is not supported as an API
 * of libkrun (but you can still do port mapping using command line arguments
 * of passt)
 */
int32_t krun_set_port_map(uint32_t ctx_id, const char *const port_map[]);

/* Flags for virglrenderer.  Copied from virglrenderer bindings. */
#define VIRGLRENDERER_USE_EGL 1 << 0
#define VIRGLRENDERER_THREAD_SYNC 1 << 1
#define VIRGLRENDERER_USE_GLX 1 << 2
#define VIRGLRENDERER_USE_SURFACELESS 1 << 3
#define VIRGLRENDERER_USE_GLES 1 << 4
#define VIRGLRENDERER_USE_EXTERNAL_BLOB 1 << 5
#define VIRGLRENDERER_VENUS 1 << 6
#define VIRGLRENDERER_NO_VIRGL 1 << 7
#define VIRGLRENDERER_USE_ASYNC_FENCE_CB 1 << 8
#define VIRGLRENDERER_RENDER_SERVER 1 << 9
#define VIRGLRENDERER_DRM 1 << 10
/**
 * Enables and configures a virtio-gpu device.
 *
 * Arguments:
 *  "ctx_id"      - the configuration context ID.
 *  "virgl_flags" - flags to pass to virglrenderer.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_gpu_options(uint32_t ctx_id, uint32_t virgl_flags);

/**
 * Enables and configures a virtio-gpu device. This variant allows specifying
 * the size of the host window (acting as vRAM in the guest).
 *
 * Arguments:
 *  "ctx_id"      - the configuration context ID.
 *  "virgl_flags" - flags to pass to virglrenderer.
 *  "shm_size"    - size of the SHM host window in bytes.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_gpu_options2(uint32_t ctx_id,
                              uint32_t virgl_flags,
                              uint64_t shm_size);

/* Maximum number of displays. Same as VIRTIO_GPU_MAX_SCANOUTS defined in the virtio-gpu spec */
#define KRUN_MAX_DISPLAYS 16

/**
 * Configure a display output for the VM.
 *
 * Note that to have display output a display backend must also be set (see krun_set_display_backend).
 *
 * Arguments:
 *  "ctx_id"      - the configuration context ID.
 *  "width"       - the width of the window/display
 *  "height"      - the height of the window/display
 *
 * Returns:
 *  The id of the display (0 to KRUN_MAX_DISPLAYS - 1) on success or a negative error number on failure.
 */
int32_t krun_add_display(uint32_t ctx_id, uint32_t width, uint32_t height);

/**
 * Configure a custom EDID blob for a display
 *
 * This replaces the generated EDID with a custom one. Configuring an EDID blob makes all display parameters except
 * width and height ignored.
 *
 * Note that libkrun doesn't do any checks if the EDID matches the width/height specified in krun_add_display().
 *
 * Arguments:
 *  "ctx_id"      - the configuration context ID.
 *  "display_id"  - the ID of the display (range: 0 to KRUN_MAX_DISPLAYS - 1)
 *  "edid_blob"   - the EDID blob
 *  "blob_size"   - the size of the blob in bytes
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_display_set_edid(uint32_t ctx_id, uint32_t display_id, const uint8_t* edid_blob, size_t blob_size);

/**
 * Configure DPI of the display reported to the guest
 *
 * This overrides the DPI set by krun_set_display_dpi()
 *
 * Arguments:
 *  "ctx_id"      - the configuration context ID.
 *  "display_id"  - the ID of the display (range: 0 to KRUN_MAX_DISPLAYS - 1)
 *  "dpi"         - DPI (PPI) dots/pixels per inch of the display
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_display_set_dpi(uint32_t ctx_id, uint32_t display_id, uint32_t dpi);

/**
 * Configure physical size of the display reported to the guest
 *
 * This overrides the physical size of the display set by krun_set_display_physical_size()
 *
 * Arguments:
 *  "ctx_id"      - the configuration context ID.
 *  "display_id"  - the ID of the display (range: 0 to KRUN_MAX_DISPLAYS - 1)
 *  "width_mm"    - width of the display in millimeters
 *  "height_mm"   - height of the display in millimeters
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_display_set_physical_size(uint32_t ctx_id, uint32_t display_id, uint16_t width_mm, uint16_t height_mm);

/**
 * Configure refresh rate for a display
 *
 *
 * Arguments:
 *  "ctx_id"      - the configuration context ID.
 *  "display_id"  - the ID of the display (range: 0 to KRUN_MAX_DISPLAYS - 1)
 *  "refresh_rate" - refresh rate (in Hz)
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_display_set_refresh_rate(uint32_t ctx_id, uint32_t display_id, uint32_t refresh_rate);

/**
 * Configures a krun_display_backend struct to be used for display output. (see libkrun_display.h)
 *
 * Arguments:
 *  "ctx_id"          - the configuration context ID
 *  "display_backend" - Pointer to a krun_display_backend struct
 *  "backend_size"    - sizeof() the krun_display_backend struct
 *
 * Returns:
 *  Zero on success or a negative error number (errno) on failure.
 */
int32_t krun_set_display_backend(uint32_t ctx_id, const void *display_backend, size_t backend_size);


/**
 * Adds an input device with separate config and events objects.
 *
 * Arguments:
 *  "ctx_id"               - the configuration context ID
 *  "config_backend"       - Pointer to a krun_input_config struct
 *  "config_backend_size"  - sizeof() the krun_input_config struct
 *  "events_backend"       - Pointer to a krun_input_event_provider struct
 *  "events_backend_size"  - sizeof() the krun_input_event_provider struct
 *
 * Returns:
 *  Zero on success or a negative error code otherwise.
 */
int krun_add_input_device(uint32_t ctx_id, const void *config_backend, size_t config_backend_size,
                            const void *events_backend, size_t events_backend_size);

/**
 * Creates a passthrough input device from a host /dev/input/* file descriptor.
 * The device configuration will be automatically queried from the host device using ioctls.
 * 
 * Arguments:
 *  "ctx_id"  - The krun context
 *  "input_fd" - File descriptor to a /dev/input/* device on the host
 *
 * Returns:
 *  Zero on success or a negative error code otherwise.
 */
int krun_add_input_device_fd(uint32_t ctx_id, int input_fd);

/**
 * Vhost-user device types.
 * These correspond to virtio device type IDs for devices.
 */
#define KRUN_VIRTIO_DEVICE_CONSOLE 3
#define KRUN_VIRTIO_DEVICE_RNG 4
#define KRUN_VIRTIO_DEVICE_RTC 17
#define KRUN_VIRTIO_DEVICE_INPUT 18
#define KRUN_VIRTIO_DEVICE_VSOCK 19
#define KRUN_VIRTIO_DEVICE_SND 25
#define KRUN_VIRTIO_DEVICE_CAN 36

/**
 * Vhost-user console device default queue configuration.
 * Console device uses 4 queues for multiport support:
 * receiveq (idx 0), transmitq (idx 1), control receiveq (idx 2), control transmitq (idx 3).
 */
#define KRUN_VHOST_USER_CONSOLE_NUM_QUEUES 4
#define KRUN_VHOST_USER_CONSOLE_QUEUE_SIZES ((uint16_t[]){128, 128, 64, 64})

/**
 * Vhost-user RNG device default queue configuration.
 * Use these when you want explicit defaults instead of auto-detection.
 */
#define KRUN_VHOST_USER_RNG_NUM_QUEUES 1
#define KRUN_VHOST_USER_RNG_QUEUE_SIZES ((uint16_t[]){256})

/**
 * Vhost-user RTC device default queue configuration.
 * RTC device uses 2 queues: requestq (idx 0), alarmq (idx 1).
 */
#define KRUN_VHOST_USER_RTC_NUM_QUEUES 2
#define KRUN_VHOST_USER_RTC_QUEUE_SIZES ((uint16_t[]){1024, 1024})

/**
 * Vhost-user input device default queue configuration.
 * Input device uses 2 queues: eventq (idx 0), statusq (idx 1).
 */
#define KRUN_VHOST_USER_INPUT_NUM_QUEUES 2
#define KRUN_VHOST_USER_INPUT_QUEUE_SIZES ((uint16_t[]){1024, 1024})

/**
 * Vhost-user sound device default queue configuration.
 * Sound device uses 4 queues: control (idx 0), event (idx 1), TX/playback (idx 2), RX/capture (idx 3).
 */
#define KRUN_VHOST_USER_SND_NUM_QUEUES 4
#define KRUN_VHOST_USER_SND_QUEUE_SIZES ((uint16_t[]){64, 64, 64, 64})

/**
 * Vhost-user vsock device default queue configuration.
 * Vsock device uses 3 queues: RX (idx 0), TX (idx 1), event (idx 2).
 */
#define KRUN_VHOST_USER_VSOCK_NUM_QUEUES 3
#define KRUN_VHOST_USER_VSOCK_QUEUE_SIZES ((uint16_t[]){128, 128, 128})

/**
 * Vhost-user CAN device default queue configuration.
 * CAN device uses 3 queues: TX (idx 0), RX (idx 1), control (idx 2).
 */
#define KRUN_VHOST_USER_CAN_NUM_QUEUES 3
#define KRUN_VHOST_USER_CAN_QUEUE_SIZES ((uint16_t[]){64, 64, 64})

/**
 * Add a vhost-user device to the VM.
 *
 * This function adds a vhost-user device by connecting to an external
 * backend process (e.g., vhost-device-rng, vhost-device-snd). The backend
 * must be running and listening on the specified socket before starting the VM.
 *
 * This API is designed for devices like RNG, sound, and CAN.
 *
 * Arguments:
 *  "ctx_id"       - the configuration context ID.
 *  "device_type"  - type of vhost-user device (e.g., KRUN_VHOST_USER_DEVICE_RNG).
 *  "socket_path"  - path to the vhost-user Unix domain socket (e.g., "/tmp/vhost-rng.sock").
 *  "name"         - device name for logging/debugging (e.g., "vhost-rng", "vhost-snd").
 *                   NULL = auto-generate from device_type ("vhost-user-4", "vhost-user-25", etc.)
 *  "num_queues"   - number of virtqueues.
 *                   0 = auto-detect from backend (requires backend MQ support).
 *                   >0 = explicit queue count.
 *                   Or use device-specific constants like KRUN_VHOST_USER_RNG_NUM_QUEUES.
 *  "queue_sizes"  - array of queue sizes for each queue.
 *                   NULL = use default size (256) for all queues.
 *                   When num_queues=0 (auto-detect): array must be 0-terminated (sentinel).
 *                   When num_queues>0 (explicit): array must have exactly num_queues elements.
 *                   Use device-specific constants like KRUN_VHOST_USER_RNG_QUEUE_SIZES for defaults.
 *
 * Examples:
 *  // Auto-detect queue count, use default size (256)
 *  krun_add_vhost_user_device(ctx, KRUN_VHOST_USER_DEVICE_RNG, "/tmp/rng.sock", NULL, 0, NULL);
 *
 *  // Auto-detect queue count, use custom size (512) for all queues
 *  uint16_t custom_size[] = {512, 0};  // 0 = sentinel terminator
 *  krun_add_vhost_user_device(ctx, KRUN_VHOST_USER_DEVICE_RNG, "/tmp/rng.sock", NULL, 0, custom_size);
 *
 *  // Explicit defaults using #define constants
 *  krun_add_vhost_user_device(ctx, KRUN_VHOST_USER_DEVICE_RNG, "/tmp/rng.sock", "vhost-rng",
 *                             KRUN_VHOST_USER_RNG_NUM_QUEUES,
 *                             KRUN_VHOST_USER_RNG_QUEUE_SIZES);
 *
 *  // Explicit queue count with custom sizes
 *  uint16_t sizes[] = {256, 512};
 *  krun_add_vhost_user_device(ctx, KRUN_VHOST_USER_DEVICE_SND, "/tmp/snd.sock", "vhost-snd", 2, sizes);
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 *  -EINVAL  - Invalid parameters (device_type, socket_path, etc.)
 *  -ENOENT  - Context doesn't exist
 *  -ENOTSUP - vhost-user support not compiled in
 */
int32_t krun_add_vhost_user_device(uint32_t ctx_id,
                                   uint32_t device_type,
                                   const char *socket_path,
                                   const char *name,
                                   uint16_t num_queues,
                                   const uint16_t *queue_sizes);

/**
 * Configures a map of rlimits to be set in the guest before starting the isolated binary.
 *
 * Arguments:
 *  "ctx_id"  - the configuration context ID.
 *  "rlimits" - an array of string pointers with format "RESOURCE=RLIM_CUR:RLIM_MAX".
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_rlimits(uint32_t ctx_id, const char *const rlimits[]);

/**
 * Sets the SMBIOS OEM Strings.
 *
 * Arguments:
 *  "ctx_id"      - the configuration context ID.
 *  "oem_strings" - an array of string pointers. Must be terminated with an additional NULL pointer.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_smbios_oem_strings(uint32_t ctx_id, const char *const oem_strings[]);

/**
 * Sets the working directory for the executable to be run inside the microVM.
 *
 * Arguments:
 *  "ctx_id"        - the configuration context ID.
 *  "workdir_path"  - the path to the working directory, relative to the root filesystem.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_workdir(uint32_t ctx_id,
                         const char *workdir_path);

/**
 * Sets the path to the executable to be run inside the microVM, the arguments to be passed to the
 * executable, and the environment variables to be configured in the context of the executable.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "exec_path" - the path to the executable, relative to the root filesystem.
 *  "argv"      - an array of string pointers to be passed as arguments.
 *  "envp"      - an array of string pointers to be injected as environment variables into the
 *                context of the executable. If NULL, it will auto-generate an array collecting the
 *                the variables currently present in the environment.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_exec(uint32_t ctx_id,
                      const char *exec_path,
                      const char *const argv[],
                      const char *const envp[]);

/**
 * Sets the path to the firmware to be loaded into the microVM.
 *
 * Arguments:
 *  "ctx_id"        - the configuration context ID.
 *  "firmware_path" - the path to the firmware, relative to the host's filesystem.
 *
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_firmware(uint32_t ctx_id, const char *firmware_path);

#define KRUN_KERNEL_FORMAT_RAW 0
#define KRUN_KERNEL_FORMAT_ELF 1
#define KRUN_KERNEL_FORMAT_PE_GZ 2
#define KRUN_KERNEL_FORMAT_IMAGE_BZ2 3
#define KRUN_KERNEL_FORMAT_IMAGE_GZ 4
#define KRUN_KERNEL_FORMAT_IMAGE_ZSTD 5
/**
 * Sets the path to the kernel to be loaded in the microVM.
 *
 * Arguments:
 *  "ctx_id"        - the configuration context ID.
 *  "kernel_path"   - the path to the kernel, relative to the host's filesystem.
 *  "kernel_format" - the kernel format.
 *  "initramfs"     - the path to the initramfs, relative to the host's filesystem.
 *  "cmdline"       - the kernel command line.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_kernel(uint32_t ctx_id,
                        const char *kernel_path,
                        uint32_t kernel_format,
                        const char *initramfs,
                        const char *cmdline);

/**
 * Sets environment variables to be configured in the context of the executable.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "envp"      - an array of string pointers to be injected as environment variables into the
 *                context of the executable. If NULL, it will auto-generate an array collecting the
 *                the variables currently present in the environment.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_env(uint32_t ctx_id, const char *const envp[]);

/**
 * Sets the file path to the TEE configuration file. Only available in libkrun-sev.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "filepath"  - a null-terminated string representing file path to the TEE config file.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_tee_config_file(uint32_t ctx_id, const char *filepath);

/**
 * Adds a port-path pairing for guest IPC with a process in the host.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "port"      - a vsock port that the guest will connect to for IPC.
 *  "filepath"  - a null-terminated string representing the path of the UNIX
 *                socket in the host.
 */
int32_t krun_add_vsock_port(uint32_t ctx_id,
                            uint32_t port,
                            const char *c_filepath);

/**
 * Adds a port-path pairing for guest IPC with a process in the host.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "port"      - a vsock port that the guest will connect to for IPC.
 *  "filepath"  - a null-terminated string representing the path of the UNIX
 *                socket in the host.
 *  "listen"    - true if guest expects connections to be initiated from host side
 */
int32_t krun_add_vsock_port2(uint32_t ctx_id,
                             uint32_t port,
                             const char *c_filepath,
                             bool listen);

/**
 * Add a vsock device with specified TSI features.
 *
 * Currently only one vsock device is supported. Calling this function
 * multiple times will return an error.
 *
 * Arguments:
 *  "ctx_id"       - the configuration context ID.
 *  "tsi_features" - bitmask of TSI features (KRUN_TSI_HIJACK_INET, KRUN_TSI_HIJACK_UNIX)
 *                   Use 0 to add vsock without any TSI hijacking.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_add_vsock(uint32_t ctx_id, uint32_t tsi_features);

/**
 * Returns the eventfd file descriptor to signal the guest to shut down orderly. This must be
 * called before starting the microVM with "krun_start_event".
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *
 * Returns:
 *  The eventfd file descriptor or a negative error number on failure.
 */
int32_t krun_get_shutdown_eventfd(uint32_t ctx_id);

/**
 * Configures the console device to write its output to "c_filepath".
 * Only available when built with AWS Nitro support.
 *
 * Arguments:
 *  "ctx_id"    - the configuration context ID.
 *  "filepath"  - a null-terminated string representing the path of the file to write the
 *                console output.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_console_output(uint32_t ctx_id, const char *c_filepath);

/**
 * Configures uid which is set right before the microVM is started.
 *
 * This is useful for example when you want to access host block devices
 * from the microVM which requires root privileges when opening the device
 * but you don't want to run the whole microVM as root.
 *
 * Arguments:
 *  "ctx_id"         - the configuration context ID.
 *  "uid"            - a user id to be set.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_setuid(uint32_t ctx_id, uid_t uid);

/**
 * Configures gid which is set right before the microVM is started.
 *
 * This is useful for example when you want to access host block devices
 * from the microVM which requires root privileges when opening the device
 * but you don't want to run the whole microVM as root.
 *
 * Arguments:
 *  "ctx_id"         - the configuration context ID.
 *  "gid"            - a group id to be set.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_setgid(uint32_t ctx_id, gid_t gid);

/**
 * Configures the microVM to support Nested Virtualization
 *
 * Arguments:
 *  "ctx_id"  - the configuration context ID.
 *  "enabled" - true to enable Nested Virtualization in the microVM.
 *
 * Returns:
 *  Zero on success or a negative error number on failure. Success doesn't imply that
 *  Nested Virtualization is supported on the system, only that it's going to be requested
 *  when the microVM is created after calling "krun_start_enter".
 */
int32_t krun_set_nested_virt(uint32_t ctx_id, bool enabled);

/**
 * Check the system if Nested Virtualization is supported
 *
 * Returns:
 *  - 1 : Success and Nested Virtualization is supported
 *  - 0 : Success and Nested Virtualization is not supported
 *  - <0: Failure
 */
int32_t krun_check_nested_virt(void);

/* Feature constants for krun_has_feature() */
#define KRUN_FEATURE_NET 0
#define KRUN_FEATURE_BLK 1
#define KRUN_FEATURE_GPU 2
#define KRUN_FEATURE_INPUT 4
#define KRUN_FEATURE_TEE 6
#define KRUN_FEATURE_AMD_SEV 7
#define KRUN_FEATURE_INTEL_TDX 8
#define KRUN_FEATURE_AWS_NITRO 9
#define KRUN_FEATURE_VIRGL_RESOURCE_MAP2 10
#define KRUN_FEATURE_INIT_BLOB 11

/**
 * Checks if a specific feature was enabled at build time.
 *
 * Arguments:
 *  "feature" - one of the KRUN_FEATURE_* constants.
 *
 * Returns:
 *  1 if the feature is supported, 0 if not supported, or a negative error
 *  number on failure (e.g., -EINVAL for invalid/unknown feature constant).
 *
 * Notes:
 *  When linking against an older version of libkrun, this function may
 *  return -EINVAL for feature constants that were added in newer versions.
 */
int32_t krun_has_feature(uint64_t feature);

/**
 * Get the maximum number of vCPUs supported by the hypervisor.
 *
 * Returns:
 *  The maximum number of vCPUs that can be created, or a negative error number on failure.
 */
int32_t krun_get_max_vcpus(void);

/**
 * Specify whether to split IRQCHIP responsibilities between the host and the guest.
 *
 * Arguments:
 *  "ctx_id" - the configuration context ID.
 *  "enable" - whether to enable the split IRQCHIP
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
*/
int32_t krun_split_irqchip(uint32_t ctx_id, bool enable);

/**
 * Do not inject the default init binary (/init.krun) into the root
 * filesystem. Must be called before configuring the root filesystem.
 *
 * No-op when libkrun is built without the "init-blob" feature (there is no
 * implicit init to disable).
 *
 * Arguments:
 *  "ctx_id" - the configuration context ID.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_disable_implicit_init(uint32_t ctx_id);

/**
 * Get a pointer to the built-in default init binary.
 *
 * This is the same binary that libkrun injects as /init.krun by default.
 * Callers that use krun_disable_implicit_init() can use this to inject the
 * init binary themselves (e.g. via krun_fs_add_overlay_file with custom
 * settings).
 *
 * The returned pointer is valid for the lifetime of the process (static data).
 *
 * Arguments:
 *  "data_out" - receives a pointer to the init binary bytes.
 *  "len_out"  - receives the length in bytes.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 *  -EINVAL   - data_out or len_out is NULL
 *  -ENOTSUP  - libkrun was built without the "init-blob" feature
 */
int32_t krun_get_default_init(const uint8_t **data_out, size_t *len_out);

/**
 * Add a virtual overlay file to a virtiofs device.
 *
 * The file is backed entirely by host memory (no host file). The data
 * pointer is NOT copied — the caller must keep the memory valid for the
 * full VM lifetime.
 *
 * "path" may contain '/' to place the file inside a virtual directory
 * previously created with krun_fs_add_overlay_dir (e.g. "etc/hostname").
 * All intermediate directories must already exist; -ENOENT is returned
 * if a component is missing, -ENOTDIR if a component is not a directory.
 *
 * Arguments:
 *  "ctx_id"   - the configuration context ID.
 *  "fs_tag"   - tag of the virtiofs device (e.g. "/dev/root").
 *  "path"     - path of the file (e.g. "init.krun" or "etc/hostname").
 *  "data"     - pointer to the file content.
 *  "data_len" - length of the file content in bytes.
 *  "mode"     - file mode bits (e.g. 0100644 for a regular file).
 *  "one_shot" - if true, the file can only be looked up once.
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 *  -EINVAL  - invalid parameters (NULL pointer, empty path component)
 *  -ENOENT  - context, fs_tag, or intermediate path component not found
 *  -ENOTDIR - intermediate path component is not a directory
 */
int32_t krun_fs_add_overlay_file(uint32_t ctx_id, const char *fs_tag,
                                 const char *path, const uint8_t *data,
                                 size_t data_len, uint32_t mode, bool one_shot);

/**
 * Add a virtual overlay directory to a virtiofs device.
 *
 * The directory is empty and read-only, useful as a mount point.
 *
 * "path" may contain '/' to nest inside an existing virtual directory
 * (e.g. "usr/lib"). All intermediate directories must already exist;
 * -ENOENT is returned if a component is missing, -ENOTDIR if a component
 * is not a directory.
 *
 * Arguments:
 *  "ctx_id"   - the configuration context ID.
 *  "fs_tag"   - tag of the virtiofs device (e.g. "/dev/root").
 *  "path"     - path of the directory (e.g. "dev" or "usr/lib").
 *  "mode"     - directory mode bits (e.g. 040755).
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 *  -EINVAL  - invalid parameters (NULL pointer, empty path component)
 *  -ENOENT  - context, fs_tag, or intermediate path component not found
 *  -ENOTDIR - intermediate path component is not a directory
 */
int32_t krun_fs_add_overlay_dir(uint32_t ctx_id, const char *fs_tag,
                                const char *path, uint32_t mode);

/*
 * Specify the value of `console=` in the kernel commandline.
 *
 * Arguments:
 *  "ctx_id" - the confiugration context ID.
 *  "console_id" - console identifier.
 *
 * Returns
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_set_kernel_console(uint32_t ctx_id, const char *console_id);

/*
 * Adds a virtio-console device to the guest.
 *
 * The function can be called multiple times for adding multiple virtio-console devices.
 * In the guest, the consoles will appear in the same order as they are added (that is,
 * the first added console will be "hvc0", the second "hvc1", ...).
 *
 * This function attaches a multi port virtio-console to the guest. If the input, output and error
 * file descriptors are TTYs, the device will be created with just a single console port (`err_fd`
 * is ignored in this case, because error output just goes to the TTY). For each of the non-TTY file
 * descriptors an additional non-console port is created ("krun-stdin"/"krun-stdout"/"krun-stderr").
 * The libkrun init process in the guest detects the existence of the additional ports and redirects
 * the stdin/stdout/stderr of the application in the guest appropriately.
 *
 * Arguments:
 *  "ctx_id"       - the configuration context ID.
 *  "input_fd"     - file descriptor to use as input for console (Unix).
 *  "input_handle" - HANDLE to use as input for console (Windows).
 *  "output_fd"     - file descriptor to use as output for console (Unix).
 *  "output_handle" - HANDLE to use as output for console (Windows).
 *  "err_fd"        - file descriptor to use as err for console (Unix).
 *  "err_handle"    - HANDLE to use as err for console (Windows).
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_add_virtio_console_default(uint32_t ctx_id,
#ifdef _WIN32
                                        void *input_handle,
                                        void *output_handle,
                                        void *err_handle
#else
                                        int input_fd,
                                        int output_fd,
                                        int err_fd
#endif
                                        );

/*
 * Adds a legacy serial device to the guest.
 *
 * The function can be called multiple times for adding multiple serial devices.
 * In the guest, the consoles will appear in the same order as they are added (that is,
 * the first added console will be "ttyS0", the second "ttyS1", ...).
 *
 * Arguments:
 *  "ctx_id"       - the configuration context ID.
 *  "input_fd"     - file descriptor to use as input for console (Unix).
 *  "input_handle" - HANDLE to use as input for console (Windows).
 *  "output_fd"     - file descriptor to use as output for console (Unix).
 *  "output_handle" - HANDLE to use as output for console (Windows).
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_add_serial_console_default(uint32_t ctx_id,
#ifdef _WIN32
                                        void *input_handle,
                                        void *output_handle
#else
                                        int input_fd,
                                        int output_fd
#endif
                                        );

/*
 * Adds a multi-port virtio-console device to the guest with explicitly configured ports.
 *
 * This function creates a new virtio-console device that can have multiple ports added to it
 * via krun_add_console_port_tty() and krun_add_console_port_inout(). Unlike krun_add_virtio_console_default(),
 * this does not do any automatic detections to configure ports based on the file descriptors.
 *
 * The function can be called multiple times for adding multiple virtio-console devices.
 * Each device appears in the guest with port 0 accessible as /dev/hvcN (hvc0, hvc1, etc.) in the order
 * devices are added. Additional ports within each device
 * (port 1, 2, ...) appear as /dev/vportNpM character devices.
 *
 * Arguments:
 *  "ctx_id" - the configuration context ID.
 *
 * Returns:
 *  The console_id (>= 0) on success or a negative error number on failure.
 */
int32_t krun_add_virtio_console_multiport(uint32_t ctx_id);

/*
 * Adds a TTY port to a multi-port virtio-console device.
 *
 * The TTY file descriptor is used for both input and output. This port will be marked with the
 * VIRTIO_CONSOLE_CONSOLE_PORT flag, enabling console-specific features notably window resize.
 *
 * Arguments:
 *  "ctx_id"     - the configuration context ID
 *  "console_id" - the console ID returned by krun_add_virtio_console_multiport()
 *  "name"       - the name of the port for identifying the port in the guest, can be empty ("")
 *  "tty_fd"     - file descriptor for the TTY to use for both input, output, and determining terminal size (Unix).
 *  "tty_handle" - HANDLE for the TTY to use for both input, output, and determining terminal size (Windows).
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_add_console_port_tty(uint32_t ctx_id,
                                  uint32_t console_id,
                                  const char *name,
#ifdef _WIN32
                                  void *tty_handle
#else
                                  int tty_fd
#endif
                                  );

/*
 * Adds a generic I/O port to a multi-port virtio-console device, suitable for arbitrary bidirectional 
 * data streams that don't require terminal functionality.
 *
 * This port will NOT be marked with the VIRTIO_CONSOLE_CONSOLE_PORT flag, meaning it won't support
 * console-specific features like window resize signals.
 *
 * Arguments:
 *  "ctx_id"     - the configuration context ID
 *  "console_id" - the console ID returned by krun_add_virtio_console_multiport()
 *  "name"       - the name of the port for identifying the port in the guest, can be empty ("")
 *  "input_fd"     - file descriptor to use for input (host writes, guest reads) (Unix).
 *  "input_handle" - HANDLE to use for input (host writes, guest reads) (Windows).
 *  "output_fd"     - file descriptor to use for output (guest writes, host reads) (Unix).
 *  "output_handle" - HANDLE to use for output (guest writes, host reads) (Windows).
 *
 * Returns:
 *  Zero on success or a negative error number on failure.
 */
int32_t krun_add_console_port_inout(uint32_t ctx_id,
                                    uint32_t console_id,
                                    const char *name,
#ifdef _WIN32
                                    void *input_handle,
                                    void *output_handle
#else
                                    int input_fd,
                                    int output_fd
#endif
                                    );

/**
 * Configure block device to be used as root filesystem.
 *
 * Arguments:
 *  "ctx_id" - the configuration context ID.
 *  "device" - a null-terminated string specifying the root device
 *             (e.g. "/dev/vda1", must refer to a previously configured block device)
 *  "fstype" - a null-terminated string specifying the filesystem type (e.g. "ext4", can be set to "auto" or NULL)
 *  "options" - a null-terminated string with a comma-separated list of mount options (can be NULL)
 *
 * Notes:
 *  This function can be used if you want a root filesystem backed by a block device instead of a virtiofs path.
 *  Because libkrun uses its own built-in init process (implemented as a virtual file in the virtiofs driver),
 *  you'd normally have to copy the executable into every filesystem image (or partition) you intend to boot from.
 *  This is obviously difficult to maintain, so instead we can create a dummy virtiofs root behind the scenes,
 *  execute init from it as usual and then switch to the actual root configured by this function.
 */
int32_t krun_set_root_disk_remount(uint32_t ctx_id, const char *device, const char *fstype, const char *options);

/**
 * Starts and enters the microVM with the configured parameters. The VMM will attempt to take over
 * stdin/stdout to manage them on behalf of the process running inside the isolated environment,
 * simulating that the latter has direct control of the terminal.
 *
 * This function consumes the configuration pointed by the context ID.
 *
 * Arguments:
 *  "ctx_id" - the configuration context ID.
 *
 * Notes:
 *  This function only returns if an error happens before starting the microVM. Otherwise, the
 *  VMM assumes it has full control of the process, and will call to exit() with the workload's exit
 *  code once the microVM shuts down. If an error occurred before running the workload the process
 *  will exit() with an error exit code.
 *
 * Error exit codes:
 *  125     - "init" cannot set up the environment inside the microVM.
 *  126     - "init" can find the executable to be run inside the microVM but cannot execute it.
 *  127     - "init" cannot find the executable to be run inside the microVM.
 *
 * Returns:
 *  -EINVAL - The VMM has detected an error in the microVM configuration.
 */
int32_t krun_start_enter(uint32_t ctx_id);

/**
 * Pause a running VM: freeze every vCPU at an instruction boundary. Thread-safe
 * and out-of-band -- call it from a thread other than the one blocked in
 * krun_start_enter(). The freeze completes asynchronously in the VM's event
 * loop; this returns as soon as the request is signalled. Idempotent. Device
 * worker threads are notification-driven, so they idle on their own while the
 * guest is frozen. Currently macOS/HVF only; returns -ENOTSUP elsewhere.
 *
 * Arguments:
 *  "ctx_id" - the configuration context ID of the running VM.
 *
 * Returns:
 *  0        - the pause request was signalled.
 *  -ENOENT  - no running VM is registered for this ctx_id.
 *  -EIO     - failed to signal the VM.
 *  -ENOTSUP - pause is unsupported on this platform.
 */
int32_t krun_vm_pause(uint32_t ctx_id);

/**
 * Resume a VM previously paused with krun_vm_pause(). The guest's virtual timer
 * is advanced by the time spent paused so armed timers do not fire en masse on
 * wake. Thread-safe, out-of-band, and idempotent. Currently macOS/HVF only;
 * returns -ENOTSUP elsewhere.
 *
 * Arguments:
 *  "ctx_id" - the configuration context ID of the paused VM.
 *
 * Returns:
 *  0        - the resume request was signalled.
 *  -ENOENT  - no running VM is registered for this ctx_id.
 *  -EIO     - failed to signal the VM.
 *  -ENOTSUP - resume is unsupported on this platform.
 */
int32_t krun_vm_resume(uint32_t ctx_id);

#ifdef __cplusplus
}
#endif

#endif // _LIBKRUN_H
