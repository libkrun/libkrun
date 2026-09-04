/*
 * This is an example implementing chroot-like functionality with libkrun.
 *
 * It executes the requested command (relative to NEWROOT) inside a fresh
 * Virtual Machine created and managed by libkrun.
 */

#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <libkrun.h>
#include <libkrun_init.h>
#include <getopt.h>
#include <stdbool.h>
#include <assert.h>

#define MAX_ARGS_LEN 4096
#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

enum net_mode {
    NET_MODE_PASST = 0,
    NET_MODE_TSI,
};

static void print_help(char *const name)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS] NEWROOT COMMAND [COMMAND_ARGS...]\n"
        "OPTIONS: \n"
        "        -h    --help                Show help\n"
        "              --log=PATH            Write libkrun log to file or named pipe at PATH\n"
        "              --color-log=PATH      Write libkrun log to file or named pipe at PATH, use color\n"
        "              --net=NET_MODE        Set network mode\n"
        "              --passt-socket=PATH   Instead of starting passt, connect to passt socket at PATH\n"
        "              --vhost-user-rng=PATH Use vhost-user RNG backend at socket PATH\n"
        "              --vhost-user-rtc=PATH Use vhost-user RTC backend at socket PATH\n"
        "              --vhost-user-input=PATH Use vhost-user input backend at socket PATH\n"
        "              --vhost-user-gpu=PATH Use vhost-user GPU backend at socket PATH\n"
        "              --vhost-user-snd=PATH Use vhost-user sound backend at socket PATH\n"
        "              --vhost-user-vsock=PATH Use vhost-user vsock backend at socket PATH\n"
        "              --vhost-user-can=PATH Use vhost-user CAN backend at socket PATH\n"
        "              --vhost-user-console=PATH Use vhost-user console backend at socket PATH\n"
        "              --virtio-pci            Use virtio-pci instead of virtio-mmio\n"
        "NET_MODE can be either TSI (default) or PASST\n"
        "\n"
        "NEWROOT:      the root directory of the vm\n"
        "COMMAND:      the command you want to execute in the vm\n"
        "COMMAND_ARGS: arguments of COMMAND\n",
        name
    );
}

static bool push_to_stderr(void *userdata, KrunStr s)
{
    (void)userdata;
    fwrite(s.data, 1, s.len, stderr);
    return true;
}

static KrunVtableHandle stderr_writer = KRUN_VTABLE_HANDLE(
    KRUN_INIT_PUSH_STR_TYPE_TAG,
    ((KrunInitPushStrVtable){ .drop = NULL, .push = push_to_stderr }),
    NULL);

#define TRY(call)                                                              \
    err = NULL;                                                                \
    call;                                                                      \
    if (err) {                                                                 \
        flockfile(stderr);                                                     \
        fprintf(stderr, "%s failed: ", #call);                                 \
        krun_init_error_message(err, &stderr_writer);                          \
        fputc('\n', stderr);                                                   \
        funlockfile(stderr);                                                   \
        krun_init_error_destroy(err);                                          \
        return -1;                                                             \
    }

static bool check_krun_error(int err, const char *msg)
{
    if (err) {
        errno = -err;
        perror(msg);
        return false;
    }
    return true;
}

static const struct option long_options[] = {
    { "help", no_argument, NULL, 'h' },
    { "log", required_argument, NULL, 'L' },
    { "color-log", required_argument, NULL, 'C' },
    { "net_mode", required_argument, NULL, 'N' },
    { "passt-socket", required_argument, NULL, 'P' },
    { "vhost-user-rng", required_argument, NULL, 'V' },
    { "vhost-user-rtc", required_argument, NULL, 'R' },
    { "vhost-user-input", required_argument, NULL, 'I' },
    { "vhost-user-gpu", required_argument, NULL, 'G' },
    { "vhost-user-snd", required_argument, NULL, 'S' },
    { "vhost-user-vsock", required_argument, NULL, 'K' },
    { "vhost-user-can", required_argument, NULL, 'A' },
    { "vhost-user-console", required_argument, NULL, 'O' },
    { "vhost-user-media", required_argument, NULL, 'M' },
    { "virtio-pci", no_argument, NULL, 'T' },
    { NULL, 0, NULL, 0 }
};

struct cmdline {
    bool show_help;
    int log_target;
    uint32_t log_style;
    enum net_mode net_mode;
    char const *passt_socket_path;
    char const *vhost_user_rng_socket;
    char const *vhost_user_rtc_socket;
    char const *vhost_user_input_socket;
    char const *vhost_user_gpu_socket;
    char const *vhost_user_snd_socket;
    char const *vhost_user_vsock_socket;
    char const *vhost_user_can_socket;
    char const *vhost_user_console_socket;
    char const *vhost_user_media_socket;
    bool virtio_pci;
    char const *new_root;
    char *const *guest_argv;
};

bool cmdline_set_log_target(struct cmdline *cmdline, const char *arg) {
    int fd = open(arg, O_WRONLY);
    if (fd < 0) {
        perror(arg);
        return false;
    }
    if (cmdline->log_target > 0) {
        close(cmdline->log_target);
    }
    cmdline->log_target = fd;
    return true;
}

bool parse_cmdline(int argc, char *const argv[], struct cmdline *cmdline)
{
    assert(cmdline != NULL);

    // set the defaults
    *cmdline = (struct cmdline){
        .show_help = false,
        .net_mode = NET_MODE_TSI,
        .passt_socket_path = NULL,
        .vhost_user_rng_socket = NULL,
        .vhost_user_rtc_socket = NULL,
        .vhost_user_input_socket = NULL,
        .vhost_user_gpu_socket = NULL,
        .vhost_user_snd_socket = NULL,
        .vhost_user_vsock_socket = NULL,
        .vhost_user_can_socket = NULL,
        .vhost_user_console_socket = NULL,
        .vhost_user_media_socket = NULL,
        .virtio_pci = false,
        .new_root = NULL,
        .guest_argv = NULL,
        .log_target = KRUN_LOG_TARGET_DEFAULT,
        .log_style = KRUN_LOG_STYLE_AUTO
    };

    int option_index = 0;
    int c;
    // the '+' in optstring is a GNU extension that disables permutating argv
    while ((c = getopt_long(argc, argv, "+h", long_options, &option_index)) != -1) {
        switch (c) {
        case 'h':
            cmdline->show_help = true;
            return true;
        case 'C':
            cmdline->log_style = KRUN_LOG_STYLE_ALWAYS;
            /* fall through */
        case 'L':
            if (!cmdline_set_log_target(cmdline, optarg)) {
                return false;
            }
            break;
        case 'N':
            if (strcasecmp("TSI", optarg) == 0) {
                cmdline->net_mode = NET_MODE_TSI;
            } else if(strcasecmp("PASST", optarg) == 0) {
                cmdline->net_mode = NET_MODE_PASST;
            } else {
                fprintf(stderr, "Unknown mode %s\n", optarg);
                return false;
            }
            break;
        case 'P':
            cmdline->passt_socket_path = optarg;
            break;
        case 'V':
            cmdline->vhost_user_rng_socket = optarg;
            break;
        case 'R':
            cmdline->vhost_user_rtc_socket = optarg;
            break;
        case 'I':
            cmdline->vhost_user_input_socket = optarg;
            break;
        case 'G':
            cmdline->vhost_user_gpu_socket = optarg;
            break;
        case 'S':
            cmdline->vhost_user_snd_socket = optarg;
            break;
        case 'K':
            cmdline->vhost_user_vsock_socket = optarg;
            break;
        case 'A':
            cmdline->vhost_user_can_socket = optarg;
            break;
        case 'O':
            cmdline->vhost_user_console_socket = optarg;
            break;
        case 'M':
            cmdline->vhost_user_media_socket = optarg;
            break;
        case 'T':
            cmdline->virtio_pci = true;
            break;
        case '?':
            return false;
        default:
            fprintf(stderr, "internal argument parsing error (returned character code 0x%x)\n", c);
            return false;
        }
    }

    if (optind <= argc - 2) {
        cmdline->new_root = argv[optind];
        cmdline->guest_argv = &argv[optind + 1];
        return true;
    }

    if (optind >= argc - 1) {
        fprintf(stderr, "Missing COMMAND argument\n");
    }

    if (optind == argc) {
        fprintf(stderr, "Missing NEWROOT argument\n");
    }

    return false;
}

int start_passt()
{
    int socket_fds[2];
    const int PARENT = 0;
    const int CHILD = 1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds) < 0) {
        perror("Failed to create passt socket fd");
        return -1;
    }

    int pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) { // child
        if (close(socket_fds[PARENT]) < 0) {
            perror("close PARENT");
        }

        char fd_as_str[16];
        snprintf(fd_as_str, sizeof(fd_as_str), "%d", socket_fds[CHILD]);

        printf("passing fd %s to passt", fd_as_str);

        if (execlp("passt", "passt", "-f", "--fd", fd_as_str, NULL) < 0) {
            perror("execlp");
            return -1;
        }

    } else { // parent
        if (close(socket_fds[CHILD]) < 0) {
            perror("close CHILD");
        }

        return socket_fds[PARENT];
    }
}


int main(int argc, char *const argv[])
{
    const char *const envp[] =
    {
        "TEST=works",
        0
    };
    const char *const port_map[] =
    {
        "18000:8000",
        0
    };
    const char *const rlimits[] =
    {
        // RLIMIT_NPROC = 6
        "6=4096:8192",
        0
    };
    int ctx_id;
    int err;
    int i;
    struct cmdline cmdline;
    struct rlimit rlim;

    if (!parse_cmdline(argc, argv, &cmdline)) {
        putchar('\n');
        print_help(argv[0]);
        return -1;
    }

    if (cmdline.show_help){
        print_help(argv[0]);
        return 0;
    }

    // Set the log level to "warn".
    err = krun_init_log(cmdline.log_target, KRUN_LOG_LEVEL_WARN, cmdline.log_style, 0);
    if (err) {
        errno = -err;
        perror("Error configuring log level");
        return -1;
    }

    // Create the configuration context.
    ctx_id = krun_create_ctx();
    if (ctx_id < 0) {
        errno = -ctx_id;
        perror("Error creating configuration context");
        return -1;
    }

    // Configure the number of vCPUs (4) and the amount of RAM (4096 MiB).
    if (err = krun_set_vm_config(ctx_id, 4, 4096)) {
        errno = -err;
        perror("Error configuring the number of vCPUs and/or the amount of RAM");
        return -1;
    }

    if (cmdline.virtio_pci) {
        if (err = krun_set_virtio_transport(ctx_id, KRUN_VIRTIO_PCI_TRNSPT)) {
            errno = -err;
            perror("Error configuring virtio-pci transport");
            return -1;
        }
    }

    if (err = krun_add_virtio_console_default(ctx_id, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO)) {
        errno = -err;
        perror("Error configuring console");
        return -1;
    }

    // Configure vhost-user RNG if requested
    if (cmdline.vhost_user_rng_socket != NULL) {
        // Test sentinel-terminated array: auto-detect queue count, use custom size
        uint16_t custom_sizes[] = {512, 0};  // 0 = sentinel terminator

        if (!check_krun_error(krun_add_vhost_user_device(ctx_id, KRUN_VIRTIO_DEVICE_RNG,
                                                          cmdline.vhost_user_rng_socket, NULL, 0, custom_sizes, 0),
                              "Error adding vhost-user RNG device")) {
            return -1;
        }
        printf("Using vhost-user RNG backend at %s (custom queue size: 512)\n", cmdline.vhost_user_rng_socket);
    }

    // Configure vhost-user RTC if requested
    if (cmdline.vhost_user_rtc_socket != NULL) {
        if (!check_krun_error(krun_add_vhost_user_device(ctx_id, KRUN_VIRTIO_DEVICE_RTC,
                                                          cmdline.vhost_user_rtc_socket, NULL,
                                                          KRUN_VHOST_USER_RTC_NUM_QUEUES,
                                                          KRUN_VHOST_USER_RTC_QUEUE_SIZES, 0),
                              "Error adding vhost-user RTC device")) {
            return -1;
        }
        printf("Using vhost-user RTC backend at %s (available as /dev/ptp* and /dev/rtc* in guest)\n", cmdline.vhost_user_rtc_socket);
    }

    // Configure vhost-user input if requested
    if (cmdline.vhost_user_input_socket != NULL) {
        if (!check_krun_error(krun_add_vhost_user_device(ctx_id, KRUN_VIRTIO_DEVICE_INPUT,
                                                          cmdline.vhost_user_input_socket, NULL,
                                                          KRUN_VHOST_USER_INPUT_NUM_QUEUES,
                                                          KRUN_VHOST_USER_INPUT_QUEUE_SIZES, 0),
                              "Error adding vhost-user input device")) {
            return -1;
        }
        printf("Using vhost-user input backend at %s\n", cmdline.vhost_user_input_socket);
    }

    // Configure vhost-user GPU if requested
    if (cmdline.vhost_user_gpu_socket != NULL) {
        if (!check_krun_error(krun_add_vhost_user_device(ctx_id, KRUN_VIRTIO_DEVICE_GPU,
                                                          cmdline.vhost_user_gpu_socket, NULL,
                                                          KRUN_VHOST_USER_GPU_NUM_QUEUES,
                                                          KRUN_VHOST_USER_GPU_QUEUE_SIZES,
                                                          KRUN_VHOST_USER_GPU_SHM_SIZE),
                              "Error adding vhost-user GPU device")) {
            return -1;
        }
        printf("Using vhost-user GPU backend at %s (built-in GPU disabled)\n", cmdline.vhost_user_gpu_socket);
    }

    // Configure vhost-user sound if requested
    if (cmdline.vhost_user_snd_socket != NULL) {
        if (!check_krun_error(krun_add_vhost_user_device(ctx_id, KRUN_VIRTIO_DEVICE_SND,
                                                          cmdline.vhost_user_snd_socket, NULL,
                                                          KRUN_VHOST_USER_SND_NUM_QUEUES,
                                                          KRUN_VHOST_USER_SND_QUEUE_SIZES, 0),
                              "Error adding vhost-user sound device")) {
            return -1;
        }
        printf("Using vhost-user sound backend at %s\n", cmdline.vhost_user_snd_socket);
    }

    // Configure vsock: either vhost-user or built-in with TSI
    if (cmdline.vhost_user_vsock_socket != NULL) {
        if (!check_krun_error(krun_add_vhost_user_device(ctx_id, KRUN_VIRTIO_DEVICE_VSOCK,
                                                          cmdline.vhost_user_vsock_socket, NULL,
                                                          KRUN_VHOST_USER_VSOCK_NUM_QUEUES,
                                                          KRUN_VHOST_USER_VSOCK_QUEUE_SIZES, 0),
                              "Error adding vhost-user vsock device")) {
            return -1;
        }
        printf("Using vhost-user vsock backend at %s\n", cmdline.vhost_user_vsock_socket);
    }

    // Configure vhost-user CAN if requested
    if (cmdline.vhost_user_can_socket != NULL) {
        if (!check_krun_error(krun_add_vhost_user_device(ctx_id, KRUN_VIRTIO_DEVICE_CAN,
                                                          cmdline.vhost_user_can_socket, NULL,
                                                          KRUN_VHOST_USER_CAN_NUM_QUEUES,
                                                          KRUN_VHOST_USER_CAN_QUEUE_SIZES, 0),
                              "Error adding vhost-user CAN device")) {
            return -1;
        }
        printf("Using vhost-user CAN backend at %s\n", cmdline.vhost_user_can_socket);
    }

    // Configure vhost-user console if requested
    if (cmdline.vhost_user_console_socket != NULL) {
        if (!check_krun_error(krun_add_vhost_user_device(ctx_id, KRUN_VIRTIO_DEVICE_CONSOLE,
                                                          cmdline.vhost_user_console_socket, NULL,
                                                          KRUN_VHOST_USER_CONSOLE_NUM_QUEUES,
                                                          KRUN_VHOST_USER_CONSOLE_QUEUE_SIZES, 0),
                              "Error adding vhost-user console device")) {
            return -1;
        }
        printf("Using vhost-user console backend at %s (available as /dev/hvc1 in guest)\n", cmdline.vhost_user_console_socket);
        printf("Test with: echo 'hello' > /dev/hvc1\n");
    }

    // Configure vhost-user media if requested
    if (cmdline.vhost_user_media_socket != NULL) {
        if (!check_krun_error(krun_add_vhost_user_device(ctx_id, KRUN_VIRTIO_DEVICE_MEDIA,
                                                          cmdline.vhost_user_media_socket, NULL,
                                                          KRUN_VHOST_USER_MEDIA_NUM_QUEUES,
                                                          KRUN_VHOST_USER_MEDIA_QUEUE_SIZES,
                                                          KRUN_VHOST_USER_MEDIA_SHM_SIZE),
                              "Error adding vhost-user media device")) {
            return -1;
        }
        printf("Using vhost-user media backend at %s\n", cmdline.vhost_user_media_socket);
    }

    // Raise RLIMIT_NOFILE to the maximum allowed to create some room for virtio-fs
    getrlimit(RLIMIT_NOFILE, &rlim);
    rlim.rlim_cur = rlim.rlim_max;
    setrlimit(RLIMIT_NOFILE, &rlim);

    if (err = krun_add_virtiofs3(ctx_id, KRUN_FS_ROOT_TAG, cmdline.new_root, 0, false)) {
        errno = -err;
        perror("Error configuring root path");
        return -1;
    }

    // Only enable built-in GPU if not using vhost-user GPU
    if (cmdline.vhost_user_gpu_socket == NULL) {
        uint32_t virgl_flags = VIRGLRENDERER_USE_EGL | VIRGLRENDERER_DRM |
            VIRGLRENDERER_THREAD_SYNC | VIRGLRENDERER_USE_ASYNC_FENCE_CB;
        if (err = krun_set_gpu_options(ctx_id, virgl_flags)) {
            errno = -err;
            perror("Error configuring gpu");
            return -1;
        }
    }

    // Add built-in vsock with TSI when not using vhost-user-vsock
    if (cmdline.vhost_user_vsock_socket == NULL) {
        if (err = krun_add_vsock(ctx_id, KRUN_TSI_HIJACK_INET | KRUN_TSI_HIJACK_UNIX)) {
            errno = -err;
            perror("Error configuring vsock");
            return -1;
        }
    }

    // Map port 18000 in the host to 8000 in the guest (if networking uses TSI)
    if (cmdline.net_mode == NET_MODE_TSI && cmdline.vhost_user_vsock_socket == NULL) {
        if (err = krun_set_port_map(ctx_id, &port_map[0])) {
            errno = -err;
            perror("Error configuring port map");
            return -1;
        }
    } else {
        uint8_t mac[] = {0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee};
        if (cmdline.passt_socket_path != NULL) {
            if (err = krun_add_net_unixstream(ctx_id, cmdline.passt_socket_path, -1, &mac[0], COMPAT_NET_FEATURES, 0)) {
                errno = -err;
                perror("Error configuring net mode");
                return -1;
            }
        } else {
            int passt_fd = start_passt();

            if (passt_fd < 0) {
                return -1;
            }

            if (err = krun_add_net_unixstream(ctx_id, NULL, passt_fd, &mac[0], COMPAT_NET_FEATURES, 0)) {
                errno = -err;
                perror("Error configuring net mode");
                return -1;
            }
        }
    }

    // Build the init configuration (executable, args, env, workdir, rlimits).
    {
        KrunInitError err;
        KrunInitBuilder builder = krun_init_config_builder();

        for (int i = 0; cmdline.guest_argv[i]; i++)
            krun_init_builder_arg(&builder, KRUN_STR(cmdline.guest_argv[i]));
        for (int i = 0; envp[i]; i++)
            krun_init_builder_env_var(&builder, KRUN_STR(envp[i]));
        for (int i = 0; rlimits[i]; i++)
            krun_init_builder_rlimit(&builder, KRUN_STR(rlimits[i]));
        krun_init_builder_workdir(&builder, KRUN_STR("/"));

        KrunInitConfig config = krun_init_builder_build(&builder);
        TRY(krun_init_config_apply(config, NULL, ctx_id,
                                   KRUN_STR("/dev/root"), &err));
    }

    if (err = krun_split_irqchip(ctx_id, false)) {
        errno = -err;
        perror("Error setting split IRQCHIP property");
        return -1;
    }

    // Start and enter the microVM. Unless there is some error while creating the microVM
    // this function never returns.
    if (err = krun_start_enter(ctx_id)) {
        errno = -err;
        perror("Error creating the microVM");
        return -1;
    }

    // Not reached.
    return 0;
}
