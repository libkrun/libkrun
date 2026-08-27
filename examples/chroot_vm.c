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

// Virtio device type IDs (for vhost-user)
#define VIRTIO_DEVICE_CONSOLE 3
#define VIRTIO_DEVICE_RNG     4
#define VIRTIO_DEVICE_GPU     16
#define VIRTIO_DEVICE_RTC     17
#define VIRTIO_DEVICE_INPUT   18
#define VIRTIO_DEVICE_VSOCK   19
#define VIRTIO_DEVICE_SND     25
#define VIRTIO_DEVICE_CAN     36
#define VIRTIO_DEVICE_MEDIA   45

// TSI flags
#define TSI_HIJACK_INET (1 << 0)
#define TSI_HIJACK_UNIX (1 << 1)

// Net feature flags
#define COMPAT_NET_FEATURES ((1 << 0) | (1 << 1) | (1 << 7) | (1 << 10) | (1 << 11) | (1 << 14))

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

// CHECK_INIT macro for init-blob errors (KrunInitError)
static KrunVtableHandle stderr_writer = KRUN_VTABLE_HANDLE(
    KRUN_INIT_PUSH_STR_TYPE_TAG,
    ((KrunInitPushStrVtable){ .drop = NULL, .push = push_to_stderr }),
    NULL);

#define CHECK_INIT(call)                                                       \
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

// CHECK macro for libkrun errors (KrunError)
static KrunVtableHandle krun_stderr_writer = KRUN_VTABLE_HANDLE(
    KRUN_PUSH_STR_TYPE_TAG,
    ((KrunPushStrVtable){ .drop = NULL, .push = push_to_stderr }),
    NULL);

#define CHECK(call)                                                            \
    krun_err = NULL;                                                           \
    call;                                                                      \
    if (krun_err) {                                                            \
        flockfile(stderr);                                                     \
        fprintf(stderr, "%s failed: ", #call);                                 \
        krun_error_message(krun_err, &krun_stderr_writer);                     \
        fputc('\n', stderr);                                                   \
        funlockfile(stderr);                                                   \
        krun_error_destroy(krun_err);                                          \
        return -1;                                                             \
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
        .new_root = NULL,
        .guest_argv = NULL,
        .log_target = -1,
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
    const char *const rlimits[] =
    {
        // RLIMIT_NPROC = 6
        "6=4096:8192",
        0
    };
    KrunError krun_err;
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
    CHECK(krun_init_log(cmdline.log_target, KRUN_LOG_LEVEL_WARN, cmdline.log_style, 0, &krun_err));

    // Create the filesystem overlay for init-blob injection.
    KrunFsOverlay overlay = krun_fs_overlay_new();

    // Create the krunfw payload (embedded kernel + init).
    KrunPayload payload = krun_payload_load_krunfw(&krun_err);
    if (!payload) {
        fprintf(stderr, "Error loading krunfw payload\n");
        return -1;
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
        CHECK_INIT(krun_init_config_apply(config, overlay, payload, &err));
    }

    // Create the device manager.
    KrunMmioDeviceManager devices = krun_mmio_device_manager_new();

    // Configure the console.
    {
        KrunConsoleBuilder cb = krun_console_device_builder();
        CHECK(krun_console_builder_add_default_console(cb, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, &krun_err));
        KrunConsoleDevice console = krun_console_builder_build(cb, &krun_err);
        krun_mmio_device_manager_add(devices, console);
    }

    // Configure vhost-user RNG if requested
    if (cmdline.vhost_user_rng_socket != NULL) {
        // Auto-detect queue count; use custom queue size of 512
        uint16_t custom_sizes[] = {512};
        CHECK(KrunVhostUserDevice rng = krun_vhost_user_device_new(VIRTIO_DEVICE_RNG,
            KRUN_STR(cmdline.vhost_user_rng_socket), KRUN_STR(""), 0, custom_sizes, 1, &krun_err));
        krun_mmio_device_manager_add(devices, rng);
        printf("Using vhost-user RNG backend at %s (custom queue size: 512)\n", cmdline.vhost_user_rng_socket);
    }

    // Configure vhost-user RTC if requested
    if (cmdline.vhost_user_rtc_socket != NULL) {
        CHECK(KrunVhostUserDevice rtc = krun_vhost_user_device_new(VIRTIO_DEVICE_RTC,
            KRUN_STR(cmdline.vhost_user_rtc_socket), KRUN_STR(""), 0, NULL, 0, &krun_err));
        krun_mmio_device_manager_add(devices, rtc);
        printf("Using vhost-user RTC backend at %s (available as /dev/ptp* and /dev/rtc* in guest)\n", cmdline.vhost_user_rtc_socket);
    }

    // Configure vhost-user input if requested
    if (cmdline.vhost_user_input_socket != NULL) {
        CHECK(KrunVhostUserDevice input = krun_vhost_user_device_new(VIRTIO_DEVICE_INPUT,
            KRUN_STR(cmdline.vhost_user_input_socket), KRUN_STR(""), 0, NULL, 0, &krun_err));
        krun_mmio_device_manager_add(devices, input);
        printf("Using vhost-user input backend at %s\n", cmdline.vhost_user_input_socket);
    }

    // Configure vhost-user GPU if requested.
    // NOTE: The built-in GPU (krun_set_gpu_options) has been removed — v2 requires a
    // DisplayBackend vtable handle which can't be constructed from C without a display
    // backend implementation. Use vhost-user GPU as the only GPU path from C.
    if (cmdline.vhost_user_gpu_socket != NULL) {
        CHECK(KrunVhostUserDevice gpu = krun_vhost_user_device_new(VIRTIO_DEVICE_GPU,
            KRUN_STR(cmdline.vhost_user_gpu_socket), KRUN_STR(""), 0, NULL, 0, &krun_err));
        krun_mmio_device_manager_add(devices, gpu);
        printf("Using vhost-user GPU backend at %s\n", cmdline.vhost_user_gpu_socket);
    }

    // Configure vhost-user sound if requested
    if (cmdline.vhost_user_snd_socket != NULL) {
        CHECK(KrunVhostUserDevice snd = krun_vhost_user_device_new(VIRTIO_DEVICE_SND,
            KRUN_STR(cmdline.vhost_user_snd_socket), KRUN_STR(""), 0, NULL, 0, &krun_err));
        krun_mmio_device_manager_add(devices, snd);
        printf("Using vhost-user sound backend at %s\n", cmdline.vhost_user_snd_socket);
    }

    // Configure vsock: either vhost-user or built-in with TSI
    if (cmdline.vhost_user_vsock_socket != NULL) {
        CHECK(KrunVhostUserDevice vsock_vu = krun_vhost_user_device_new(VIRTIO_DEVICE_VSOCK,
            KRUN_STR(cmdline.vhost_user_vsock_socket), KRUN_STR(""), 0, NULL, 0, &krun_err));
        krun_mmio_device_manager_add(devices, vsock_vu);
        printf("Using vhost-user vsock backend at %s\n", cmdline.vhost_user_vsock_socket);
    }

    // Configure vhost-user CAN if requested
    if (cmdline.vhost_user_can_socket != NULL) {
        CHECK(KrunVhostUserDevice can = krun_vhost_user_device_new(VIRTIO_DEVICE_CAN,
            KRUN_STR(cmdline.vhost_user_can_socket), KRUN_STR(""), 0, NULL, 0, &krun_err));
        krun_mmio_device_manager_add(devices, can);
        printf("Using vhost-user CAN backend at %s\n", cmdline.vhost_user_can_socket);
    }

    // Configure vhost-user console if requested
    if (cmdline.vhost_user_console_socket != NULL) {
        CHECK(KrunVhostUserDevice vu_console = krun_vhost_user_device_new(VIRTIO_DEVICE_CONSOLE,
            KRUN_STR(cmdline.vhost_user_console_socket), KRUN_STR(""), 0, NULL, 0, &krun_err));
        krun_mmio_device_manager_add(devices, vu_console);
        printf("Using vhost-user console backend at %s (available as /dev/hvc1 in guest)\n", cmdline.vhost_user_console_socket);
        printf("Test with: echo 'hello' > /dev/hvc1\n");
    }

    // Configure vhost-user media if requested
    if (cmdline.vhost_user_media_socket != NULL) {
        CHECK(KrunVhostUserDevice media = krun_vhost_user_device_new(VIRTIO_DEVICE_MEDIA,
            KRUN_STR(cmdline.vhost_user_media_socket), KRUN_STR(""), 0, NULL, 0, &krun_err));
        krun_mmio_device_manager_add(devices, media);
        printf("Using vhost-user media backend at %s\n", cmdline.vhost_user_media_socket);
    }

    // Raise RLIMIT_NOFILE to the maximum allowed to create some room for virtio-fs
    getrlimit(RLIMIT_NOFILE, &rlim);
    rlim.rlim_cur = rlim.rlim_max;
    setrlimit(RLIMIT_NOFILE, &rlim);

    // Configure the root filesystem via virtiofs.
    {
        CHECK(KrunFsDevice rootfs = krun_fs_device_new(KRUN_STR("/dev/root"), KRUN_STR(cmdline.new_root), &krun_err));
        krun_fs_device_set_overlay(rootfs, overlay);
        krun_mmio_device_manager_add(devices, rootfs);
    }

    // Add built-in vsock with TSI when not using vhost-user-vsock
    if (cmdline.vhost_user_vsock_socket == NULL) {
        CHECK(KrunVsockDevice vsock = krun_vsock_device_new(3, TSI_HIJACK_INET | TSI_HIJACK_UNIX, &krun_err));

        // Map port 18000 in the host to 8000 in the guest (if networking uses TSI)
        if (cmdline.net_mode == NET_MODE_TSI) {
            CHECK(krun_vsock_device_add_port_forward(vsock, KRUN_STR("18000:8000"), &krun_err));
        }

        krun_mmio_device_manager_add(devices, vsock);
    }

    // Configure network
    if (cmdline.net_mode == NET_MODE_PASST || cmdline.vhost_user_vsock_socket != NULL) {
        uint8_t mac[] = {0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee};
        KrunNetDevice net;
        if (cmdline.passt_socket_path != NULL) {
            net = krun_net_device_new_unixstream_path(KRUN_STR("net0"),
                KRUN_STR(cmdline.passt_socket_path), KRUN_BYTES(mac), COMPAT_NET_FEATURES, 0, &krun_err);
        } else {
            int passt_fd = start_passt();
            if (passt_fd < 0) {
                return -1;
            }
            net = krun_net_device_new_unixstream_fd(KRUN_STR("net0"),
                passt_fd, KRUN_BYTES(mac), COMPAT_NET_FEATURES, 0, &krun_err);
        }
        if (krun_err) {
            fprintf(stderr, "Error configuring net mode\n");
            krun_error_destroy(krun_err);
            return -1;
        }
        krun_mmio_device_manager_add(devices, net);
    }

    {
        CHECK(KrunRngDevice rng = krun_rng_device_new(&krun_err));
        krun_mmio_device_manager_add(devices, rng);

        CHECK(KrunBalloonDevice balloon = krun_balloon_device_new(&krun_err));
        krun_mmio_device_manager_add(devices, balloon);
    }

    // Build the VM.
    KrunVmmBuilder builder = krun_vmm_builder_new();
    CHECK(krun_vmm_builder_vcpus(&builder, 4, &krun_err));
    CHECK(krun_vmm_builder_ram_mib(&builder, 4096, &krun_err));
    krun_vmm_builder_payload(&builder, payload);
    krun_vmm_builder_devices(&builder, devices);
    CHECK(krun_vmm_builder_split_irqchip(&builder, false, &krun_err));

    CHECK(KrunVmm vmm = krun_vmm_builder_build(&builder, &krun_err));
    krun_vmm_run(vmm); // never returns

    // Not reached.
    return 0;
}
