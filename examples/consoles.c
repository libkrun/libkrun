#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <libkrun.h>
#include <libkrun_init.h>

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

static int cmd_output(char *output, size_t output_size, const char *prog, ...)
{
    va_list args;
    const char *argv[32];
    int argc = 0;
    int pipe_fds[2] = { -1, -1 };

    argv[argc++] = prog;
    va_start(args, prog);
    while (argc < 31) {
        const char *arg = va_arg(args, const char *);
        argv[argc++] = arg;
        if (arg == NULL) break;
    }
    va_end(args);
    argv[argc] = NULL;

    if (output && output_size > 0) {
        if (pipe(pipe_fds) < 0) return -1;
    }

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (pipe_fds[0] >= 0) {
            close(pipe_fds[0]);
            dup2(pipe_fds[1], STDOUT_FILENO);
            close(pipe_fds[1]);
        }
        execvp(prog, (char *const *)argv);
        abort();
    }

    if (pipe_fds[0] >= 0) {
        close(pipe_fds[1]);
        ssize_t n = read(pipe_fds[0], output, output_size - 1);
        close(pipe_fds[0]);
        if (n < 0) n = 0;
        output[n] = '\0';
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

#define cmd(...) ({ char _d[1]; cmd_output(_d, 0, __VA_ARGS__); })

static int create_tmux_tty(const char *session_name)
{
    char tty_path[256];
    char wait_cmd[128];
    
    snprintf(wait_cmd, sizeof(wait_cmd), "waitpid %d", (int)getpid());
    if (cmd("tmux", "new-session", "-d", "-s", session_name, "sh", "-c", wait_cmd, NULL) != 0)
        return -1;

    // Hook up tmux to send us SIGWINCH signal on resize
    char hook_cmd[128];
    snprintf(hook_cmd, sizeof(hook_cmd), "run-shell 'kill -WINCH %d'", (int)getpid());
    cmd("tmux", "set-hook", "-g", "client-resized", hook_cmd, NULL);

    if (cmd_output(tty_path, sizeof(tty_path), "tmux", "display-message", "-p", "-t", session_name, "#{pane_tty}", NULL) != 0)
        return -1;
    tty_path[strcspn(tty_path, "\n")] = '\0';

    int fd = open(tty_path, O_RDWR);
    if (fd < 0) return -1;
    return fd;
}

static int mkfifo_if_needed(const char *path)
{
    if (mkfifo(path, 0666) < 0) {
        if (errno != EEXIST) return -1;
    }
    return 0;
}


static int create_fifo_inout(const char *fifo_in, const char *fifo_out, int *input_fd, int *output_fd)
{
    if (mkfifo_if_needed(fifo_in) < 0) return -1;
    if (mkfifo_if_needed(fifo_out) < 0) return -1;

    int in_fd = open(fifo_in, O_RDONLY | O_NONBLOCK);
    if (in_fd < 0) return -1;

    int out_fd = open(fifo_out, O_RDWR | O_NONBLOCK);
    if (out_fd < 0) { close(in_fd); return -1; }

    *input_fd = in_fd;
    *output_fd = out_fd;
    return 0;
}

int main(int argc, char *const argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s ROOT_DIR COMMAND [ARGS...]\n", argv[0]);
        return 1;
    }

    const char *root_dir = argv[1];
    const char *command = argv[2];
    const char *const *command_args = (argc > 3) ? (const char *const *)&argv[3] : NULL;
    const char *const envp[] = { 0 };

    KrunError krun_err;
    CHECK(krun_init_log(-1, KRUN_LOG_LEVEL_WARN, KRUN_LOG_STYLE_AUTO, 0, &krun_err));

    // Create the filesystem overlay for init-blob injection.
    KrunFsOverlay overlay = krun_fs_overlay_new();

    // Create the krunfw payload (embedded kernel + init).
    KrunPayload payload = krun_payload_load_krunfw(&krun_err);
    if (!payload) {
        fprintf(stderr, "Error loading krunfw payload\n");
        return 1;
    }

    // Build init configuration.
    {
        KrunInitError err;
        KrunInitBuilder builder = krun_init_config_builder();

        krun_init_builder_arg(&builder, KRUN_STR(command));
        if (command_args) {
            for (int i = 0; command_args[i]; i++)
                krun_init_builder_arg(&builder, KRUN_STR(command_args[i]));
        }

        KrunInitConfig config = krun_init_builder_build(&builder);
        CHECK_INIT(krun_init_config_apply(config, overlay, payload, &err));
    }

    // Create the device manager.
    KrunMmioDeviceManager devices = krun_mmio_device_manager_new();

    /* Configure console ports - edit this section to add/remove ports */
    {
        KrunConsoleBuilder cb = krun_console_device_builder();

        // You could also use the controlling terminal of this process in the guest:
        /*
        uint32_t port_idx;
        int host_tty = open("/dev/tty", O_RDWR);
        CHECK(krun_console_builder_add_tty_port(cb, KRUN_STR("host_tty"), host_tty, &port_idx, &krun_err));
        */

        int num_consoles = 3;
        for (int i = 0; i < num_consoles; i++) {
            char session_name[64];
            char port_name[64];
            snprintf(session_name, sizeof(session_name), "krun-console-%d", i + 1);
            snprintf(port_name, sizeof(port_name), "console-%d", i + 1);

            int tmux_fd = create_tmux_tty(session_name);
            if (tmux_fd < 0) {
                perror("create_tmux_tty");
                return 1;
            }
            uint32_t port_idx;
            CHECK(krun_console_builder_add_tty_port(cb, KRUN_STR(port_name), tmux_fd, &port_idx, &krun_err));
        }

        int in_fd, out_fd;
        if (create_fifo_inout("/tmp/consoles_example_in", "/tmp/consoles_example_out", &in_fd, &out_fd) < 0) {
            perror("create_fifo_inout");
            return 1;
        }
        uint32_t port_idx;
        CHECK(krun_console_builder_add_inout_port(cb, KRUN_STR("fifo_inout"), in_fd, out_fd, &port_idx, &krun_err));

        fprintf(stderr, "\n=== Console ports configured ===\n");
        for (int i = 0; i < num_consoles; i++) {
            fprintf(stderr, "  console-%d: tmux attach -t krun-console-%d\n", i + 1, i + 1);
        }
        fprintf(stderr, "  fifo_inout: /tmp/consoles_example_in (host->guest)\n");
        fprintf(stderr, "  fifo_inout: /tmp/consoles_example_out (guest->host)\n");
        fprintf(stderr, "================================\n\n");

        CHECK(KrunConsoleDevice console = krun_console_builder_build(cb, &krun_err));
        krun_mmio_device_manager_add(devices, console);
    }

    // Configure the root filesystem via virtiofs.
    {
        CHECK(KrunFsDevice rootfs = krun_fs_device_new(KRUN_STR("/dev/root"), KRUN_STR(root_dir), &krun_err));
        krun_fs_device_set_overlay(rootfs, overlay);
        krun_mmio_device_manager_add(devices, rootfs);
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

    CHECK(KrunVmm vmm = krun_vmm_builder_build(&builder, &krun_err));
    krun_vmm_run(vmm);
    return 0;
}
