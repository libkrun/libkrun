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

static KrunVtableHandle stderr_writer = KRUN_VTABLE_HANDLE(
    KRUN_PUSH_STR_TYPE_TAG,
    ((KrunPushStrVtable){ .drop = NULL, .push = push_to_stderr }),
    NULL);

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
    int ret = 1;
    KrunError err = NULL;

    KrunMmioDeviceManager devices = NULL;
    KrunFsDevice rootfs = NULL;
    KrunConsoleBuilder console_builder = NULL;
    KrunConsoleDevice console = NULL;
    KrunPayload payload = NULL;
    KrunVmmBuilder vmm_builder = NULL;
    KrunVmm vmm = NULL;
    KrunFsOverlay overlay = NULL;

    krun_init_log(KRUN_LOG_TARGET_DEFAULT, KRUN_LOG_LEVEL_WARN, KRUN_LOG_STYLE_AUTO, NULL);

    // Load kernel
    payload = krun_payload_load_krunfw(&err);
    if (!payload) {
        fprintf(stderr, "krun_payload_load_krunfw failed\n");
        goto cleanup;
    }

    // Create rootfs
    rootfs = krun_fs_device_new(KRUN_STR("/dev/root"), KRUN_STR(root_dir), &err);
    if (!rootfs) {
        fprintf(stderr, "krun_fs_device_new failed\n");
        goto cleanup;
    }

    // Build init config
    {
        KrunInitError init_err = NULL;
        KrunInitBuilder builder = krun_init_config_builder();
        krun_init_builder_arg(&builder, KRUN_STR(command));
        if (command_args) {
            for (int i = 0; command_args[i]; i++)
                krun_init_builder_arg(&builder, KRUN_STR(command_args[i]));
        }
        KrunInitConfig config = krun_init_builder_build(&builder);
        overlay = krun_fs_overlay_new();
        krun_init_config_apply(config, NULL, overlay, payload, &init_err);
        if (init_err) {
            fprintf(stderr, "krun_init_config_apply failed\n");
            krun_init_error_destroy(init_err);
            goto cleanup;
        }
        krun_fs_device_set_overlay(rootfs, overlay);
        overlay = NULL;
    }

    // Build multiport console
    console_builder = krun_console_device_builder();

    /* Configure console ports - edit this section to add/remove ports */
    {
        int num_consoles = 3;
        for (int i = 0; i < num_consoles; i++) {
            char session_name[64];
            char port_name[64];
            snprintf(session_name, sizeof(session_name), "krun-console-%d", i + 1);
            snprintf(port_name, sizeof(port_name), "console-%d", i + 1);

            int tmux_fd = create_tmux_tty(session_name);
            if (tmux_fd < 0) {
                perror("create_tmux_tty");
                goto cleanup;
            }
            uint32_t port_idx;
            if (krun_console_builder_add_tty_port(console_builder, KRUN_STR(port_name), tmux_fd, &port_idx, &err) != KRUN_RESULT_SUCCESS) {
                fprintf(stderr, "krun_console_builder_add_tty_port failed\n");
                goto cleanup;
            }
        }

        int in_fd, out_fd;
        if (create_fifo_inout("/tmp/consoles_example_in", "/tmp/consoles_example_out", &in_fd, &out_fd) < 0) {
            perror("create_fifo_inout");
            goto cleanup;
        }
        uint32_t port_idx;
        if (krun_console_builder_add_inout_port(console_builder, KRUN_STR("fifo_inout"), in_fd, out_fd, &port_idx, &err) != KRUN_RESULT_SUCCESS) {
            fprintf(stderr, "krun_console_builder_add_inout_port failed\n");
            goto cleanup;
        }

        fprintf(stderr, "\n=== Console ports configured ===\n");
        for (int i = 0; i < num_consoles; i++) {
            fprintf(stderr, "  console-%d: tmux attach -t krun-console-%d\n", i + 1, i + 1);
        }
        fprintf(stderr, "  fifo_inout: /tmp/consoles_example_in (host->guest)\n");
        fprintf(stderr, "  fifo_inout: /tmp/consoles_example_out (guest->host)\n");
        fprintf(stderr, "================================\n\n");
    }

    console = krun_console_builder_build(console_builder, &err);
    if (!console) {
        fprintf(stderr, "krun_console_builder_build failed\n");
        goto cleanup;
    }
    krun_console_builder_destroy(console_builder);
    console_builder = NULL;

    // Device manager
    devices = krun_mmio_device_manager_new();
    krun_mmio_device_manager_add(devices, (KrunAttachDevice)rootfs);
    rootfs = NULL;
    krun_mmio_device_manager_add(devices, (KrunAttachDevice)console);
    console = NULL;

    // Build and run VM
    vmm_builder = krun_vmm_builder_new();
    if (krun_vmm_builder_vcpus(&vmm_builder, 4, &err) != KRUN_RESULT_SUCCESS) goto cleanup;
    if (krun_vmm_builder_ram_mib(&vmm_builder, 4096, &err) != KRUN_RESULT_SUCCESS) goto cleanup;
    krun_vmm_builder_payload(&vmm_builder, payload);
    payload = NULL;
    krun_vmm_builder_devices(&vmm_builder, devices);
    devices = NULL;

    vmm = krun_vmm_builder_build(&vmm_builder, &err);
    if (!vmm) {
        fprintf(stderr, "krun_vmm_builder_build failed\n");
        goto cleanup;
    }

    krun_vmm_run(vmm);
    ret = 0;

cleanup:
    if (err) {
        flockfile(stderr);
        fprintf(stderr, "Error: ");
        krun_error_message(err, (KrunPushStr)&stderr_writer);
        fputc('\n', stderr);
        funlockfile(stderr);
        krun_error_destroy(err);
    }
    if (vmm) krun_vmm_destroy(vmm);
    if (vmm_builder) krun_vmm_builder_destroy(vmm_builder);
    if (devices) krun_mmio_device_manager_destroy(devices);
    if (console_builder) krun_console_builder_destroy(console_builder);
    if (console) krun_console_device_destroy(console);
    if (rootfs) krun_fs_device_destroy(rootfs);
    if (payload) krun_payload_destroy(payload);
    if (overlay) krun_fs_overlay_destroy(overlay);
    return ret;
}
