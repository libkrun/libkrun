/*
 * Guest side of the vsock first-connection latency reproducer.
 *
 * Runs as PID 1 inside a libkrun microVM. Binds AF_VSOCK on port 1234,
 * accepts ITERATIONS connections, and exits — which makes libkrun shut
 * the VM down.
 *
 * Each accepted connection gets exactly one ack byte. The host times
 * connect() + read(1) to measure end-to-end vsock round-trip cost,
 * since the host-side connect() returns as soon as libkrun's
 * UnixAcceptorProxy accepts on the host — NOT when the guest accepts.
 *
 * Built static so it only depends on one file in the rootfs.
 */

#include <errno.h>
#include <linux/vm_sockets.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define VSOCK_PORT 1234
#define ITERATIONS 5

static int die(const char *what)
{
    fprintf(stderr, "guest: %s: %s\n", what, strerror(errno));
    return 1;
}

int main(void)
{
    int s = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (s < 0)
        return die("socket(AF_VSOCK)");

    struct sockaddr_vm a;
    memset(&a, 0, sizeof a);
    a.svm_family = AF_VSOCK;
    a.svm_cid    = VMADDR_CID_ANY;
    a.svm_port   = VSOCK_PORT;

    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0)
        return die("bind");
    if (listen(s, 8) < 0)
        return die("listen");

    fprintf(stderr, "guest: listening on vsock:%u\n", VSOCK_PORT);

    for (int i = 0; i < ITERATIONS; i++) {
        int c = accept(s, NULL, NULL);
        if (c < 0)
            return die("accept");
        char ack = 'a';
        if (write(c, &ack, 1) != 1)
            return die("write ack");
        fprintf(stderr, "guest: accept[%d] ack\n", i);
        close(c);
    }

    close(s);
    return 0;
}
