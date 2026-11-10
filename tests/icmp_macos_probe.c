#define __APPLE_USE_RFC_3542
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static unsigned checksum(const unsigned char *data, size_t size)
{
    unsigned sum = 0;
    for (size_t i = 0; i < size; i += 2)
        sum += (unsigned)data[i] << 8 | (i + 1 < size ? data[i + 1] : 0);
    while (sum >> 16)
        sum = (sum & 65535) + (sum >> 16);
    return (~sum) & 65535;
}

static void option(int fd, int level, int name, const char *label)
{
    int value = 1;
    errno = 0;
    int result = setsockopt(fd, level, name, &value, sizeof(value));
    printf("option %s result=%d errno=%d\n", label, result, errno);
}

static void name(int fd, int peer)
{
    struct sockaddr_storage address;
    socklen_t size = sizeof(address);
    errno = 0;
    int result = peer ? getpeername(fd, (void *)&address, &size)
                      : getsockname(fd, (void *)&address, &size);
    printf("%s result=%d errno=%d len=%u", peer ? "peer" : "local", result, errno, size);
    if (result == 0) {
        char ip[INET6_ADDRSTRLEN];
        if (address.ss_family == AF_INET) {
            struct sockaddr_in *a = (void *)&address;
            inet_ntop(AF_INET, &a->sin_addr, ip, sizeof(ip));
            printf(" ip=%s port=%u", ip, ntohs(a->sin_port));
        } else {
            struct sockaddr_in6 *a = (void *)&address;
            inet_ntop(AF_INET6, &a->sin6_addr, ip, sizeof(ip));
            printf(" ip=%s port=%u scope=%u", ip, ntohs(a->sin6_port), a->sin6_scope_id);
        }
    }
    putchar('\n');
}

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void probe(int family, int connected, int bound, int collide, int strip, int tiny)
{
    printf("CASE family=%d connected=%d bind=%d collision=%d strip=%d tiny=%d\n",
           family, connected, bound, collide, strip, tiny);
    struct sockaddr_storage target = {0};
    socklen_t target_len;
    if (family == AF_INET) {
        struct sockaddr_in *a = (void *)&target;
        a->sin_len = sizeof(*a);
        a->sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &a->sin_addr);
        target_len = sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (void *)&target;
        a->sin6_len = sizeof(*a);
        a->sin6_family = AF_INET6;
        const char *ip = getenv("TSI_PROBE_IPV6");
        inet_pton(AF_INET6, ip ? ip : "::1", &a->sin6_addr);
        target_len = sizeof(*a);
    }
    struct pollfd sockets[2];
    unsigned own[2] = {0}, foreign[2] = {0};
    for (int i = 0; i < 2; ++i) {
        errno = 0;
        int fd = socket(family, SOCK_DGRAM, family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6);
        printf("socket index=%d fd=%d errno=%d\n", i, fd, errno);
        sockets[i] = (struct pollfd){.fd = fd, .events = POLLIN};
        if (fd < 0)
            continue;
        if (family == AF_INET) {
            option(fd, IPPROTO_IP, IP_PKTINFO, "IP_PKTINFO");
            option(fd, IPPROTO_IP, IP_RECVDSTADDR, "IP_RECVDSTADDR");
            option(fd, IPPROTO_IP, IP_RECVIF, "IP_RECVIF");
            option(fd, IPPROTO_IP, IP_RECVTTL, "IP_RECVTTL");
            if (strip)
                option(fd, IPPROTO_IP, IP_STRIPHDR, "IP_STRIPHDR");
        } else {
            option(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, "IPV6_RECVPKTINFO");
            option(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, "IPV6_RECVHOPLIMIT");
        }
        if (bound >= 0) {
            struct sockaddr_storage local = target;
            if (family == AF_INET)
                ((struct sockaddr_in *)&local)->sin_port = htons(bound);
            else
                ((struct sockaddr_in6 *)&local)->sin6_port = htons(bound);
            errno = 0;
            int result = bind(fd, (void *)&local, target_len);
            printf("bind index=%d result=%d errno=%d\n", i, result, errno);
        }
        if (connected) {
            errno = 0;
            int result = connect(fd, (void *)&target, target_len);
            printf("connect index=%d result=%d errno=%d\n", i, result, errno);
        }
        name(fd, 0);
        name(fd, 1);
    }
    for (int i = 0; i < 2; ++i) {
        if (sockets[i].fd < 0)
            continue;
        unsigned char packet[40] = {0};
        packet[0] = family == AF_INET ? 8 : 128;
        unsigned id = 4242 + (collide ? 0 : i);
        packet[4] = id >> 8;
        packet[5] = id;
        packet[7] = 1;
        memcpy(packet + 8, "TSIv4-Darwin-nonce-", 18);
        packet[26] = '0' + i;
        if (family == AF_INET) {
            unsigned sum = checksum(packet, sizeof(packet));
            packet[2] = sum >> 8;
            packet[3] = sum;
        }
        errno = 0;
        ssize_t result = connected ? send(sockets[i].fd, packet, sizeof(packet), 0)
                                   : sendto(sockets[i].fd, packet, sizeof(packet), 0, (void *)&target, target_len);
        printf("send index=%d id=%u count=%zd errno=%d\n", i, id, result, errno);
    }
    double deadline = now() + 0.25;
    while (now() < deadline) {
        int ready = poll(sockets, 2, 25);
        if (ready <= 0)
            continue;
        for (int i = 0; i < 2; ++i) {
            if (!(sockets[i].revents & POLLIN))
                continue;
            unsigned char bytes[512] = {0};
            union { struct cmsghdr alignment; unsigned char bytes[512]; } control;
            struct sockaddr_storage from;
            struct iovec iov = {.iov_base = bytes, .iov_len = tiny ? 12 : sizeof(bytes)};
            struct msghdr msg = {.msg_name = &from, .msg_namelen = sizeof(from),
                                 .msg_iov = &iov, .msg_iovlen = 1,
                                 .msg_control = &control, .msg_controllen = sizeof(control)};
            errno = 0;
            ssize_t count = recvmsg(sockets[i].fd, &msg, tiny == 2 ? MSG_TRUNC : 0);
            printf("recv index=%d count=%zd errno=%d flags=%x addrlen=%u data=", i, count, errno, msg.msg_flags, msg.msg_namelen);
            size_t available = count < 0 ? 0 : (size_t)count < iov.iov_len ? (size_t)count : iov.iov_len;
            for (size_t j = 0; j < available; ++j)
                printf("%02x", bytes[j]);
            putchar('\n');
            size_t offset = family == AF_INET && available && (bytes[0] >> 4) == 4 ? (bytes[0] & 15) * 4 : 0;
            if (available >= offset + 27) {
                unsigned char *icmp = bytes + offset;
                int nonce = icmp[26] - '0';
                printf("icmp index=%d offset=%zu type=%u id=%u sequence=%u nonce=%d\n",
                       i, offset, icmp[0], icmp[4] * 256 + icmp[5], icmp[6] * 256 + icmp[7], nonce);
                if (icmp[0] == (family == AF_INET ? 0 : 129) && nonce >= 0 && nonce < 2) {
                    if (nonce == i) ++own[i]; else ++foreign[i];
                }
            }
            for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
                printf("cmsg level=%d type=%d len=%u data=", c->cmsg_level, c->cmsg_type, c->cmsg_len);
                for (size_t j = 0; j < c->cmsg_len - CMSG_LEN(0); ++j)
                    printf("%02x", CMSG_DATA(c)[j]);
                putchar('\n');
            }
        }
    }
    for (int i = 0; i < 2; ++i) {
        printf("SUMMARY index=%d own=%u foreign=%u\n", i, own[i], foreign[i]);
        if (sockets[i].fd >= 0) close(sockets[i].fd);
    }
}

int main(void)
{
    struct utsname os;
    uname(&os);
    printf("OS %s %s %s compiler=%s uid=%u\n", os.sysname, os.release, os.machine, __VERSION__, getuid());
    for (int i = 0; i < 2; ++i) {
        int family = i ? AF_INET6 : AF_INET;
        probe(family, 0, -1, 0, 0, 0);
        probe(family, 1, -1, 0, 0, 0);
        probe(family, 0, 0, 0, 0, 0);
        probe(family, 0, 4242, 1, 0, 0);
        probe(family, 0, -1, 1, 1, 0);
        probe(family, 0, -1, 0, 0, 1);
        probe(family, 0, -1, 0, 0, 2);
    }
    return 0;
}
