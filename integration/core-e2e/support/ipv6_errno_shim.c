/*
 * Test-environment shim for hosts whose kernel has NO IPv6 support at all.
 *
 * Holochain 0.7.0's websocket listener (holochain_websocket::dual_bind)
 * always binds IPv6 first and only falls back to IPv4 when that fails with
 * EADDRNOTAVAIL (what a host with IPv6 *disabled* returns). A kernel built
 * or booted without IPv6 instead returns EAFNOSUPPORT from socket(), which
 * the conductor treats as fatal.
 *
 * This shim changes nothing else: when socket(AF_INET6, ...) really fails
 * with EAFNOSUPPORT it reports EADDRNOTAVAIL instead, so the conductor takes
 * its existing IPv4-only path. It is never needed on hosts with IPv6 and is
 * not part of any product build.
 *
 *   cc -shared -fPIC -O2 -o libipv6_errno_shim.so ipv6_errno_shim.c -ldl
 *   LD_PRELOAD=$PWD/libipv6_errno_shim.so cargo test ...
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/socket.h>

int socket(int domain, int type, int protocol) {
    static int (*real_socket)(int, int, int);
    if (!real_socket) {
        real_socket = (int (*)(int, int, int))dlsym(RTLD_NEXT, "socket");
    }
    int fd = real_socket(domain, type, protocol);
    if (fd < 0 && domain == AF_INET6 && errno == EAFNOSUPPORT) {
        errno = EADDRNOTAVAIL;
    }
    return fd;
}
