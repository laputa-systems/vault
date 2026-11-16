#include <errno.h>
#include <poll.h>
#include <sys/socket.h>

static int refuse_ready_accept(int fd, struct sockaddr *address, socklen_t *length) {
    (void)address;
    (void)length;
    struct pollfd listener = { .fd = fd, .events = POLLIN };
    int ready = poll(&listener, 1, 0);
    if (ready < 0) return -1;
    errno = ready == 0 ? EAGAIN : EMFILE;
    return -1;
}

__attribute__((used)) static struct {
    const void *replacement;
    const void *original;
} interpose_accept __attribute__((section("__DATA,__interpose"))) = {
    (const void *)refuse_ready_accept,
    (const void *)accept,
};
