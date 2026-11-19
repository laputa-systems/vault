#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int signal_calls, interrupt_calls;
static int active(void) {
    const char *root = getenv("VAULT_SIGNAL_ROOT");
    char path[PATH_MAX];
    return root && snprintf(path, sizeof(path), "%s/armed", root) < (int)sizeof(path) && access(path, F_OK) == 0;
}
static int mode(const char *name) {
    const char *value = getenv("VAULT_SIGNAL_MODE");
    return value && strcmp(value, name) == 0;
}
static void event(char kind, int number, int fail) {
    char path[PATH_MAX], buf[32];
    const char *root = getenv("VAULT_SIGNAL_ROOT");
    if (!root || snprintf(path, sizeof(path), "%s/events", root) >= (int)sizeof(path)) _exit(120);
    int n = snprintf(buf, sizeof(buf), "%c%d%s\n", kind, number, fail ? "!" : "");
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0 || write(fd, buf, (size_t)n) != n || close(fd) != 0) _exit(121);
}
typedef void (*handler)(int);
static handler fault_signal(int sig, handler fn) {
    if (!active() || (getenv("VAULT_SIGNAL_MODE") && strncmp(getenv("VAULT_SIGNAL_MODE"), "io-", 3) == 0)) return signal(sig, fn);
    ++signal_calls;
    int fail = (mode("caller-restore") && signal_calls == 1)
        || ((mode("install") || mode("combined")) && signal_calls == 2)
        || (mode("combined") && signal_calls == 3)
        || ((mode("restore") || mode("suspend-restore")) && (signal_calls == 6 || signal_calls == 8));
    event('S', sig, fail);
    if (fail) { errno = signal_calls == 8 ? EACCES : EIO; return SIG_ERR; }
    return signal(sig, fn);
}
static int fault_interrupt(int sig, int flag) {
    if (!active() || (getenv("VAULT_SIGNAL_MODE") && strncmp(getenv("VAULT_SIGNAL_MODE"), "io-", 3) == 0)) return siginterrupt(sig, flag);
    ++interrupt_calls;
    int fail = mode("interrupt") && interrupt_calls == 2;
    event('I', sig, fail);
    if (fail) { errno = EINVAL; return -1; }
    return siginterrupt(sig, flag);
}
static int fault_raise(int sig) {
    if (!active() || (getenv("VAULT_SIGNAL_MODE") && strncmp(getenv("VAULT_SIGNAL_MODE"), "io-", 3) == 0)) return raise(sig);
    int fail = mode("raise");
    event('R', sig, fail);
    if (fail) { errno = ESRCH; return -1; }
    return raise(sig);
}
static int fault_open(const char *path, int flags, ...) {
    int create_mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        create_mode = va_arg(args, int);
        va_end(args);
    }
    if (strcmp(path, "/dev/tty") == 0 && mode("io-open") && active()) {
        event('O', 1, 1);
        errno = EIO;
        return -1;
    }
    return open(path, flags, create_mode);
}
/* The child owns its controlling PTY; restrict faults to its /dev/tty descriptors. */
static ssize_t fault_write(int fd, const void *buf, size_t count) {
    char path[PATH_MAX];
    if (active() && fd != STDERR_FILENO && fcntl(fd, F_GETPATH, path) == 0
        && strcmp(path, "/dev/tty") == 0) {
        int prompt = count == 14 && memcmp(buf, "owned prompt: ", 14) == 0;
        int newline = count == 1 && memcmp(buf, "\n", 1) == 0;
        if ((mode("io-prompt") && prompt) || (mode("io-newline") && newline)) {
            event('W', prompt ? 1 : 2, 1);
            errno = EIO;
            return -1;
        }
    }
    return write(fd, buf, count);
}
#define INTERPOSE(replacement, original) __attribute__((used)) static struct { const void *replacement_fn; const void *original_fn; } interpose_##replacement __attribute__((section("__DATA,__interpose"))) = { (const void *)replacement, (const void *)original }
INTERPOSE(fault_signal, signal);
INTERPOSE(fault_interrupt, siginterrupt);
INTERPOSE(fault_raise, raise);

INTERPOSE(fault_write, write);
INTERPOSE(fault_open, open);
