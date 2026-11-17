#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
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
    if (!active()) return signal(sig, fn);
    ++signal_calls;
    int fail = ((mode("install") || mode("combined")) && signal_calls == 2)
        || (mode("combined") && signal_calls == 3)
        || ((mode("restore") || mode("suspend-restore")) && (signal_calls == 6 || signal_calls == 8));
    event('S', sig, fail);
    if (fail) { errno = signal_calls == 8 ? EACCES : EIO; return SIG_ERR; }
    return signal(sig, fn);
}
static int fault_interrupt(int sig, int flag) {
    if (!active()) return siginterrupt(sig, flag);
    ++interrupt_calls;
    int fail = mode("interrupt") && interrupt_calls == 2;
    event('I', sig, fail);
    if (fail) { errno = EINVAL; return -1; }
    return siginterrupt(sig, flag);
}
static int fault_raise(int sig) {
    if (!active()) return raise(sig);
    int fail = mode("raise");
    event('R', sig, fail);
    if (fail) { errno = ESRCH; return -1; }
    return raise(sig);
}
#define INTERPOSE(replacement, original) __attribute__((used)) static struct { const void *replacement_fn; const void *original_fn; } interpose_##replacement __attribute__((section("__DATA,__interpose"))) = { (const void *)replacement, (const void *)original }
INTERPOSE(fault_signal, signal);
INTERPOSE(fault_interrupt, siginterrupt);
INTERPOSE(fault_raise, raise);
