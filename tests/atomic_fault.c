#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

static int root_fd(int fd) {
    char path[PATH_MAX];
    const char *root = getenv("VAULT_ATOMIC_ROOT");
    return root && fcntl(fd, F_GETPATH, path) == 0 && strcmp(path, root) == 0;
}
static int temp_fd(int fd) {
    char path[PATH_MAX];
    const char *root = getenv("VAULT_ATOMIC_ROOT");
    if (!root || fcntl(fd, F_GETPATH, path) != 0) return 0;
    size_t n = strlen(root);
    return strlen(path) >= n + 6 && strncmp(path, root, n) == 0 && strncmp(path + n, "/.tmp-", 6) == 0 && !strchr(path + n + 1, '/');
}
static int mode(const char *name) {
    const char *value = getenv("VAULT_ATOMIC_MODE");
    return value && strcmp(value, name) == 0;
}
static void event(const char *name) {
    const char *root = getenv("VAULT_ATOMIC_ROOT");
    char path[PATH_MAX];
    if (!root || snprintf(path, sizeof(path), "%s/.event", root) >= (int)sizeof(path)) _exit(120);
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0 || write(fd, name, strlen(name)) != (ssize_t)strlen(name) || close(fd) != 0) _exit(121);
}
static ssize_t fault_write(int fd, const void *buf, size_t count) {
    if (temp_fd(fd) && (mode("write") || mode("cleanup"))) {
        event("W"); errno = EIO; return -1;
    }
    return write(fd, buf, count);
}
static int fault_fsync(int fd) {
    if (temp_fd(fd) && mode("file-sync")) { event("F"); errno = EIO; return -1; }
    if (root_fd(fd) && mode("dir-sync")) { event("D"); errno = EIO; return -1; }
    int result = fsync(fd);
    if (result == 0 && temp_fd(fd) && mode("kill-file")) { event("S"); for (;;) pause(); }
    return result;
}
static int fault_rename(int from, const char *old, int to, const char *new, unsigned int flags) {
    int match = root_fd(from) && root_fd(to) && strncmp(old, ".tmp-", 5) == 0 && !strchr(old, '/') && strcmp(new, "recipient") == 0 && flags == 0;
    if (match && mode("rename")) { event("R"); errno = EIO; return -1; }
    int result = renameatx_np(from, old, to, new, flags);
    if (result == 0 && match && mode("kill-rename")) { event("N"); for (;;) pause(); }
    return result;
}
static int fault_unlink(int dir, const char *name, int flags) {
    if (root_fd(dir) && strncmp(name, ".tmp-", 5) == 0 && !strchr(name, '/') && flags == 0 && mode("cleanup")) {
        event("U"); errno = EACCES; return -1;
    }
    return unlinkat(dir, name, flags);
}
#define INTERPOSE(replacement, original) __attribute__((used)) static struct { const void *replacement_fn; const void *original_fn; } interpose_##replacement __attribute__((section("__DATA,__interpose"))) = { (const void *)replacement, (const void *)original }
INTERPOSE(fault_write, write);
INTERPOSE(fault_fsync, fsync);
INTERPOSE(fault_rename, renameatx_np);
INTERPOSE(fault_unlink, unlinkat);
