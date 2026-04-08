/*
 * tamio-hook.c — LD_PRELOAD library for debugging tamio's USB framing.
 *
 * Hooks read()/write()/recv()/send() on /dev/ssmac_avb (the USB endpoint
 * character device) and syslog() to log raw USB frames to /tmp/tamio-hook.log
 * WITHOUT the 512-byte chunking artifacts that usbmon produces.
 *
 * tamio reads full logical transfers in one call, so each READ/WRITE line
 * in the log corresponds to exactly one CONNECT/PING/PONG/PTTH/NREK frame.
 *
 * Also hooks the IPC pipes to MOTUAVBController so we can see when HTTP
 * requests are forwarded and responses come back.
 *
 * Build (requires arm-linux-gnueabi cross-toolchain):
 *   arm-linux-gnueabi-gcc -march=armv5t -msoft-float \
 *       -shared -fPIC -O1 -o tamio-hook.so tamio-hook.c -ldl
 *
 * Deploy:
 *   See scripts/deploy-hook.sh
 *
 * Architecture:
 *   USB host (our Rust code)
 *     ↕  binary framing (CONNECT/PING/PTTH/NREK)
 *   /dev/ssmac_avb   ← WE HOOK HERE
 *     ↕
 *   tamio (ETunnel + L3Proxy)
 *     ↕  HTTP over local socket (max 1499 bytes / frame, 12-byte header)
 *   /tmp/com.motu.ipc.proxy ← AND HERE
 *     ↕
 *   MOTUAVBController:80
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>

/* ── State ─────────────────────────────────────────────────────────────────── */

static int g_log_fd   = -1;  /* /tmp/tamio-hook.log, opened with raw syscall */
static int g_usb_fd   = -1;  /* /dev/ssmac_avb (USB endpoint) */
static int g_ipc_w_fd = -1;  /* /tmp/com.motu.ipc.proxy   (tamio→controller) */
static int g_ipc_r_fd = -1;  /* /tmp/com.motu.ipc.controller (controller→tamio) */
static int g_chc_w_fd = -1;  /* /tmp/com.motu.ipc.chc.proxy  */
static int g_chc_r_fd = -1;  /* /tmp/com.motu.ipc.chc.controller */

/* Thread-local recursion guard — prevents logging from triggering itself */
static __thread int g_in = 0;

/* ── Raw log (bypasses our write() hook via direct syscall) ────────────────── */

static void rawlog(const char *buf, size_t n) {
    if (g_log_fd >= 0 && n > 0)
        syscall(SYS_write, g_log_fd, buf, n);
}

static void logf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void logf(const char *fmt, ...) {
    if (g_in) return;
    g_in = 1;
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    rawlog(buf, n > 0 ? (size_t)(n < (int)sizeof(buf) ? n : (int)sizeof(buf) - 1) : 0);
    g_in = 0;
}

static void hex_dump(const uint8_t *data, size_t len) {
    if (g_in) return;
    g_in = 1;
    size_t show = len < 256 ? len : 256;
    char buf[64];
    for (size_t i = 0; i < show; i++) {
        int n = 0;
        if (i % 16 == 0) n = snprintf(buf, sizeof(buf), "\n  %04zx:", i);
        n += snprintf(buf + n, sizeof(buf) - n, " %02x", data[i]);
        rawlog(buf, (size_t)n);
    }
    if (len > 256) {
        int n = snprintf(buf, sizeof(buf), "\n  ... +%zu bytes", len - 256);
        rawlog(buf, (size_t)n);
    }
    rawlog("\n", 1);
    g_in = 0;
}

/* ── Frame label helper (recognises our binary protocol) ──────────────────── */

static const char *frame_label(const uint8_t *d, size_t len) {
    if (len < 4) return "SHORT";
    uint8_t flags = d[1];
    if (flags == 0x82) return "CONNECT";
    if (flags == 0x81) return "PING";
    if (flags == 0x00 && len == 8)  return "PONG";
    if (len < 12)      return "DATA(short)";
    if (flags == 0x80 || flags == 0x00) {
        /* Check fourcc at [4:8] */
        if (len >= 8) {
            if (memcmp(d + 4, "PTTH", 4) == 0) return "PTTH";
            if (memcmp(d + 4, "NREK", 4) == 0) return "NREK";
        }
        return "DATA";
    }
    return "UNKNOWN";
}

static void log_frame(const char *dir, int fd, const char *fd_name,
                      const uint8_t *data, size_t len) {
    const char *label = frame_label(data, len);
    logf("%s fd=%-2d %-20s  [%s %zu bytes]", dir, fd, fd_name, label, len);
    hex_dump(data, len);
}

/* ── fd name resolution ────────────────────────────────────────────────────── */

static const char *fd_name(int fd) {
    if (fd == g_usb_fd)   return "/dev/ssmac_avb";
    if (fd == g_ipc_w_fd) return "ipc.proxy(W)";
    if (fd == g_ipc_r_fd) return "ipc.controller(R)";
    if (fd == g_chc_w_fd) return "ipc.chc.proxy(W)";
    if (fd == g_chc_r_fd) return "ipc.chc.controller(R)";
    return "other";
}

static int is_interesting(int fd) {
    return fd == g_usb_fd   ||
           fd == g_ipc_w_fd || fd == g_ipc_r_fd ||
           fd == g_chc_w_fd || fd == g_chc_r_fd;
}

/* ── Constructor — runs when .so is loaded ─────────────────────────────────── */

static void __attribute__((constructor)) hook_init(void) {
    /* Use raw syscall so we don't recurse into our own open() hook */
    g_log_fd = (int)syscall(SYS_open, "/tmp/tamio-hook.log",
                            O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    logf("=== tamio-hook loaded (log_fd=%d) ===\n", g_log_fd);
}

/* ── Hook: open() — detect ssmac_avb and IPC paths ───────────────────────── */

int open(const char *path, int flags, ...) {
    static int (*real)(const char *, int, ...) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "open");
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    int fd = real(path, flags, mode);
    if (fd < 0 || !path) return fd;

    if (strstr(path, "ssmac_avb")) {
        g_usb_fd = fd;
        logf("OPEN  fd=%-2d  %s\n", fd, path);
    } else if (strstr(path, "ipc.proxy")) {
        g_ipc_w_fd = fd;
        logf("OPEN  fd=%-2d  %s\n", fd, path);
    } else if (strstr(path, "ipc.controller")) {
        g_ipc_r_fd = fd;
        logf("OPEN  fd=%-2d  %s\n", fd, path);
    } else if (strstr(path, "ipc.chc.proxy")) {
        g_chc_w_fd = fd;
        logf("OPEN  fd=%-2d  %s\n", fd, path);
    } else if (strstr(path, "ipc.chc.controller")) {
        g_chc_r_fd = fd;
        logf("OPEN  fd=%-2d  %s\n", fd, path);
    }
    return fd;
}

/* ── Hook: close() — clear cached fds ────────────────────────────────────── */

int close(int fd) {
    static int (*real)(int) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "close");
    if (is_interesting(fd)) logf("CLOSE fd=%-2d  %s\n", fd, fd_name(fd));
    if (fd == g_usb_fd)   g_usb_fd   = -1;
    if (fd == g_ipc_w_fd) g_ipc_w_fd = -1;
    if (fd == g_ipc_r_fd) g_ipc_r_fd = -1;
    if (fd == g_chc_w_fd) g_chc_w_fd = -1;
    if (fd == g_chc_r_fd) g_chc_r_fd = -1;
    return real(fd);
}

/* ── Hook: syslog() — capture ALL messages including LOG_DEBUG ─────────────── */

void syslog(int pri, const char *fmt, ...) {
    static void (*real)(int, const char *, ...) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "syslog");
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    /* strip trailing newline — we add one */
    size_t l = strlen(msg);
    if (l > 0 && msg[l - 1] == '\n') msg[l - 1] = '\0';
    logf("SYSLOG[%d] %s\n", pri, msg);
    real(pri, "%s", msg);
}

/* ── Hook: read() ──────────────────────────────────────────────────────────── */

ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real)(int, void *, size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "read");
    ssize_t r = real(fd, buf, count);
    if (r > 0 && !g_in && is_interesting(fd))
        log_frame("READ ", fd, fd_name(fd), (const uint8_t *)buf, (size_t)r);
    return r;
}

/* ── Hook: write() ─────────────────────────────────────────────────────────── */

ssize_t write(int fd, const void *buf, size_t count) {
    static ssize_t (*real)(int, const void *, size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "write");
    if (count > 0 && !g_in && is_interesting(fd))
        log_frame("WRITE", fd, fd_name(fd), (const uint8_t *)buf, count);
    return real(fd, buf, count);
}

/* ── Hook: recv() ──────────────────────────────────────────────────────────── */

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    static ssize_t (*real)(int, void *, size_t, int) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "recv");
    ssize_t r = real(fd, buf, len, flags);
    if (r > 0 && !g_in && is_interesting(fd))
        log_frame("RECV ", fd, fd_name(fd), (const uint8_t *)buf, (size_t)r);
    return r;
}

/* ── Hook: send() ──────────────────────────────────────────────────────────── */

ssize_t send(int fd, const void *buf, size_t len, int flags) {
    static ssize_t (*real)(int, const void *, size_t, int) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "send");
    if (len > 0 && !g_in && is_interesting(fd))
        log_frame("SEND ", fd, fd_name(fd), (const uint8_t *)buf, len);
    return real(fd, buf, len, flags);
}
