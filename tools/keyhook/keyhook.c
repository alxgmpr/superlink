/*
 * keyhook.c — LD_PRELOAD shim for lorabrd on USL Gateway
 *
 * Intercepts libsodium's crypto_stream_xsalsa20_xor (and the
 * crypto_stream_xor wrapper that calls it) to capture all ephemeral
 * session keys used for XSalsa20 stream encryption.
 *
 * Uses crypto_core_hsalsa20 + crypto_stream_salsa20_xor as the real
 * XSalsa20 implementation to avoid infinite recursion.
 *
 * Build:
 *   arm-linux-gnueabihf-gcc -shared -fPIC -o keyhook.so keyhook.c
 *
 * Usage:
 *   LD_PRELOAD=/tmp/keyhook.so /usr/sbin/lorabrd --syslog ...
 *   cat /tmp/keyhook.log
 */

#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define NONCE_LEN 24
#define KEY_LEN   32
#define MAX_LOG   500

static int logfd = -1;
static int log_count = 0;

static const char hx[] = "0123456789abcdef";

static void whex(int fd, const unsigned char *b, int n) {
    char o[2];
    for (int i = 0; i < n; i++) {
        o[0] = hx[b[i] >> 4];
        o[1] = hx[b[i] & 0xf];
        write(fd, o, 2);
    }
}

static void wstr(int fd, const char *s) {
    write(fd, s, strlen(s));
}

static void wdec(int fd, unsigned long long v) {
    char buf[20];
    int i = 19;
    buf[i] = 0;
    if (!v) buf[--i] = '0';
    while (v) { buf[--i] = '0' + v % 10; v /= 10; }
    wstr(fd, &buf[i]);
}

static void log_call(const char *func, const unsigned char *k,
                     const unsigned char *n, unsigned long long len) {
    if (log_count >= MAX_LOG) return;

    if (logfd < 0)
        logfd = open("/tmp/keyhook.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (logfd < 0) return;

    log_count++;
    wstr(logfd, "FUNC="); wstr(logfd, func);
    wstr(logfd, "\nKEY=");   whex(logfd, k, KEY_LEN);
    wstr(logfd, "\nNONCE="); whex(logfd, n, NONCE_LEN);
    wstr(logfd, "\nLEN="); wdec(logfd, len);
    wstr(logfd, "\n---\n");
}

/*
 * Real XSalsa20 implementation using lower-level libsodium primitives.
 * XSalsa20(k, n) = Salsa20(HSalsa20(k, n[0:16]), n[16:24])
 */
extern int crypto_core_hsalsa20(
    unsigned char *out, const unsigned char *in,
    const unsigned char *k, const unsigned char *c);

extern int crypto_stream_salsa20_xor(
    unsigned char *c, const unsigned char *m,
    unsigned long long mlen, const unsigned char *n,
    const unsigned char *k);

static int real_xsalsa20_xor(unsigned char *c, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *n,
                              const unsigned char *k) {
    unsigned char subkey[32];
    crypto_core_hsalsa20(subkey, n, k, 0);
    int rc = crypto_stream_salsa20_xor(c, m, mlen, n + 16, subkey);
    memset(subkey, 0, 32);
    return rc;
}

/* --- Hooked functions --- */

int crypto_stream_xsalsa20_xor(
    unsigned char *c, const unsigned char *m,
    unsigned long long mlen, const unsigned char *n,
    const unsigned char *k) {
    log_call("xsalsa20", k, n, mlen);
    return real_xsalsa20_xor(c, m, mlen, n, k);
}

int crypto_stream_xor(unsigned char *c, const unsigned char *m,
                      unsigned long long mlen, const unsigned char *n,
                      const unsigned char *k) {
    log_call("stream", k, n, mlen);
    return real_xsalsa20_xor(c, m, mlen, n, k);
}
