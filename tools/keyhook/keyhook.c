/*
 * keyhook.c — LD_PRELOAD shim for lorabrd on USL Gateway
 *
 * Intercepts libsodium crypto_stream_xor to capture ephemeral session keys.
 * Avoids dlsym (requires GLIBC_2.34) by only hooking crypto_stream_xor and
 * calling crypto_stream_xsalsa20_xor directly (which libsodium's
 * crypto_stream_xor normally wraps).
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
#define MAX_KEYS  16

static unsigned char seen_keys[MAX_KEYS][KEY_LEN];
static int num_seen = 0;
static int logfd = -1;

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

static void log_key(const unsigned char *k, const unsigned char *n,
                    unsigned long long len) {
    if (logfd < 0)
        logfd = open("/tmp/keyhook.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (logfd < 0) return;

    for (int i = 0; i < num_seen; i++)
        if (!memcmp(seen_keys[i], k, KEY_LEN)) return;
    if (num_seen < MAX_KEYS)
        memcpy(seen_keys[num_seen++], k, KEY_LEN);

    wstr(logfd, "KEY=");   whex(logfd, k, KEY_LEN);
    wstr(logfd, "\nNONCE="); whex(logfd, n, NONCE_LEN);
    wstr(logfd, "\nLEN="); wdec(logfd, len);
    wstr(logfd, "\n---\n");
}

/*
 * libsodium's crypto_stream_xor() is a thin wrapper around
 * crypto_stream_xsalsa20_xor(). We interpose crypto_stream_xor
 * and call the inner function directly — the linker resolves it
 * to libsodium's copy since we don't define it ourselves.
 */
extern int crypto_stream_xsalsa20_xor(
    unsigned char *c, const unsigned char *m,
    unsigned long long mlen, const unsigned char *n,
    const unsigned char *k);

int crypto_stream_xor(unsigned char *c, const unsigned char *m,
                      unsigned long long mlen, const unsigned char *n,
                      const unsigned char *k) {
    log_key(k, n, mlen);
    return crypto_stream_xsalsa20_xor(c, m, mlen, n, k);
}
