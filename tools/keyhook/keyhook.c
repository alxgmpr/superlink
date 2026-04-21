/*
 * keyhook.c — LD_PRELOAD shim for lorabrd on USL Gateway
 *
 * Captures:
 *   - XSalsa20 stream keys + nonces (session keys used for inner/outer encryption)
 *   - BLAKE2b KDF inputs: every crypto_generichash_init/update/final,
 *     grouped by state pointer so a single KDF computation can be reconstructed
 *     post-hoc. This exposes the exact bytes that form the session key —
 *     critical for knowing what's hashed after shared||gw_pub||sensor_pub
 *     (i.e. the keypair+0x30 context vector and arg3 trailer).
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
#include <stdint.h>

#define NONCE_LEN 24
#define KEY_LEN   32
#define MAX_LOG   4000

static int logfd = -1;
static int log_count = 0;

static const char hx[] = "0123456789abcdef";

static void whex(int fd, const unsigned char *b, unsigned long n) {
    char o[2];
    for (unsigned long i = 0; i < n; i++) {
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

static void wptr(int fd, const void *p) {
    uintptr_t v = (uintptr_t)p;
    char buf[9];
    for (int i = 7; i >= 0; i--) { buf[i] = hx[v & 0xf]; v >>= 4; }
    buf[8] = 0;
    wstr(fd, buf);
}

static int bump(void) {
    if (log_count >= MAX_LOG) return 0;
    if (logfd < 0)
        logfd = open("/tmp/keyhook.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (logfd < 0) return 0;
    log_count++;
    return 1;
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

/* --- XSalsa20 hooks ---
 *
 * Log the INPUT (m) bytes before the call and OUTPUT (c) bytes after —
 * for XOR ciphers they're different (plaintext vs ciphertext). Even when
 * m==c (in-place), capturing pre- and post- gives us both.
 */

#define STREAM_MAX_DATA 512   /* cap per-call logged bytes */

static void log_stream(const char *func,
                       const unsigned char *c, const unsigned char *m,
                       unsigned long long mlen,
                       const unsigned char *n, const unsigned char *k,
                       int phase /* 0=pre, 1=post */,
                       const void *caller_ra) {
    if (!bump()) return;
    unsigned long cap = mlen < STREAM_MAX_DATA ? mlen : STREAM_MAX_DATA;
    wstr(logfd, "FUNC=");    wstr(logfd, func);
    wstr(logfd, "\nPHASE="); wstr(logfd, phase ? "post" : "pre");
    if (phase == 0) {
        /* Caller return-address, so we can look up the call site in
         * Binary Ninja. Only logged on PRE to avoid doubling log size. */
        wstr(logfd, "\nRA=");   wptr(logfd, caller_ra);
    }
    wstr(logfd, "\nKEY=");   whex(logfd, k, KEY_LEN);
    wstr(logfd, "\nNONCE="); whex(logfd, n, NONCE_LEN);
    wstr(logfd, "\nLEN=");   wdec(logfd, mlen);
    if (phase == 0 && m) {
        wstr(logfd, "\nIN=");  whex(logfd, m, cap);
    }
    if (phase == 1 && c) {
        wstr(logfd, "\nOUT="); whex(logfd, c, cap);
    }
    wstr(logfd, "\n---\n");
}

int crypto_stream_xsalsa20_xor(
    unsigned char *c, const unsigned char *m,
    unsigned long long mlen, const unsigned char *n,
    const unsigned char *k) {
    const void *ra = __builtin_return_address(0);
    log_stream("xsalsa20", c, m, mlen, n, k, 0, ra);
    int rc = real_xsalsa20_xor(c, m, mlen, n, k);
    log_stream("xsalsa20", c, m, mlen, n, k, 1, 0);
    return rc;
}

int crypto_stream_xor(unsigned char *c, const unsigned char *m,
                      unsigned long long mlen, const unsigned char *n,
                      const unsigned char *k) {
    const void *ra = __builtin_return_address(0);
    log_stream("stream", c, m, mlen, n, k, 0, ra);
    int rc = real_xsalsa20_xor(c, m, mlen, n, k);
    log_stream("stream", c, m, mlen, n, k, 1, 0);
    return rc;
}

/* --- crypto_scalarmult hook ---
 *
 * crypto_scalarmult(q, n, p): q = n * p on Curve25519.
 * Logs privkey (n), pubkey input (p), shared output (q). Lets us tie each
 * gh_update shared-secret back to the specific DH pair that produced it.
 *
 * Call the low-level named variant directly — no recursion, no dlsym.
 */

extern int crypto_scalarmult_curve25519(
    unsigned char *q, const unsigned char *n, const unsigned char *p);

int crypto_scalarmult(unsigned char *q, const unsigned char *n,
                      const unsigned char *p) {
    const void *ra = __builtin_return_address(0);
    int rc = crypto_scalarmult_curve25519(q, n, p);
    if (bump()) {
        wstr(logfd, "FUNC=scalarmult\nRA="); wptr(logfd, ra);
        wstr(logfd, "\nPRIV=");              whex(logfd, n, 32);
        wstr(logfd, "\nPUB=");               whex(logfd, p, 32);
        wstr(logfd, "\nSHARED=");            whex(logfd, q, 32);
        wstr(logfd, "\nRC=");                wdec(logfd, (unsigned)rc);
        wstr(logfd, "\n---\n");
    }
    return rc;
}

/* --- BLAKE2b hooks ---
 *
 * Hook the public API (crypto_generichash_*) and call the private/low-level
 * blake2b-suffixed forms directly. They're separate exported symbols in
 * libsodium.so, so there's no recursion through our own hook — no dlsym
 * needed (avoids pulling in newer glibc).
 */

extern int crypto_generichash_blake2b_init(
    void *state, const unsigned char *key, size_t keylen, size_t outlen);
extern int crypto_generichash_blake2b_update(
    void *state, const unsigned char *in, unsigned long long inlen);
extern int crypto_generichash_blake2b_final(
    void *state, unsigned char *out, size_t outlen);

int crypto_generichash_init(void *state, const unsigned char *key,
                             size_t keylen, size_t outlen) {
    if (bump()) {
        wstr(logfd, "FUNC=gh_init\nSTATE=");  wptr(logfd, state);
        wstr(logfd, "\nKEYLEN=");             wdec(logfd, keylen);
        wstr(logfd, "\nOUTLEN=");             wdec(logfd, outlen);
        if (keylen && key) {
            wstr(logfd, "\nKEY=");            whex(logfd, key, keylen);
        }
        wstr(logfd, "\n---\n");
    }
    return crypto_generichash_blake2b_init(state, key, keylen, outlen);
}

int crypto_generichash_update(void *state, const unsigned char *in,
                               unsigned long long inlen) {
    if (bump()) {
        wstr(logfd, "FUNC=gh_update\nSTATE="); wptr(logfd, state);
        wstr(logfd, "\nLEN=");                 wdec(logfd, inlen);
        wstr(logfd, "\nDATA=");                whex(logfd, in, inlen);
        wstr(logfd, "\n---\n");
    }
    return crypto_generichash_blake2b_update(state, in, inlen);
}

int crypto_generichash_final(void *state, unsigned char *out, size_t outlen) {
    const void *ra = __builtin_return_address(0);
    int rc = crypto_generichash_blake2b_final(state, out, outlen);
    if (bump()) {
        wstr(logfd, "FUNC=gh_final\nRA=");     wptr(logfd, ra);
        wstr(logfd, "\nSTATE=");               wptr(logfd, state);
        wstr(logfd, "\nOUTLEN=");              wdec(logfd, outlen);
        wstr(logfd, "\nOUT=");                 whex(logfd, out, outlen);
        wstr(logfd, "\n---\n");
    }
    return rc;
}
