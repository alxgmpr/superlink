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
 *   arm-linux-gnueabihf-gcc -DKEYHOOK_QUIET=1 -shared -fPIC -o keyhook.so keyhook.c
 *
 * KEYHOOK_QUIET=1 is REQUIRED — without it the memcpy/send/recv hooks
 * compile in and the binary crashes early in lorabrd startup.
 *
 * Usage:
 *   LD_PRELOAD=/tmp/keyhook.so /usr/sbin/lorabrd --syslog ...
 *   cat /tmp/keyhook.log
 */

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>

/* Pin dlsym to the oldest armhf glibc symbol version so the resulting .so
 * loads on the bridge's glibc 2.30 regardless of what the Mac's cross
 * compiler defaults to. GLIBC_2.4 is the armhf baseline. */
__asm__(".symver dlsym,dlsym@GLIBC_2.4");
extern void *dlsym(void *handle, const char *name);
#define RTLD_NEXT ((void *)-1l)

#define NONCE_LEN 24
#define KEY_LEN   32
#ifdef KEYHOOK_QUIET
#define MAX_LOG   200000   /* SSL-only build: long-running pair capture */
#else
#define MAX_LOG   30000
#endif

static int logfd = -1;
static int log_count = 0;

static const char hx[] = "0123456789abcdef";

static void whex(int fd, const unsigned char *b, size_t n) {
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

/* --- memcmp hook (narrow filter) ---
 *
 * The authorize handler at lorabrd 0x5fe14 (memcmp@plt callsite) compares
 * the just-decrypted authorize.secret plaintext against an EXPECTED value
 * stored in connection state. We need EXPECTED to forge a valid secret.
 * Hook memcmp, filter by RA = lorabrd text in the authorize-handler range
 * to keep the log small.
 */

static int local_memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *p = a, *q = b;
    while (n--) {
        if (*p != *q) return (int)*p - (int)*q;
        p++; q++;
    }
    return 0;
}

int memcmp(const void *a, const void *b, size_t n) {
    const void *ra = __builtin_return_address(0);
    int r = local_memcmp(a, b, n);
    /* Authorize handler memcmp is at lorabrd 0x5fe18 (Thumb LR after BLX). */
    uintptr_t rai = (uintptr_t)ra;
    int is_authorize = (n == 32 && rai >= 0x5fe00 && rai < 0x5fe40);
    if (is_authorize && bump()) {
        wstr(logfd, "FUNC=memcmp\nRA=");  wptr(logfd, ra);
        wstr(logfd, "\nLEN=");             wdec(logfd, n);
        wstr(logfd, "\nA=");               whex(logfd, (const unsigned char *)a, n);
        wstr(logfd, "\nB=");               whex(logfd, (const unsigned char *)b, n);
        wstr(logfd, "\nRC=");              wdec(logfd, (unsigned)r);
        /* Dump heap context near A to identify the parent auth_state struct.
         * A is &EXPECTED[0]; the std::vector header (begin/end/end_cap) sits
         * 0x48 bytes earlier inside auth_state. Dump 0x60 bytes before A
         * to capture the surrounding header info. */
        const unsigned char *ap = (const unsigned char *)a;
        wstr(logfd, "\nA_ADDR=");  wptr(logfd, a);
        wstr(logfd, "\nA_CTX=");   whex(logfd, ap - 0x60, 0xc0);
        wstr(logfd, "\n");
    }
    /* Bypass mode: when the LD_PRELOAD'd lorabrd was started with
     * KEYHOOK_BYPASS_AUTH=1 in the environment, force the authorize-handler
     * memcmp to return 0 ("equal") regardless of the actual byte comparison.
     * This lets a mock controller authorize successfully without knowing the
     * per-connection EXPECTED. Other memcmp callsites are unaffected. */
    if (is_authorize) {
        static int bypass_checked = 0;
        static int bypass_enabled = 0;
        if (!bypass_checked) {
            extern char **environ;
            char **e = environ;
            while (e && *e) {
                const char *s = *e;
                if (s[0]=='K' && s[1]=='E' && s[2]=='Y' && s[3]=='H'
                    && s[4]=='O' && s[5]=='O' && s[6]=='K' && s[7]=='_'
                    && s[8]=='B' && s[9]=='Y' && s[10]=='P' && s[11]=='A'
                    && s[12]=='S' && s[13]=='S' && s[14]=='_' && s[15]=='A'
                    && s[16]=='U' && s[17]=='T' && s[18]=='H' && s[19]=='='
                    && s[20]=='1') {
                    bypass_enabled = 1;
                    break;
                }
                e++;
            }
            bypass_checked = 1;
        }
        if (bypass_enabled) {
            if (bump()) {
                wstr(logfd, "FUNC=memcmp_bypass\nRA=");  wptr(logfd, ra);
                wstr(logfd, "\n---\n");
            }
            return 0;
        }
    }
    return r;
}

/* --- crypto_secretbox hooks ---
 *
 * Hook crypto_secretbox_easy / open_easy so we can recover the (key, nonce,
 * ciphertext, plaintext) tuple. Used to crack the JSON-RPC `authorize.secret`
 * format on lorabrd: the bridge runs open_easy on the base64-decoded secret
 * and memcmp's the plaintext against an expected value. Static RE shows the
 * call but not the key/nonce composition; this captures all four live during
 * a real-controller authorize.
 *
 * Real symbols available in libsodium for direct dispatch:
 *   crypto_secretbox_xsalsa20poly1305(_open)
 * which the public _easy wrappers delegate to. We call these directly so our
 * own hook isn't re-entered.
 *
 * Easy / open_easy layout (per libsodium docs):
 *   open_easy(out, ciphertext, ctlen, nonce, key)
 *     ciphertext = MAC(16) || encrypted(N), ctlen = 16+N, plaintext = N bytes
 *   easy(out, plaintext, ptlen, nonce, key)
 *     out = MAC(16) || encrypted(ptlen), ptlen = N
 */

extern int crypto_secretbox_xsalsa20poly1305_open(
    unsigned char *m, const unsigned char *c, unsigned long long clen,
    const unsigned char *n, const unsigned char *k);
extern int crypto_secretbox_xsalsa20poly1305(
    unsigned char *c, const unsigned char *m, unsigned long long mlen,
    const unsigned char *n, const unsigned char *k);

#define SBOX_MAX_DATA 512

/* Local byte-copy so we don't depend on KEYHOOK_QUIET-gated real_memcpy. */
static void sbox_copy(unsigned char *d, const unsigned char *s, size_t n) {
    while (n--) *d++ = *s++;
}

int crypto_secretbox_open_easy(
    unsigned char *out, const unsigned char *ciphertext,
    unsigned long long ctlen, const unsigned char *nonce,
    const unsigned char *key) {
    const void *ra = __builtin_return_address(0);
    /* Pass through to the real libsodium open_easy via dlsym so we don't
     * accidentally diverge from its exact memory layout / output write. */
    static int (*real)(unsigned char *, const unsigned char *,
                       unsigned long long, const unsigned char *,
                       const unsigned char *) = 0;
    if (!real) real = dlsym(RTLD_NEXT, "crypto_secretbox_open_easy");
    int rc = real(out, ciphertext, ctlen, nonce, key);

    if (bump()) {
        unsigned long ctcap = ctlen < SBOX_MAX_DATA ? ctlen : SBOX_MAX_DATA;
        unsigned long ptlen = (rc == 0 && ctlen >= 16) ? (ctlen - 16) : 0;
        unsigned long ptcap = ptlen < SBOX_MAX_DATA ? ptlen : SBOX_MAX_DATA;
        wstr(logfd, "FUNC=secretbox_open\nRA=");  wptr(logfd, ra);
        wstr(logfd, "\nKEY=");                    whex(logfd, key, KEY_LEN);
        wstr(logfd, "\nNONCE=");                  whex(logfd, nonce, NONCE_LEN);
        wstr(logfd, "\nCTLEN=");                  wdec(logfd, (unsigned long long)ctlen);
        wstr(logfd, "\nCT=");                     whex(logfd, ciphertext, ctcap);
        wstr(logfd, "\nRC=");                     wdec(logfd, (unsigned)rc);
        if (rc == 0) {
            wstr(logfd, "\nPT=");                 whex(logfd, out, ptcap);
        }
        wstr(logfd, "\n---\n");
    }
    return rc;
}

int crypto_secretbox_easy(
    unsigned char *out, const unsigned char *plaintext,
    unsigned long long ptlen, const unsigned char *nonce,
    const unsigned char *key) {
    const void *ra = __builtin_return_address(0);
    unsigned char tmpm[32 + 4096];
    unsigned char tmpc[32 + 4096];
    unsigned long long inflated = ptlen + 32;
    int rc;
    if (inflated > sizeof(tmpm)) {
        static int (*real)(unsigned char *, const unsigned char *,
                           unsigned long long, const unsigned char *,
                           const unsigned char *);
        if (!real) real = dlsym(RTLD_NEXT, "crypto_secretbox_easy");
        rc = real(out, plaintext, ptlen, nonce, key);
    } else {
        for (int i = 0; i < 32; i++) tmpm[i] = 0;
        sbox_copy(tmpm + 32, plaintext, (size_t)ptlen);
        rc = crypto_secretbox_xsalsa20poly1305(
            tmpc, tmpm, inflated, nonce, key);
        if (rc == 0)
            sbox_copy(out, tmpc + 16, (size_t)(ptlen + 16));
    }

    if (bump()) {
        unsigned long ptcap = ptlen < SBOX_MAX_DATA ? ptlen : SBOX_MAX_DATA;
        unsigned long long ctlen = ptlen + 16;
        unsigned long ctcap = ctlen < SBOX_MAX_DATA ? ctlen : SBOX_MAX_DATA;
        wstr(logfd, "FUNC=secretbox\nRA=");  wptr(logfd, ra);
        wstr(logfd, "\nKEY=");               whex(logfd, key, KEY_LEN);
        wstr(logfd, "\nNONCE=");             whex(logfd, nonce, NONCE_LEN);
        wstr(logfd, "\nPTLEN=");             wdec(logfd, (unsigned long long)ptlen);
        wstr(logfd, "\nPT=");                whex(logfd, plaintext, ptcap);
        wstr(logfd, "\nRC=");                wdec(logfd, (unsigned)rc);
        if (rc == 0) {
            wstr(logfd, "\nCT=");            whex(logfd, out, ctcap);
        }
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

/* --- randombytes_buf hook ---
 *
 * Top candidate for where the SwitchClassBRsp 70-byte body's 64 middle bytes
 * come from. If the firmware calls randombytes_buf(64) somewhere in
 * sub_52e78's subtree (per RA), those bytes ARE the Class B grant payload —
 * literal random, not validated semantically. That would mean we can reproduce
 * the grant with any 64 random bytes in our emulator.
 *
 * Avoid dlsym (pulls GLIBC_2.34 on the build host). Instead fulfill the call
 * by reading /dev/urandom directly — same effect as libsodium's sysrandom
 * backend. The KEY data point is the RA; the bytes themselves are logged so
 * we can tie them to the subsequent 70-byte body.
 */

static void fill_from_urandom(unsigned char *buf, unsigned long size) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { for (unsigned long i = 0; i < size; i++) buf[i] = 0; return; }
    unsigned long off = 0;
    while (off < size) {
        long n = read(fd, buf + off, size - off);
        if (n <= 0) break;
        off += (unsigned long)n;
    }
    close(fd);
}

void randombytes_buf(void *buf, unsigned long size) {
    const void *ra = __builtin_return_address(0);
    fill_from_urandom((unsigned char *)buf, size);
    if (bump()) {
        unsigned long cap = size < 512 ? size : 512;
        wstr(logfd, "FUNC=randombytes\nRA="); wptr(logfd, ra);
        wstr(logfd, "\nLEN=");                wdec(logfd, size);
        wstr(logfd, "\nBUF=");                whex(logfd, (const unsigned char *)buf, cap);
        wstr(logfd, "\n---\n");
    }
}

#ifndef KEYHOOK_QUIET
/* --- memcpy / memmove / memset hooks ---
 *
 * Catch structured assembly of the 70-byte SwitchClassBRsp body. The 64B
 * middle has no crypto call producing it, so it MUST be written via byte
 * copies or memset init. Hook the three libc primitives and filter by RA
 * being inside lorabrd text (0x10000–0x80000) — skips the enormous noise
 * from libstdc++ / glibc internals.
 *
 * To avoid recursion, implement each op byte-by-byte internally. Slower
 * than the real glibc assembly versions, but it's only active for the
 * pairing window.
 *
 * Y3 update: the 70B grant turned out to be controller-generated and
 * arrives via JSON-RPC `sendMessage.data`, not built locally on the bridge.
 * These hooks are now noise — disabled when KEYHOOK_QUIET is set.
 */

#define FW_TEXT_LO 0x10000u
#define FW_TEXT_HI 0x80000u
#define MEM_MAX_LOG_BYTES 2048

static void *real_memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}

static void *real_memmove(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d == s || n == 0) return dst;
    if ((uintptr_t)d < (uintptr_t)s) {
        while (n--) *d++ = *s++;
    } else {
        d += n; s += n;
        while (n--) *--d = *--s;
    }
    return dst;
}

static void *real_memset(void *dst, int v, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    unsigned char c = (unsigned char)v;
    while (n--) *d++ = c;
    return dst;
}

static int ra_in_fw(const void *ra) {
    uintptr_t r = (uintptr_t)ra;
    return r >= FW_TEXT_LO && r < FW_TEXT_HI;
}

/* Size filter — capture likely field sizes (MAC, key, timing fields, full
 * body). Skip 1-3 byte writes (noisy and uninformative). */
static int interesting_size(size_t n) {
    if (n < 4) return 0;
    if (n > 256) return 0;
    return 1;
}

void *memcpy(void *dst, const void *src, size_t n) {
    const void *ra = __builtin_return_address(0);
    void *r = real_memcpy(dst, src, n);
    if (ra_in_fw(ra) && interesting_size(n) && bump()) {
        unsigned long cap = n < MEM_MAX_LOG_BYTES ? n : MEM_MAX_LOG_BYTES;
        wstr(logfd, "FUNC=memcpy\nRA=");  wptr(logfd, ra);
        wstr(logfd, "\nDST=");             wptr(logfd, dst);
        wstr(logfd, "\nSRC=");             wptr(logfd, src);
        wstr(logfd, "\nLEN=");             wdec(logfd, n);
        wstr(logfd, "\nDATA=");            whex(logfd, (const unsigned char *)dst, cap);
        wstr(logfd, "\n---\n");
    }
    return r;
}

void *memmove(void *dst, const void *src, size_t n) {
    const void *ra = __builtin_return_address(0);
    void *r = real_memmove(dst, src, n);
    if (ra_in_fw(ra) && interesting_size(n) && bump()) {
        unsigned long cap = n < MEM_MAX_LOG_BYTES ? n : MEM_MAX_LOG_BYTES;
        wstr(logfd, "FUNC=memmove\nRA="); wptr(logfd, ra);
        wstr(logfd, "\nDST=");             wptr(logfd, dst);
        wstr(logfd, "\nSRC=");             wptr(logfd, src);
        wstr(logfd, "\nLEN=");             wdec(logfd, n);
        wstr(logfd, "\nDATA=");            whex(logfd, (const unsigned char *)dst, cap);
        wstr(logfd, "\n---\n");
    }
    return r;
}

/* Manual ARM stack walker. Reads SP, scans upward, collects return-address
 * candidates that fall in the firmware text range. Works where GCC's
 * __builtin_return_address(N>0) returns NULL (target lacks frame pointers).
 *
 * For the memset(DST, 0, 70) case in particular:
 *   - ra0 (__builtin_return_address(0)) = 0x32679 (in sub_32650)
 *   - sub_32650 prologue: `push {r4, r5, r6, lr}` → its saved LR is the
 *     address we want (= caller of sub_32650 + 4)
 *   - The saved LR sits on the stack at a known offset relative to sub_32650's
 *     own SP, but by the time we run several frames have pushed/popped
 *     - so instead of a fixed offset we scan.
 */
static void walk_stack(uintptr_t sp, const void *ra0,
                       const void **slots, int max_slots) {
    int found = 0;
    for (int i = 0; i < 64 && found < max_slots; i++) {
        uintptr_t val = *(volatile uintptr_t *)(sp + (unsigned)i * 4);
        /* Firmware text range (lorabrd .text ends around 0xef000) */
        if (val >= FW_TEXT_LO && val < FW_TEXT_HI &&
            val != (uintptr_t)ra0) {
            slots[found++] = (const void *)val;
        }
    }
    while (found < max_slots) slots[found++] = 0;
}

void *memset(void *dst, int v, size_t n) {
    const void *ra0 = __builtin_return_address(0);
    uintptr_t sp;
    asm volatile ("mov %0, sp" : "=r"(sp));
    void *r = real_memset(dst, v, n);
    if (ra_in_fw(ra0) && interesting_size(n) && bump()) {
        const void *frames[4] = {0};
        walk_stack(sp, ra0, frames, 4);
        wstr(logfd, "FUNC=memset\nRA=");  wptr(logfd, ra0);
        wstr(logfd, "\nRA1=");             wptr(logfd, frames[0]);
        wstr(logfd, "\nRA2=");             wptr(logfd, frames[1]);
        wstr(logfd, "\nRA3=");             wptr(logfd, frames[2]);
        wstr(logfd, "\nRA4=");             wptr(logfd, frames[3]);
        wstr(logfd, "\nDST=");             wptr(logfd, dst);
        wstr(logfd, "\nVAL=");             wdec(logfd, (unsigned)v & 0xff);
        wstr(logfd, "\nLEN=");             wdec(logfd, n);
        wstr(logfd, "\n---\n");
    }
    return r;
}

#endif /* !KEYHOOK_QUIET (mem hooks) */

#ifndef KEYHOOK_QUIET
/* --- TCP send/recv hooks (TLS ciphertext) ---
 *
 * Hooking these on the controller WS socket gave us TLS-encrypted bytes —
 * useful before SSL_read/SSL_write hooks existed. Now superseded by the
 * SSL plaintext hooks below; disabled in quiet builds.
 */

typedef long ssize_t_t;  /* ssize_t — avoid pulling in the real header's typedef */

extern ssize_t_t sendto(int fd, const void *buf, size_t len, int flags,
                         const void *dst, unsigned int dstlen);
extern ssize_t_t recvfrom(int fd, void *buf, size_t len, int flags,
                           void *src, unsigned int *srclen);

#define SOCK_MAX_LOG_BYTES 2048

ssize_t_t send(int fd, const void *buf, size_t len, int flags) {
    const void *ra = __builtin_return_address(0);
    ssize_t_t r = sendto(fd, buf, len, flags, 0, 0);
    if (r > 0 && bump()) {
        size_t cap = (size_t)r < SOCK_MAX_LOG_BYTES ? (size_t)r : SOCK_MAX_LOG_BYTES;
        wstr(logfd, "FUNC=send\nFD=");  wdec(logfd, (unsigned)fd);
        wstr(logfd, "\nRA=");            wptr(logfd, ra);
        wstr(logfd, "\nLEN=");           wdec(logfd, (unsigned)r);
        wstr(logfd, "\nDATA=");          whex(logfd, (const unsigned char *)buf, cap);
        wstr(logfd, "\n---\n");
    }
    return r;
}

ssize_t_t recv(int fd, void *buf, size_t len, int flags) {
    const void *ra = __builtin_return_address(0);
    ssize_t_t r = recvfrom(fd, buf, len, flags, 0, 0);
    if (r > 0 && bump()) {
        size_t cap = (size_t)r < SOCK_MAX_LOG_BYTES ? (size_t)r : SOCK_MAX_LOG_BYTES;
        wstr(logfd, "FUNC=recv\nFD=");  wdec(logfd, (unsigned)fd);
        wstr(logfd, "\nRA=");            wptr(logfd, ra);
        wstr(logfd, "\nLEN=");           wdec(logfd, (unsigned)r);
        wstr(logfd, "\nDATA=");          whex(logfd, (const unsigned char *)buf, cap);
        wstr(logfd, "\n---\n");
    }
    return r;
}

#endif /* !KEYHOOK_QUIET (send/recv hooks) */

/* --- OpenSSL plaintext hooks ---
 *
 * lorabrd links libssl.so.3 + libcrypto.so.3 (confirmed via /proc/<pid>/maps
 * on the bridge). Hooking send/recv below gives us TLS ciphertext only.
 * Hooking SSL_read/SSL_write gives plaintext — i.e. the WebSocket-framed,
 * permessage-deflate-compressed controller<->bridge stream. A Python
 * post-processor (tools/keyhook/ssl_decode.py) parses WS framing and
 * inflates deflate to recover JSON-RPC.
 *
 * Notes on the hook:
 *   - We cache the real function pointer lazily via dlsym(RTLD_NEXT, ...).
 *   - Log the SSL* pointer so the post-processor can demux multiple
 *     simultaneous TLS connections (controller WS + any incidental HTTPS).
 *   - For SSL_write, dump plaintext BEFORE calling through so we capture
 *     the buffer the caller presented (SSL_write doesn't mutate it, but
 *     logging pre-call makes the ordering match the wire order with
 *     SSL_read's post-call dump).
 *   - Success for SSL_read/SSL_write: positive return. For _ex forms:
 *     returns 1 on success and writes *readbytes / *written.
 */

static int (*real_SSL_read)(void *, void *, int) = 0;
static int (*real_SSL_write)(void *, const void *, int) = 0;
static int (*real_SSL_read_ex)(void *, void *, size_t, size_t *) = 0;
static int (*real_SSL_write_ex)(void *, const void *, size_t, size_t *) = 0;

#define SSL_MAX_LOG_BYTES 4096

static void log_ssl(const char *func, const void *ssl, const void *ra,
                    const unsigned char *buf, size_t n) {
    if (!bump()) return;
    size_t cap = n < SSL_MAX_LOG_BYTES ? n : SSL_MAX_LOG_BYTES;
    wstr(logfd, "FUNC=");     wstr(logfd, func);
    wstr(logfd, "\nSSL=");    wptr(logfd, ssl);
    wstr(logfd, "\nRA=");     wptr(logfd, ra);
    wstr(logfd, "\nLEN=");    wdec(logfd, (unsigned long long)n);
    wstr(logfd, "\nDATA=");   whex(logfd, buf, cap);
    wstr(logfd, "\n---\n");
}

int SSL_read(void *ssl, void *buf, int num) {
    const void *ra = __builtin_return_address(0);
    if (!real_SSL_read)
        real_SSL_read = dlsym(RTLD_NEXT, "SSL_read");
    int r = real_SSL_read(ssl, buf, num);
    if (r > 0)
        log_ssl("ssl_read", ssl, ra, (const unsigned char *)buf, (size_t)r);
    return r;
}

int SSL_write(void *ssl, const void *buf, int num) {
    const void *ra = __builtin_return_address(0);
    if (!real_SSL_write)
        real_SSL_write = dlsym(RTLD_NEXT, "SSL_write");
    /* Log pre-call: the plaintext the caller handed us, whatever the
     * actual bytes-written count ends up being. Keeps wire ordering
     * deterministic when paired with SSL_read's post-call log. */
    if (num > 0)
        log_ssl("ssl_write", ssl, ra, (const unsigned char *)buf, (size_t)num);
    return real_SSL_write(ssl, buf, num);
}

int SSL_read_ex(void *ssl, void *buf, size_t num, size_t *readbytes) {
    const void *ra = __builtin_return_address(0);
    if (!real_SSL_read_ex)
        real_SSL_read_ex = dlsym(RTLD_NEXT, "SSL_read_ex");
    int rc = real_SSL_read_ex(ssl, buf, num, readbytes);
    if (rc == 1 && readbytes && *readbytes > 0)
        log_ssl("ssl_read_ex", ssl, ra, (const unsigned char *)buf, *readbytes);
    return rc;
}

int SSL_write_ex(void *ssl, const void *buf, size_t num, size_t *written) {
    const void *ra = __builtin_return_address(0);
    if (!real_SSL_write_ex)
        real_SSL_write_ex = dlsym(RTLD_NEXT, "SSL_write_ex");
    if (num > 0)
        log_ssl("ssl_write_ex", ssl, ra, (const unsigned char *)buf, num);
    return real_SSL_write_ex(ssl, buf, num, written);
}

/* --- read hook (file-source hunting for authorize EXPECTED) ---
 *
 * 2026-04-30: lorabrd's per-connection EXPECTED for authorize.secret memcmp
 * is generated/loaded somehow but is NOT caught by libsodium hooks. Likely
 * source: direct file read (lorabrd has fd 10 → /dev/urandom).
 *
 * Implementation: bypass libc entirely via direct ARM EABI syscall.
 * dlsym(RTLD_NEXT, "read") caused SIGSEGV during early init due to
 * recursion (dlsym uses read internally). The svc-based syscall avoids
 * that completely.
 *
 * Filter:
 *   - RA in lorabrd .text range (0x10000..0xef000) — skips ld.so / libc reads
 *   - Read length 4..256 bytes — crypto-sized
 *
 * Build with -DKEYHOOK_QUIET=1 — without that flag, the memcpy/memmove
 * hooks above produce a binary that crashes early (something in their
 * pass-through logic interacts badly with libstdc++ init).
 */
#include <sys/types.h>
#include <errno.h>

/* Direct ARM EABI syscall for read(). r0..r2 = args, r7 = syscall #,
 * result back in r0. Use "+r" (in-out) on r0 — declaring two register
 * variables on the same physical register (separate input + output) is
 * undefined and was the bug in our first attempt. */
static ssize_t kh_syscall_read(int fd, void *buf, size_t count) {
    register int r0 asm("r0") = fd;
    register void *r1 asm("r1") = buf;
    register size_t r2 asm("r2") = count;
    register int r7 asm("r7") = 3;  /* __NR_read on ARM EABI */
    asm volatile("svc 0"
                 : "+r"(r0)
                 : "r"(r1), "r"(r2), "r"(r7)
                 : "memory");
    if (r0 < 0 && r0 > -4096) {
        errno = -r0;
        return -1;
    }
    return r0;
}

ssize_t read(int fd, void *buf, size_t count) {
    const void *ra = __builtin_return_address(0);
    ssize_t r = kh_syscall_read(fd, buf, count);
    /* Log all reads up to 4KB. Inside this we cap captured bytes at 256
     * but report the actual length so we can spot 4KB entropy-pool seeds.
     * Skip very large (file-slurp) reads to keep log size reasonable. */
    if (r > 0 && r >= 4 && r <= 4096 && bump()) {
        size_t cap = (size_t)r < 256 ? (size_t)r : 256;
        wstr(logfd, "FUNC=read\nRA=");  wptr(logfd, ra);
        wstr(logfd, "\nFD=");            wdec(logfd, (unsigned)fd);
        wstr(logfd, "\nLEN=");           wdec(logfd, (unsigned long long)r);
        wstr(logfd, "\nDATA=");          whex(logfd, (const unsigned char *)buf, cap);
        wstr(logfd, "\n---\n");
    }
    return r;
}

/* getrandom() — modern glibc's preferred random source. libsodium uses this
 * over /dev/urandom when available. Direct syscall same as read.
 * Linux: __NR_getrandom = 384 on ARM EABI. Args: (buf, buflen, flags). */
static ssize_t kh_syscall_getrandom(void *buf, size_t buflen, unsigned int flags) {
    register void *r0 asm("r0") = buf;
    register size_t r1 asm("r1") = buflen;
    register unsigned int r2 asm("r2") = flags;
    register int r7 asm("r7") = 384;
    asm volatile("svc 0"
                 : "+r"(r0)
                 : "r"(r1), "r"(r2), "r"(r7)
                 : "memory");
    long ret = (long)r0;
    if (ret < 0 && ret > -4096) {
        errno = (int)-ret;
        return -1;
    }
    return ret;
}

ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
    const void *ra = __builtin_return_address(0);
    ssize_t r = kh_syscall_getrandom(buf, buflen, flags);
    if (r > 0 && bump()) {
        size_t cap = (size_t)r < 256 ? (size_t)r : 256;
        wstr(logfd, "FUNC=getrandom\nRA=");  wptr(logfd, ra);
        wstr(logfd, "\nLEN=");                wdec(logfd, (unsigned long long)r);
        wstr(logfd, "\nFLAGS=");              wdec(logfd, (unsigned long long)flags);
        wstr(logfd, "\nDATA=");               whex(logfd, (const unsigned char *)buf, cap);
        wstr(logfd, "\n---\n");
    }
    return r;
}
