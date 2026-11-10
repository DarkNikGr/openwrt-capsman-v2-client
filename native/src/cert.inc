/* cert.inc — CAP certificate lifecycle for CAPsMAN v2 (W16/W43).
 *
 * Protocol facts established in /tmp/opencode/work-W16/REPORT.md:
 *   - join 0x4029 may carry 0x76 = PKCS#10 CSR (DER).  The manager signs it
 *     with its auto-generated CAPsMAN CA and returns, in the same 0xc029:
 *       0x77 = issued leaf certificate (DER, key type preserved from CSR)
 *       0x78 = CA certificate / chain (DER)
 *       0xa7 = manager protocol version (1 byte, 0x01)
 *       0x46 = manager boot nonce (8 bytes, not an echo of the CAP nonce)
 *   - a CAP with no certificate at all can join and enrol, provided the
 *     manager has require-peer-certificate=no (the RouterOS default).
 *   - a join error is 0xc029 { 0x0001 = u32 code, 0x0002 = ASCII message }.
 *     Re-enrolling an already-issued CN yields code 2,
 *     "certificate issue failed - a valid certificate with the same common
 *      name already exists!".
 *   - the 0x77 certificate keeps the CSR public key and is directly usable
 *     as the TLS client certificate on later joins.
 *
 * This module implements: key generation, CSR, join-response parsing,
 * chain/key validation, atomic persistence, expiry check and re-enrolment.
 * It is included after util.inc (put_el/find_el/read_exact) and before
 * discovery.inc (connect_tls uses cert_key_ok()).
 *
 * W43: the join response is not read synchronously.  It stays in the main
 * poll loop, where cert_handle_join_resp() recognises a certificate reply
 * (0x77 DER leaf + 0x78 CA) or an error reply (0x0001+0x0002) and lets
 * apply.inc's handle_c029() deal with the M2 configuration tree as before.
 */

#include "mbedtls/x509_csr.h"
#include "mbedtls/ecp.h"
#include "mbedtls/base64.h"

#define CERT_CN_MAX      128
#define CERT_CSR_MAX     2048

/* Return codes of cert_handle_join_resp(). */
#define CERT_RESP_NONE      0   /* not a certificate/error reply            */
#define CERT_RESP_ENROLLED  1   /* leaf+CA validated and stored             */
#define CERT_RESP_IGNORED   2   /* certificate reply, nothing to do         */
#define CERT_RESP_DUP      -1   /* duplicate CN: retry with a fresh CN      */
#define CERT_RESP_ERROR    -2   /* other join error (code != duplicate)     */

/* State shared with the main loop for one run_once() attempt. */
static mbedtls_pk_context *g_cert_pk;      /* key the CSR was made with     */
static mbedtls_ctr_drbg_context *g_cert_ctr;
static const struct cfg *g_cert_cfg;
static char g_cert_cn[CERT_CN_MAX];
static int g_cert_enrolling;
static int g_cert_dup;                     /* last attempt hit a duplicate CN */
static int g_cert_fail_streak;             /* consecutive enrolment failures */

static int cert_write_all(const char *path, const void *data, size_t len,
                          int mode)
{
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) return -1;
    const uint8_t *p = data;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, p + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd); unlink(tmp); return -1;
        }
        off += (size_t)w;
    }
    fsync(fd);                       /* best effort on overlayfs */
    close(fd);
    chmod(tmp, mode);
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

/* DER SEQUENCE length -> total bytes, 0 if not a well-formed certificate. */
static size_t cert_der_total(const uint8_t *p, size_t n)
{
    if (n < 2 || p[0] != 0x30) return 0;
    size_t hdr, len;
    if (p[1] < 0x80) { hdr = 2; len = p[1]; }
    else {
        size_t k = p[1] & 0x7f;
        if (k == 0 || k > 4 || n < 2 + k) return 0;
        len = 0;
        for (size_t i = 0; i < k; i++) len = (len << 8) | p[2 + i];
        hdr = 2 + k;
    }
    if (len == 0 || hdr + len > n) return 0;
    return hdr + len;
}

static int cert_pem_block(FILE *f, const uint8_t *der, size_t len)
{
    size_t olen = 0;
    int r = mbedtls_base64_encode(NULL, 0, &olen, der, len);
    if (r != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL && r != 0) return -1;
    char *b64 = malloc(olen + 1);
    if (!b64) return -1;
    if ((r = mbedtls_base64_encode((unsigned char *)b64, olen, &olen,
                                   der, len)) != 0) {
        free(b64);
        return -1;
    }
    b64[olen] = 0;
    fprintf(f, "-----BEGIN CERTIFICATE-----\n");
    for (size_t i = 0; i < olen; i += 64)
        fprintf(f, "%.*s\n", (int)(olen - i < 64 ? olen - i : 64), b64 + i);
    fprintf(f, "-----END CERTIFICATE-----\n");
    free(b64);
    return 0;
}

/* Write one or more concatenated DER certificates as PEM. */
static int cert_write_cert_pem(const char *path, const uint8_t *der,
                               size_t len, int mode)
{
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    size_t off = 0, wrote = 0;
    while (off < len) {
        size_t one = cert_der_total(der + off, len - off);
        if (!one) break;
        if (cert_pem_block(f, der + off, one) != 0) {
            fclose(f); unlink(tmp); return -1;
        }
        off += one;
        wrote++;
    }
    if (!wrote && cert_pem_block(f, der, len) != 0) {
        fclose(f); unlink(tmp); return -1;
    }
    fflush(f); fsync(fileno(f)); fclose(f);
    chmod(tmp, mode);
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

static int cert_key_pem(const char *path, mbedtls_pk_context *pk)
{
    unsigned char buf[4096];
    int r = mbedtls_pk_write_key_pem(pk, buf, sizeof(buf));
    if (r != 0) return -1;
    return cert_write_all(path, buf, strlen((char *)buf), 0600);
}

static const char *cert_dir_of(const char *path, char *out, size_t n)
{
    snprintf(out, n, "%s", path ? path : "/etc/cap/client.pem");
    char *slash = strrchr(out, '/');
    if (slash && slash != out) *slash = 0;
    else snprintf(out, n, ".");
    return out;
}

static int cert_mkdirs(const char *file)
{
    char dir[256];
    cert_dir_of(file, dir, sizeof(dir));
    return mkdir(dir, 0700);            /* EEXIST is fine */
}

static int cert_file_ok(const char *path)
{
    struct stat st;
    return path && *path && stat(path, &st) == 0 && st.st_size > 0;
}

static int cert_key_ok(const struct cfg *c)
{
    return cert_file_ok(c->cert) && cert_file_ok(c->key);
}

static int cert_is_expired(const struct cfg *c)
{
    if (!cert_file_ok(c->cert)) return 1;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int r = mbedtls_x509_crt_parse_file(&crt, c->cert);
    int past = 1;
    if (r == 0) past = mbedtls_x509_time_is_past(&crt.valid_to);
    mbedtls_x509_crt_free(&crt);
    return past;
}

/* Subject of the stored certificate, for the "using stored certificate"
 * log line.  Returns "-" when the file cannot be parsed. */
static const char *cert_stored_subject(const struct cfg *c)
{
    static char subj[192] = "-";
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    subj[0] = 0;
    if (mbedtls_x509_crt_parse_file(&crt, c->cert) == 0)
        mbedtls_x509_dn_gets(subj, sizeof(subj), &crt.subject);
    mbedtls_x509_crt_free(&crt);
    return subj[0] ? subj : "-";
}

static void cert_sanitize(const char *in, char *out, size_t n)
{
    size_t j = 0;
    for (size_t i = 0; in && in[i] && j + 1 < n; i++) {
        unsigned char ch = (unsigned char)in[i];
        if (isalnum(ch) || ch == '-' || ch == '_' || ch == '.')
            out[j++] = (char)ch;
        else
            out[j++] = '-';
    }
    out[j] = 0;
}

/* Stable-ish CN base: identity, /etc/cap/identity, hostname, fallback. */
static void cert_identity(const struct cfg *c, char *out, size_t n)
{
    out[0] = 0;
    if (c->identity && *c->identity)
        snprintf(out, n, "%s", c->identity);
    if (!out[0]) read_trim("/etc/cap/identity", out, n);
    if (!out[0]) read_trim("/proc/sys/kernel/hostname", out, n);
    if (!out[0]) snprintf(out, n, "OpenWrt-CAP");
    out[strcspn(out, "\r\n")] = 0;
}

/* Enrolment CN.  A random suffix is deliberate: RouterOS refuses to issue a
 * second certificate for a CN that already exists, and a factory-reset CAP
 * has lost its old certificate while the manager still remembers the CN.
 * After a duplicate-CN rejection even a fixed --cert-cn gets a random suffix
 * so the retry can make progress. */
static void cert_make_cn(const struct cfg *c, char *out, size_t n,
                         mbedtls_ctr_drbg_context *ctr)
{
    char base[96], clean[96];
    if (c->cert_cn && *c->cert_cn && !g_cert_dup) {
        snprintf(out, n, "%s", c->cert_cn);
        return;
    }
    if (c->cert_cn && *c->cert_cn && g_cert_dup) {
        cert_sanitize(c->cert_cn, clean, sizeof(clean));
    } else {
        cert_identity(c, base, sizeof(base));
        cert_sanitize(base, clean, sizeof(clean));
    }
    if (!clean[0]) snprintf(clean, sizeof(clean), "OpenWrt-CAP");
    unsigned char rnd[4] = {0};
    if (!ctr || mbedtls_ctr_drbg_random(ctr, rnd, sizeof(rnd)) != 0) {
        uint32_t t = (uint32_t)time(NULL);
        memcpy(rnd, &t, sizeof(t));
    }
    snprintf(out, n, "%s-%02x%02x%02x%02x", clean,
             rnd[0], rnd[1], rnd[2], rnd[3]);
}

static int cert_gen_key(mbedtls_pk_context *pk, mbedtls_ctr_drbg_context *ctr)
{
    mbedtls_pk_init(pk);
    int r = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (r != 0) return r;
    /* P-256: ~4x faster than RSA-2048 on mt7621 and accepted by 7.25.1. */
    return mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(*pk),
                               mbedtls_ctr_drbg_random, ctr);
}

static int cert_make_csr(const char *cn, mbedtls_pk_context *pk,
                         mbedtls_ctr_drbg_context *ctr,
                         uint8_t *out, size_t outmax, size_t *outlen)
{
    mbedtls_x509write_csr csr;
    uint8_t buf[CERT_CSR_MAX];      /* enough for P-256 and RSA-2048 CSR */
    char subj[CERT_CN_MAX + 8];
    int r;

    if (strlen(cn) + 4 >= sizeof(subj)) return -1;
    snprintf(subj, sizeof(subj), "CN=%s", cn);

    mbedtls_x509write_csr_init(&csr);
    mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_key(&csr, pk);
    if ((r = mbedtls_x509write_csr_set_subject_name(&csr, subj)) != 0)
        goto bad;
    /* mbedtls writes DER at the END of buf and returns the length. */
    r = mbedtls_x509write_csr_der(&csr, buf, sizeof(buf),
                                  mbedtls_ctr_drbg_random, ctr);
    if (r <= 0 || (size_t)r > outmax) goto bad;
    memcpy(out, buf + sizeof(buf) - (size_t)r, (size_t)r);
    *outlen = (size_t)r;
    mbedtls_x509write_csr_free(&csr);
    return 0;
bad:
    mbedtls_x509write_csr_free(&csr);
    return -1;
}

/* Verify leaf -> CA chain and leaf public key == our private key. */
static int cert_validate(const uint8_t *cert, size_t certlen,
                         const uint8_t *ca, size_t calen,
                         mbedtls_pk_context *pk,
                         mbedtls_ctr_drbg_context *ctr,
                         char *subject, size_t subjn)
{
    mbedtls_x509_crt crt, chain;
    uint32_t flags = 0;
    int r;

    mbedtls_x509_crt_init(&crt);
    mbedtls_x509_crt_init(&chain);

    if ((r = mbedtls_x509_crt_parse_der(&crt, cert, certlen)) != 0) goto bad;
    size_t off = 0;
    while (off < calen) {
        size_t one = cert_der_total(ca + off, calen - off);
        if (!one) break;
        if ((r = mbedtls_x509_crt_parse_der(&chain, ca + off, one)) != 0)
            goto bad;
        off += one;
    }
    if (!off && (r = mbedtls_x509_crt_parse_der(&chain, ca, calen)) != 0)
        goto bad;

    if ((r = mbedtls_x509_crt_verify(&crt, &chain, NULL, NULL, &flags,
                                     NULL, NULL)) != 0 || flags != 0)
        goto bad;
    if ((r = mbedtls_pk_check_pair(&crt.pk, pk,
                                   mbedtls_ctr_drbg_random, ctr)) != 0)
        goto bad;
    if (subject && subjn)
        mbedtls_x509_dn_gets(subject, subjn, &crt.subject);
    mbedtls_x509_crt_free(&crt);
    mbedtls_x509_crt_free(&chain);
    return 0;
bad:
    if (subject && subjn) subject[0] = 0;
    mbedtls_x509_crt_free(&crt);
    mbedtls_x509_crt_free(&chain);
    return -1;
}

/* Persist key+cert+CA.  Called only after cert_validate(). */
static int cert_save(const struct cfg *c, const uint8_t *cert, size_t certlen,
                     const uint8_t *ca, size_t calen, mbedtls_pk_context *pk,
                     mbedtls_ctr_drbg_context *ctr, const char *cn)
{
    char subj[256];
    if (cert_mkdirs(c->cert) != 0 && errno != EEXIST) { /* try anyway */ }
    if (cert_validate(cert, certlen, ca, calen, pk, ctr, subj, sizeof(subj)) != 0) {
        fprintf(stderr, "cert: issued certificate does not verify against "
                        "0x78/key (CN=%s)\n", cn ? cn : "-");
        return -1;
    }
    if (cert_key_pem(c->key, pk) != 0) {
        fprintf(stderr, "cert: cannot write %s\n", c->key);
        return -1;
    }
    if (cert_write_cert_pem(c->cert, cert, certlen, 0644) != 0) {
        fprintf(stderr, "cert: cannot write %s\n", c->cert);
        return -1;
    }
    if (ca && calen && c->ca_cert && *c->ca_cert) {
        if (cert_write_cert_pem(c->ca_cert, ca, calen, 0644) != 0) {
            fprintf(stderr, "cert: cannot write %s\n", c->ca_cert);
            return -1;
        }
    }
    printf("cert: enrolled CN=%s subject=%s key=%s ca=%s\n",
           cn ? cn : "-", subj, c->key, c->ca_cert ? c->ca_cert : "-");
    fflush(stdout);
    g_cert_fail_streak = 0;
    g_cert_dup = 0;
    return 0;
}

/* True when a 0xc029 body is a certificate reply: a well-formed DER 0x77
 * plus a 0x78 chain.  A configuration 0x77 (M2 tree) never has both. */
static int cert_is_reply(const uint8_t *body, uint16_t len,
                         const uint8_t **cert, uint16_t *certlen,
                         const uint8_t **ca, uint16_t *calen)
{
    const uint8_t *t = NULL, *a = NULL;
    uint16_t tl = 0, al = 0;
    if (!find_el(body, len, 0x77, &t, &tl) || !tl) return 0;
    if (!find_el(body, len, 0x78, &a, &al) || !al) return 0;
    if (cert_der_total(t, tl) != tl) return 0;
    if (cert && certlen) { *cert = t; *certlen = tl; }
    if (ca && calen) { *ca = a; *calen = al; }
    return 1;
}

/* Called from the main poll loop for every 0xc029.  Returns
 * CERT_RESP_NONE when the body is a configuration push and apply.inc's
 * handle_c029() must run, CERT_RESP_ENROLLED on success and the error codes
 * otherwise. */
static int cert_handle_join_resp(const uint8_t *body, uint16_t len)
{
    const uint8_t *cert = NULL, *ca = NULL, *ev = NULL, *em = NULL;
    uint16_t certlen = 0, calen = 0, evlen = 0, emlen = 0;

    if (cert_is_reply(body, len, &cert, &certlen, &ca, &calen)) {
        if (!g_cert_enrolling || !g_cert_pk) {
            /* The manager never issues without a CSR; do not let a stray
             * 0x77/0x78 pair reach the M2 config parser. */
            fprintf(stderr, "cert: manager issued a certificate although no "
                            "CSR was sent; ignoring\n");
            return CERT_RESP_IGNORED;
        }
        if (cert_save(g_cert_cfg, cert, certlen, ca, calen, g_cert_pk,
                      g_cert_ctr, g_cert_cn) != 0) {
            g_cert_fail_streak++;
            return CERT_RESP_ERROR;
        }
        /* The CA may have changed.  g_ca is reset at the start of the next
         * run_once(), not here: the live TLS session may still reference it. */
        return CERT_RESP_ENROLLED;
    }

    /* Join error: { 0x0001 = u32 code, 0x0002 = message }.  Only when there
     * is no 0x77, so an M2 tree that happens to use tag 0x0001 is safe. */
    if (find_el(body, len, 0x77, &cert, &certlen) && certlen) return CERT_RESP_NONE;
    if (!find_el(body, len, 0x0001, &ev, &evlen) || evlen < 4) return CERT_RESP_NONE;
    find_el(body, len, 0x0002, &em, &emlen);
    char msg[192];
    snprintf(msg, sizeof(msg), "%.*s", (int)(emlen < sizeof(msg) - 1
                                              ? emlen : sizeof(msg) - 1),
             em ? (const char *)em : "");
    uint32_t code = rd32(ev);
    fprintf(stderr, "cert: join failed: code=%u msg=%s\n", code, msg);
    g_cert_fail_streak++;
    if (code == 2 && (strstr(msg, "same common name") ||
                      strstr(msg, "already exists"))) {
        g_cert_dup = 1;
        if (g_cert_cfg && g_cert_cfg->cert_cn && *g_cert_cfg->cert_cn)
            fprintf(stderr, "cert: manager reports a duplicate CN (%s); "
                            "retrying with a random suffix\n", g_cert_cn);
        else
            fprintf(stderr, "cert: manager reports a duplicate CN (%s); "
                            "retrying with a fresh CN\n", g_cert_cn);
        return CERT_RESP_DUP;
    }
    return CERT_RESP_ERROR;
}

/* Delay before the next reconnect.  5 s normally; doubled for each
 * consecutive certificate failure, capped at 60 s (never a busy loop). */
static int cert_retry_delay(void)
{
    int d = 5;
    for (int i = 1; i < g_cert_fail_streak && d < 60; i++) d *= 2;
    return d > 60 ? 60 : d;
}
