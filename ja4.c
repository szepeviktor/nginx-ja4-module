#include "ja4.h"

#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { const unsigned char *p; size_t n; } cursor;
typedef struct { uint16_t *v; size_t n; } ids;

static int take(cursor *c, size_t n, cursor *out)
{
    if (n > c->n) return 0;
    out->p = c->p; out->n = n;
    c->p += n; c->n -= n;
    return 1;
}

static unsigned u16(const unsigned char *p)
{
    return ((unsigned)p[0] << 8) | p[1];
}

static int vector(cursor *c, unsigned bytes, cursor *out)
{
    cursor size;
    if (!take(c, bytes, &size)) return 0;
    return take(c, bytes == 1 ? size.p[0] : u16(size.p), out);
}

static int grease(unsigned n)
{
    return (n & 0x0f0f) == 0x0a0a && (n >> 8) == (n & 255);
}

static int compare_id(const void *a, const void *b)
{
    return (int)*(const uint16_t *)a - (int)*(const uint16_t *)b;
}

static void collect(ids *out, cursor data)
{
    size_t i;
    for (i = 0; i < data.n; i += 2) {
        unsigned n = u16(data.p + i);
        if (!grease(n)) out->v[out->n++] = (uint16_t)n;
    }
}

static char *format_ids(char *out, ids list)
{
    size_t i;
    for (i = 0; i < list.n; ++i) {
        if (i) *out++ = ',';
        snprintf(out, 5, "%04x", (unsigned)list.v[i]);
        out += 4;
    }
    *out = '\0';
    return out;
}

static int hash12(const char *text, char out[13])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned n, i;
    if (!EVP_Digest(text, strlen(text), digest, &n, EVP_sha256(), NULL) || n < 6)
        return 0;
    for (i = 0; i < 6; ++i) snprintf(out + 2 * i, 3, "%02x", digest[i]);
    return 1;
}

static int alnum_ascii(unsigned c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z');
}

static const char *version_name(unsigned n)
{
    switch (n) {
    case 0x0304: return "13";
    case 0x0303: return "12";
    case 0x0302: return "11";
    case 0x0301: return "10";
    case 0x0300: return "s3";
    case 0x0002: return "s2";
    default: return "00";
    }
}

int ja4_compute(const unsigned char *message, size_t length, ja4_result *result)
{
    cursor c, part, cipherdata, extdata, e, data, list;
    ids ciphers = {0}, extensions = {0}, signatures = {0};
    unsigned version, type, ext_count = 0, has_sni = 0;
    unsigned char seen[8192] = {0};
    char alpn[3] = "00", prefix[11], b[13] = "000000000000";
    char h[13] = "000000000000", *raw = NULL, *cipherstr, *extstr, *sigstr, *end;
    size_t capacity, i;
    int ok = 0;

    if (!result) return 0;
    memset(result, 0, sizeof(*result));
    if (!message || length < 4 || length > 131072 || message[0] != 1 ||
        (((size_t)message[1] << 16) | ((size_t)message[2] << 8) | message[3]) != length - 4)
        return 0;
    c.p = message + 4; c.n = length - 4;
    if (!take(&c, 34, &part)) return 0;
    version = u16(part.p);
    if (!vector(&c, 1, &part) || part.n > 32 ||
        !vector(&c, 2, &cipherdata) || cipherdata.n % 2 ||
        !vector(&c, 1, &part) || part.n == 0) return 0;
    extdata.p = c.p; extdata.n = 0;
    if (c.n && (!vector(&c, 2, &extdata) || c.n)) return 0;

    /* At most one ID per two bytes; bounded by the input cap above. */
    capacity = length / 2 + 1;
    ciphers.v = malloc(capacity * sizeof(uint16_t));
    extensions.v = malloc(capacity * sizeof(uint16_t));
    signatures.v = malloc(capacity * sizeof(uint16_t));
    if (!ciphers.v || !extensions.v || !signatures.v) goto done;
    collect(&ciphers, cipherdata);
    e = extdata;
    while (e.n) {
        if (!take(&e, 2, &part)) goto done;
        type = u16(part.p);
        if (seen[type / 8] & (1u << (type % 8))) goto done;
        seen[type / 8] |= (unsigned char)(1u << (type % 8));
        if (!vector(&e, 2, &data)) goto done;
        if (!grease(type)) {
            ++ext_count;
            if (type != 0 && type != 16) extensions.v[extensions.n++] = (uint16_t)type;
        }
        if (type == 0) has_sni = 1;
        else if (type == 43) {
            if (!vector(&data, 1, &list) || data.n || list.n % 2) goto done;
            version = 0;
            for (i = 0; i < list.n; i += 2) {
                unsigned v = u16(list.p + i);
                if (!grease(v) && v > version) version = v;
            }
        }
        else if (type == 13) {
            if (!vector(&data, 2, &list) || data.n || list.n % 2) goto done;
            collect(&signatures, list); /* Signature order is significant. */
        }
        else if (type == 16) {
            int first = 1;
            if (!vector(&data, 2, &list) || data.n) goto done;
            while (list.n) {
                if (!vector(&list, 1, &part)) goto done;
                if (first && part.n) {
                    unsigned a = part.p[0], z = part.p[part.n - 1];
                    if (alnum_ascii(a) && alnum_ascii(z)) {
                        alpn[0] = (char)a; alpn[1] = (char)z;
                    }
                    else {
                        const char *hex = "0123456789abcdef";
                        alpn[0] = hex[a >> 4]; alpn[1] = hex[z & 15];
                    }
                }
                first = 0;
            }
        }
    }
    qsort(ciphers.v, ciphers.n, sizeof(uint16_t), compare_id);
    qsort(extensions.v, extensions.n, sizeof(uint16_t), compare_id);
    snprintf(prefix, sizeof(prefix), "t%s%c%02u%02u%s", version_name(version),
             has_sni ? 'd' : 'i', (unsigned)(ciphers.n > 99 ? 99 : ciphers.n),
             ext_count > 99 ? 99 : ext_count, alpn);
    raw = malloc(16 + 5 * (ciphers.n + extensions.n + signatures.n));
    if (!raw) goto done;
    memcpy(raw, prefix, 10); raw[10] = '_';
    cipherstr = raw + 11;
    end = format_ids(cipherstr, ciphers);
    if (ciphers.n && !hash12(cipherstr, b)) goto done;
    *end++ = '_'; extstr = end;
    end = format_ids(end, extensions);
    /* Hash before the final raw separator when no signature list exists. */
    if (!signatures.n && extensions.n && !hash12(extstr, h)) goto done;
    *end++ = '_'; sigstr = end;
    format_ids(sigstr, signatures);
    if (signatures.n && extensions.n && !hash12(extstr, h)) goto done;
    snprintf(result->fingerprint, sizeof(result->fingerprint), "%s_%s_%s", prefix, b, h);
    result->raw = raw; raw = NULL;
    ok = 1;
done:
    free(raw); free(ciphers.v); free(extensions.v); free(signatures.v);
    return ok;
}
