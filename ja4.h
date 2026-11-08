#ifndef JA4_H
#define JA4_H

#include <stddef.h>

typedef struct {
    char fingerprint[37];
    char *raw;
} ja4_result;

/* Complete TLS handshake message, including its four-byte handshake header.
 * Returns 1 on success, 0 on malformed input or allocation/hash failure.
 * The caller owns result->raw and must free it after success. */
int ja4_compute(const unsigned char *message, size_t length, ja4_result *result);

#endif
