#ifndef GM_SM3_H
#define GM_SM3_H

#include <stdint.h>
#include <stddef.h>

#define SM3_DIGEST_SIZE   32
#define SM3_BLOCK_SIZE    64
#define SM3_HMAC_SIZE     32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[SM3_BLOCK_SIZE];
} sm3_ctx_t;

void sm3_init(sm3_ctx_t *ctx);
void sm3_update(sm3_ctx_t *ctx, const uint8_t *data, size_t len);
void sm3_final(sm3_ctx_t *ctx, uint8_t digest[SM3_DIGEST_SIZE]);
void sm3(const uint8_t *data, size_t len, uint8_t digest[SM3_DIGEST_SIZE]);

/* HMAC-SM3 */
void sm3_hmac(const uint8_t *key, size_t key_len,
              const uint8_t *data, size_t data_len,
              uint8_t mac[SM3_HMAC_SIZE]);

#endif /* GM_SM3_H */
