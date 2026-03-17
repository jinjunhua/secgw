#ifndef GM_SM4_H
#define GM_SM4_H

#include <stdint.h>
#include <stddef.h>

#define SM4_KEY_SIZE    16
#define SM4_BLOCK_SIZE  16

typedef struct {
    uint32_t rk[32]; /* round keys */
} sm4_ctx_t;

/* Key schedule */
void sm4_set_key_enc(sm4_ctx_t *ctx, const uint8_t key[SM4_KEY_SIZE]);
void sm4_set_key_dec(sm4_ctx_t *ctx, const uint8_t key[SM4_KEY_SIZE]);

/* Single-block ECB */
void sm4_encrypt(const sm4_ctx_t *ctx, const uint8_t in[SM4_BLOCK_SIZE], uint8_t out[SM4_BLOCK_SIZE]);
void sm4_decrypt(const sm4_ctx_t *ctx, const uint8_t in[SM4_BLOCK_SIZE], uint8_t out[SM4_BLOCK_SIZE]);

/* CBC mode */
void sm4_cbc_encrypt(const sm4_ctx_t *ctx, const uint8_t *iv,
                     const uint8_t *in, uint8_t *out, size_t len);
void sm4_cbc_decrypt(const sm4_ctx_t *ctx, const uint8_t *iv,
                     const uint8_t *in, uint8_t *out, size_t len);

/* CTR mode */
void sm4_ctr_crypt(const sm4_ctx_t *ctx, uint8_t *ctr,
                   const uint8_t *in, uint8_t *out, size_t len);

/* GCM mode */
int  sm4_gcm_encrypt(const uint8_t key[SM4_KEY_SIZE],
                     const uint8_t *iv,  size_t iv_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *in,  size_t in_len,
                     uint8_t *out, uint8_t *tag, size_t tag_len);
int  sm4_gcm_decrypt(const uint8_t key[SM4_KEY_SIZE],
                     const uint8_t *iv,  size_t iv_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *in,  size_t in_len,
                     uint8_t *out,
                     const uint8_t *tag, size_t tag_len);

#endif /* GM_SM4_H */
