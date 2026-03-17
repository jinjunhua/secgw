/*
 * SM3 Hash Algorithm implementation
 * Reference: GM/T 0004-2012
 */
#include "sm3.h"
#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define T(j) (((j) < 16) ? 0x79cc4519u : 0x7a879d8au)
#define FF(x, y, z, j) (((j) < 16) ? ((x) ^ (y) ^ (z)) : (((x) & (y)) | ((x) & (z)) | ((y) & (z))))
#define GG(x, y, z, j) (((j) < 16) ? ((x) ^ (y) ^ (z)) : (((x) & (y)) | ((~(x)) & (z))))
#define P0(x) ((x) ^ ROTL32((x), 9)  ^ ROTL32((x), 17))
#define P1(x) ((x) ^ ROTL32((x), 15) ^ ROTL32((x), 23))

static const uint32_t SM3_IV[8] = {
    0x7380166fu, 0x4914b2b9u, 0x172442d7u, 0xda8a0600u,
    0xa96f30bcu, 0x163138aau, 0xe38dee4du, 0xb0fb0e4eu
};

static inline uint32_t get_uint32_be(const uint8_t *b, int i)
{
    return ((uint32_t)b[i]     << 24) |
           ((uint32_t)b[i + 1] << 16) |
           ((uint32_t)b[i + 2] <<  8) |
           ((uint32_t)b[i + 3]);
}

static inline void put_uint32_be(uint8_t *b, int i, uint32_t n)
{
    b[i]     = (uint8_t)(n >> 24);
    b[i + 1] = (uint8_t)(n >> 16);
    b[i + 2] = (uint8_t)(n >>  8);
    b[i + 3] = (uint8_t)(n);
}

static void sm3_compress(uint32_t state[8], const uint8_t block[SM3_BLOCK_SIZE])
{
    uint32_t W[68], W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    int j;

    for (j = 0; j < 16; j++)
        W[j] = get_uint32_be(block, j * 4);

    for (j = 16; j < 68; j++)
        W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL32(W[j-3], 15))
               ^ ROTL32(W[j-13], 7) ^ W[j-6];

    for (j = 0; j < 64; j++)
        W1[j] = W[j] ^ W[j + 4];

    A = state[0]; B = state[1]; C = state[2]; D = state[3];
    E = state[4]; F = state[5]; G = state[6]; H = state[7];

    for (j = 0; j < 64; j++) {
        SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(T(j), j % 32), 7);
        SS2 = SS1 ^ ROTL32(A, 12);
        TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
        TT2 = GG(E, F, G, j) + H + SS1 + W[j];
        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }

    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

void sm3_init(sm3_ctx_t *ctx)
{
    memcpy(ctx->state, SM3_IV, sizeof(SM3_IV));
    ctx->count = 0;
    memset(ctx->buf, 0, sizeof(ctx->buf));
}

void sm3_update(sm3_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t fill = (size_t)(ctx->count % SM3_BLOCK_SIZE);
    size_t left = SM3_BLOCK_SIZE - fill;

    ctx->count += (uint64_t)len;

    if (fill && len >= left) {
        memcpy(ctx->buf + fill, data, left);
        sm3_compress(ctx->state, ctx->buf);
        data += left;
        len  -= left;
        fill  = 0;
    }

    while (len >= SM3_BLOCK_SIZE) {
        sm3_compress(ctx->state, data);
        data += SM3_BLOCK_SIZE;
        len  -= SM3_BLOCK_SIZE;
    }

    if (len > 0)
        memcpy(ctx->buf + fill, data, len);
}

void sm3_final(sm3_ctx_t *ctx, uint8_t digest[SM3_DIGEST_SIZE])
{
    uint8_t msglen[8];
    uint64_t bits = ctx->count * 8;
    uint8_t pad = 0x80;
    size_t fill = (size_t)(ctx->count % SM3_BLOCK_SIZE);

    /* encode bit length in big-endian */
    msglen[0] = (uint8_t)(bits >> 56);
    msglen[1] = (uint8_t)(bits >> 48);
    msglen[2] = (uint8_t)(bits >> 40);
    msglen[3] = (uint8_t)(bits >> 32);
    msglen[4] = (uint8_t)(bits >> 24);
    msglen[5] = (uint8_t)(bits >> 16);
    msglen[6] = (uint8_t)(bits >>  8);
    msglen[7] = (uint8_t)(bits);

    sm3_update(ctx, &pad, 1);

    /* pad to 56 mod 64 */
    pad = 0x00;
    while ((ctx->count % SM3_BLOCK_SIZE) != 56)
        sm3_update(ctx, &pad, 1);

    sm3_update(ctx, msglen, 8);

    for (int i = 0; i < 8; i++)
        put_uint32_be(digest, i * 4, ctx->state[i]);

    /* clear sensitive data */
    memset(ctx, 0, sizeof(*ctx));
    (void)fill;
}

void sm3(const uint8_t *data, size_t len, uint8_t digest[SM3_DIGEST_SIZE])
{
    sm3_ctx_t ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, len);
    sm3_final(&ctx, digest);
}

void sm3_hmac(const uint8_t *key, size_t key_len,
              const uint8_t *data, size_t data_len,
              uint8_t mac[SM3_HMAC_SIZE])
{
    sm3_ctx_t ctx;
    uint8_t k_ipad[SM3_BLOCK_SIZE];
    uint8_t k_opad[SM3_BLOCK_SIZE];
    uint8_t tk[SM3_DIGEST_SIZE];
    uint8_t inner[SM3_DIGEST_SIZE];

    /* if key is longer than block size, hash it */
    if (key_len > SM3_BLOCK_SIZE) {
        sm3(key, key_len, tk);
        key     = tk;
        key_len = SM3_DIGEST_SIZE;
    }

    memset(k_ipad, 0x36, SM3_BLOCK_SIZE);
    memset(k_opad, 0x5c, SM3_BLOCK_SIZE);

    for (size_t i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    /* inner hash */
    sm3_init(&ctx);
    sm3_update(&ctx, k_ipad, SM3_BLOCK_SIZE);
    sm3_update(&ctx, data, data_len);
    sm3_final(&ctx, inner);

    /* outer hash */
    sm3_init(&ctx);
    sm3_update(&ctx, k_opad, SM3_BLOCK_SIZE);
    sm3_update(&ctx, inner, SM3_DIGEST_SIZE);
    sm3_final(&ctx, mac);

    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
}
