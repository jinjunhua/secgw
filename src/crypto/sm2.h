#ifndef GM_SM2_H
#define GM_SM2_H

#include <stdint.h>
#include <stddef.h>

/*
 * SM2 Elliptic Curve Public Key Cryptography
 * Reference: GM/T 0003-2012
 * Curve: y^2 = x^3 + ax + b  over GF(p)
 */

#define SM2_KEY_SIZE        32   /* 256-bit */
#define SM2_PUBKEY_SIZE     64   /* uncompressed: 32+32 */
#define SM2_SIG_SIZE        64   /* (r, s), each 32 bytes */
#define SM2_SHARED_KEY_SIZE 32

/* SM2 key pair */
typedef struct {
    uint8_t d[SM2_KEY_SIZE];          /* private key */
    uint8_t Qx[SM2_KEY_SIZE];         /* public key X */
    uint8_t Qy[SM2_KEY_SIZE];         /* public key Y */
} sm2_key_t;

/* SM2 signature */
typedef struct {
    uint8_t r[SM2_KEY_SIZE];
    uint8_t s[SM2_KEY_SIZE];
} sm2_sig_t;

/* Generate key pair (requires a CSPRNG source) */
int sm2_generate_key(sm2_key_t *key,
                     int (*rng)(uint8_t *buf, size_t len, void *ctx),
                     void *rng_ctx);

/*
 * Sign:  Z = SM3(ENTL || ID || a || b || Gx || Gy || Qx || Qy)
 *        M' = Z || M
 *        e  = SM3(M')
 *        Sign(e, d) -> (r, s)
 */
int sm2_sign(const sm2_key_t *key,
             const uint8_t *id, size_t id_len,
             const uint8_t *msg, size_t msg_len,
             sm2_sig_t *sig,
             int (*rng)(uint8_t *buf, size_t len, void *ctx),
             void *rng_ctx);

/*
 * Verify signature
 */
int sm2_verify(const sm2_key_t *pub,
               const uint8_t *id, size_t id_len,
               const uint8_t *msg, size_t msg_len,
               const sm2_sig_t *sig);

/*
 * Key encapsulation (for IKE)
 * Encrypts a short message using SM2 public key:
 *   C = C1 || C3 || C2
 * Returns 0 on success.
 */
int sm2_encrypt(const sm2_key_t *pub,
                const uint8_t *plain, size_t plain_len,
                uint8_t *cipher, size_t *cipher_len,
                int (*rng)(uint8_t *buf, size_t len, void *ctx),
                void *rng_ctx);

int sm2_decrypt(const sm2_key_t *key,
                const uint8_t *cipher, size_t cipher_len,
                uint8_t *plain, size_t *plain_len);

/*
 * ECDH key agreement (SM2 ECDH)
 */
int sm2_ecdh(const sm2_key_t *local_key,
             const uint8_t *peer_Qx, const uint8_t *peer_Qy,
             uint8_t shared[SM2_SHARED_KEY_SIZE]);

/* Utility: compute Z value (user identity digest) */
void sm2_compute_z(const uint8_t *id, size_t id_len,
                   const uint8_t Qx[SM2_KEY_SIZE],
                   const uint8_t Qy[SM2_KEY_SIZE],
                   uint8_t z[32]);

#endif /* GM_SM2_H */
