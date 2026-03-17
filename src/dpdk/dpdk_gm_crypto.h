#ifndef DPDK_GM_CRYPTO_H
#define DPDK_GM_CRYPTO_H

/*
 * DPDK Crypto PMD integration for GM algorithms (SM2/SM3/SM4)
 *
 * This header defines the interface for registering and using
 * GM cryptographic algorithms as a DPDK software crypto PMD.
 *
 * Build dependency: DPDK >= 22.11
 */

#ifdef HAVE_DPDK
#include <rte_cryptodev.h>
#include <rte_crypto.h>
#endif

#include <stdint.h>
#include <stddef.h>

/* GM cipher algorithm IDs (extending DPDK's enum) */
#define GM_CIPHER_SM4_CBC    0x1001
#define GM_CIPHER_SM4_CTR    0x1002
#define GM_CIPHER_SM4_GCM    0x1003

/* GM auth algorithm IDs */
#define GM_AUTH_SM3          0x2001
#define GM_AUTH_HMAC_SM3     0x2002

/* Session parameters for SM4-CBC */
typedef struct {
    uint8_t key[16];
    uint8_t iv[16];
    int     encrypt; /* 1 = encrypt, 0 = decrypt */
} gm_sm4_cbc_session_t;

/* Session parameters for SM4-GCM */
typedef struct {
    uint8_t  key[16];
    uint8_t  iv[12];
    size_t   aad_len;
    size_t   tag_len;
    int      encrypt;
} gm_sm4_gcm_session_t;

/* Session parameters for HMAC-SM3 */
typedef struct {
    uint8_t  key[64];
    size_t   key_len;
} gm_hmac_sm3_session_t;

/*
 * Process a crypto operation synchronously (software path).
 * Used when DPDK PMD is not available or for testing.
 */
int gm_sw_process_cipher(const gm_sm4_cbc_session_t *sess,
                          const uint8_t *in, uint8_t *out, size_t len);

int gm_sw_process_aead(const gm_sm4_gcm_session_t *sess,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *in,  uint8_t *out, size_t len,
                        uint8_t *tag, size_t tag_len);

int gm_sw_process_auth(const gm_hmac_sm3_session_t *sess,
                        const uint8_t *data, size_t data_len,
                        uint8_t *digest);

#ifdef HAVE_DPDK
/*
 * Register GM crypto PMD with DPDK.
 * Must be called after rte_eal_init().
 */
int gm_dpdk_crypto_init(void);

/*
 * Create a crypto session for SM4-CBC/CTR/GCM or HMAC-SM3.
 * Returns session pointer or NULL on failure.
 */
struct rte_cryptodev_sym_session *
gm_dpdk_session_create(uint8_t dev_id,
                        struct rte_mempool *sess_mp,
                        int algo_id,
                        const uint8_t *key, size_t key_len,
                        int encrypt);

/*
 * Enqueue a batch of crypto operations.
 * Returns number of operations successfully enqueued.
 */
uint16_t gm_dpdk_enqueue_burst(uint8_t dev_id, uint16_t qp_id,
                                struct rte_crypto_op **ops, uint16_t nb_ops);

/*
 * Dequeue completed crypto operations.
 * Returns number of operations dequeued.
 */
uint16_t gm_dpdk_dequeue_burst(uint8_t dev_id, uint16_t qp_id,
                                struct rte_crypto_op **ops, uint16_t nb_ops);
#endif /* HAVE_DPDK */

#endif /* DPDK_GM_CRYPTO_H */
