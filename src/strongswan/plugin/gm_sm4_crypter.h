/*
 * SM4 Crypter - strongSwan crypter_t implementation using SM4
 */
#ifndef GM_SM4_CRYPTER_H
#define GM_SM4_CRYPTER_H

#include <crypto/crypters/crypter.h>

/**
 * Create SM4 CBC/CTR crypter.
 * @param algo   ENCR_SM4_CBC or ENCR_SM4_CTR
 * @param keylen key length in bytes (must be 16)
 */
crypter_t *gm_sm4_crypter_create(encryption_algorithm_t algo, size_t keylen);

#endif /* GM_SM4_CRYPTER_H */
