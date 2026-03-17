/*
 * IKEv2 GM negotiation helper
 *
 * Provides helper functions for GM-specific IKEv2 negotiations,
 * including transform proposal building and SA parameter exchange.
 */
#ifndef GM_IKE_H
#define GM_IKE_H

#include <stdint.h>
#include <stddef.h>

/* IKEv2 Transform IDs for GM algorithms */

/* Encryption (Transform Type 1) */
#define IKEV2_ENCR_SM4_CBC      28    /* RFC 8709 / IANA pending */
#define IKEV2_ENCR_SM4_CTR      29
#define IKEV2_ENCR_SM4_GCM_16   30    /* with 16-byte ICV */

/* Integrity (Transform Type 3) */
#define IKEV2_AUTH_HMAC_SM3_256 31

/* PRF (Transform Type 2) */
#define IKEV2_PRF_HMAC_SM3      32

/* DH Group (Transform Type 4) */
#define IKEV2_DH_SM2_256        41

/* ESP Transform IDs matching above */
#define ESP_ENCR_SM4_CBC        IKEV2_ENCR_SM4_CBC
#define ESP_ENCR_SM4_GCM_16     IKEV2_ENCR_SM4_GCM_16
#define ESP_AUTH_HMAC_SM3_256   IKEV2_AUTH_HMAC_SM3_256

/*
 * IKEv2 SA proposal for GM IPSec
 *
 * IKE SA:
 *   Encryption: SM4-CBC-128
 *   Integrity:  HMAC-SM3-256-256
 *   PRF:        PRF-HMAC-SM3
 *   DH:         SM2-256
 *
 * ESP SA:
 *   Encryption: SM4-GCM-128-16 (or SM4-CBC + HMAC-SM3)
 *   Integrity:  HMAC-SM3-256-256 (only for non-AEAD)
 */
typedef struct {
    uint16_t encr_id;
    uint16_t encr_keylen;
    uint16_t integ_id;
    uint16_t prf_id;
    uint16_t dh_id;
} gm_ike_proposal_t;

typedef struct {
    uint16_t encr_id;
    uint16_t encr_keylen;
    uint16_t integ_id;   /* 0 for AEAD */
} gm_esp_proposal_t;

static const gm_ike_proposal_t GM_IKE_PROPOSAL = {
    .encr_id     = IKEV2_ENCR_SM4_CBC,
    .encr_keylen = 128,
    .integ_id    = IKEV2_AUTH_HMAC_SM3_256,
    .prf_id      = IKEV2_PRF_HMAC_SM3,
    .dh_id       = IKEV2_DH_SM2_256,
};

static const gm_esp_proposal_t GM_ESP_PROPOSAL_AEAD = {
    .encr_id     = IKEV2_ENCR_SM4_GCM_16,
    .encr_keylen = 128,
    .integ_id    = 0,
};

static const gm_esp_proposal_t GM_ESP_PROPOSAL_CBC = {
    .encr_id     = IKEV2_ENCR_SM4_CBC,
    .encr_keylen = 128,
    .integ_id    = IKEV2_AUTH_HMAC_SM3_256,
};

#endif /* GM_IKE_H */
