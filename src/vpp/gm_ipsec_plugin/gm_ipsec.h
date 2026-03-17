/*
 * GM IPSec VPP Plugin
 *
 * Implements ESP encapsulation/decapsulation using SM4-GCM-128
 * and SM3-HMAC-256 for authentication, integrated with VPP's
 * IPSec framework.
 *
 * Build: requires VPP dev headers (>= 23.02)
 */

#ifndef GM_IPSEC_H
#define GM_IPSEC_H

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ipsec/ipsec.h>
#include <vppinfra/error.h>

/* Plugin name */
#define GM_IPSEC_PLUGIN_NAME "gm_ipsec"

/* GM algorithm IDs registered with VPP */
#define GM_IPSEC_CRYPTO_ALG_SM4_GCM_128    0x80  /* custom */
#define GM_IPSEC_INTEG_ALG_SM3_HMAC_256    0x81  /* custom */

/* Node names */
#define GM_IPSEC_ESP_ENC_NODE   "gm-esp4-encrypt"
#define GM_IPSEC_ESP_DEC_NODE   "gm-esp4-decrypt"

/* Error strings */
#define foreach_gm_ipsec_error                  \
    _(NONE,           "No error")               \
    _(BAD_SPI,        "ESP SPI not found")      \
    _(AUTH_FAILED,    "Authentication failed")  \
    _(REPLAY,         "Replay check failed")    \
    _(DECRYPT_FAILED, "Decryption failed")      \
    _(ENCRYPT_FAILED, "Encryption failed")

typedef enum {
#define _(sym, str) GM_IPSEC_ERROR_##sym,
    foreach_gm_ipsec_error
#undef _
    GM_IPSEC_N_ERROR,
} gm_ipsec_error_t;

/* Per-SA crypto context */
typedef struct {
    uint8_t  enc_key[16];    /* SM4 key */
    uint8_t  auth_key[32];   /* HMAC-SM3 key */
    uint32_t spi;
    uint32_t seq;
    uint8_t  iv[12];         /* GCM IV base */
} gm_sa_ctx_t;

/* Plugin main structure */
typedef struct {
    /* VPP node indices */
    u32 enc_node_index;
    u32 dec_node_index;

    /* SA database */
    gm_sa_ctx_t *sa_pool;

    /* VPP API message handler index */
    u16 msg_id_base;

    vlib_main_t *vlib_main;
    vnet_main_t *vnet_main;
} gm_ipsec_main_t;

extern gm_ipsec_main_t gm_ipsec_main;

/* Node declarations */
extern vlib_node_registration_t gm_esp4_encrypt_node;
extern vlib_node_registration_t gm_esp4_decrypt_node;

/* API */
clib_error_t *gm_ipsec_init(vlib_main_t *vm);

#endif /* GM_IPSEC_H */
