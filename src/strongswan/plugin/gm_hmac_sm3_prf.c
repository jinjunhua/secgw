/*
 * HMAC-SM3 PRF/Signer implementation for strongSwan
 */
#include "gm_hmac_sm3_prf.h"
#include "../../crypto/sm3.h"
#include <utils/debug.h>

/* ------------------------------------------------------------------ */
/* PRF                                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    prf_t  public;
    uint8_t key[SM3_BLOCK_SIZE];
    size_t  key_len;
} private_hmac_sm3_prf_t;

METHOD(prf_t, get_block_size, size_t,
    private_hmac_sm3_prf_t *this)
{
    return SM3_HMAC_SIZE;
}

METHOD(prf_t, get_key_size_prf, size_t,
    private_hmac_sm3_prf_t *this)
{
    return SM3_HMAC_SIZE;
}

METHOD(prf_t, set_key_prf, bool,
    private_hmac_sm3_prf_t *this, chunk_t key)
{
    size_t len = key.len < SM3_BLOCK_SIZE ? key.len : SM3_BLOCK_SIZE;
    memcpy(this->key, key.ptr, len);
    this->key_len = len;
    return TRUE;
}

METHOD(prf_t, get_bytes, bool,
    private_hmac_sm3_prf_t *this, chunk_t seed, uint8_t *out)
{
    sm3_hmac(this->key, this->key_len, seed.ptr, seed.len, out);
    return TRUE;
}

METHOD(prf_t, allocate_bytes, bool,
    private_hmac_sm3_prf_t *this, chunk_t seed, chunk_t *out)
{
    if (out) {
        *out = chunk_alloc(SM3_HMAC_SIZE);
        return get_bytes(this, seed, out->ptr);
    }
    return get_bytes(this, seed, NULL);
}

METHOD(prf_t, destroy_prf, void,
    private_hmac_sm3_prf_t *this)
{
    memset(this, 0, sizeof(*this));
    free(this);
}

prf_t *gm_hmac_sm3_prf_create(pseudo_random_function_t algo)
{
    private_hmac_sm3_prf_t *this;

    if (algo != PRF_HMAC_SM3)
        return NULL;

    INIT(this,
        .public = {
            .get_block_size = _get_block_size,
            .get_key_size   = _get_key_size_prf,
            .set_key        = _set_key_prf,
            .get_bytes      = _get_bytes,
            .allocate_bytes = _allocate_bytes,
            .destroy        = _destroy_prf,
        },
    );
    return &this->public;
}

/* ------------------------------------------------------------------ */
/* Signer                                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    signer_t public;
    uint8_t  key[SM3_BLOCK_SIZE];
    size_t   key_len;
    size_t   trunc_len;
} private_hmac_sm3_signer_t;

METHOD(signer_t, get_key_size_sig, size_t,
    private_hmac_sm3_signer_t *this)
{
    return SM3_HMAC_SIZE;
}

METHOD(signer_t, get_block_size_sig, size_t,
    private_hmac_sm3_signer_t *this)
{
    return this->trunc_len;
}

METHOD(signer_t, set_key_sig, bool,
    private_hmac_sm3_signer_t *this, chunk_t key)
{
    size_t len = key.len < SM3_BLOCK_SIZE ? key.len : SM3_BLOCK_SIZE;
    memcpy(this->key, key.ptr, len);
    this->key_len = len;
    return TRUE;
}

METHOD(signer_t, get_signature, bool,
    private_hmac_sm3_signer_t *this, chunk_t data, uint8_t *out)
{
    uint8_t mac[SM3_HMAC_SIZE];
    sm3_hmac(this->key, this->key_len, data.ptr, data.len, mac);
    if (out)
        memcpy(out, mac, this->trunc_len);
    return TRUE;
}

METHOD(signer_t, allocate_signature, bool,
    private_hmac_sm3_signer_t *this, chunk_t data, chunk_t *sig)
{
    if (sig) {
        *sig = chunk_alloc(this->trunc_len);
        return get_signature(this, data, sig->ptr);
    }
    return get_signature(this, data, NULL);
}

METHOD(signer_t, verify_signature, bool,
    private_hmac_sm3_signer_t *this, chunk_t data, chunk_t sig)
{
    uint8_t mac[SM3_HMAC_SIZE];
    sm3_hmac(this->key, this->key_len, data.ptr, data.len, mac);
    if (sig.len != this->trunc_len)
        return FALSE;
    /* constant-time comparison */
    uint8_t diff = 0;
    for (size_t i = 0; i < this->trunc_len; i++)
        diff |= mac[i] ^ sig.ptr[i];
    return diff == 0;
}

METHOD(signer_t, destroy_sig, void,
    private_hmac_sm3_signer_t *this)
{
    memset(this, 0, sizeof(*this));
    free(this);
}

signer_t *gm_hmac_sm3_signer_create(integrity_algorithm_t algo)
{
    private_hmac_sm3_signer_t *this;

    if (algo != AUTH_HMAC_SM3_256_256)
        return NULL;

    INIT(this,
        .public = {
            .get_key_size    = _get_key_size_sig,
            .get_block_size  = _get_block_size_sig,
            .set_key         = _set_key_sig,
            .get_signature   = _get_signature,
            .allocate_signature = _allocate_signature,
            .verify_signature   = _verify_signature,
            .destroy         = _destroy_sig,
        },
        .trunc_len = 32, /* 256-bit */
    );
    return &this->public;
}
