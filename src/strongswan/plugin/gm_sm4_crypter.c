/*
 * SM4 Crypter implementation for strongSwan
 */
#include "gm_sm4_crypter.h"
#include "../../crypto/sm4.h"
#include <utils/debug.h>

typedef struct private_sm4_crypter_t private_sm4_crypter_t;

struct private_sm4_crypter_t {
    crypter_t     public;
    sm4_ctx_t     ctx_enc;
    sm4_ctx_t     ctx_dec;
    encryption_algorithm_t algo;
};

METHOD(crypter_t, encrypt, bool,
    private_sm4_crypter_t *this,
    chunk_t data, chunk_t iv, chunk_t *encrypted)
{
    uint8_t *out;
    if (encrypted) {
        *encrypted = chunk_alloc(data.len);
        out = encrypted->ptr;
    } else {
        out = data.ptr; /* in-place */
    }

    if (this->algo == ENCR_SM4_CBC) {
        sm4_cbc_encrypt(&this->ctx_enc, iv.ptr, data.ptr, out, data.len);
    } else if (this->algo == ENCR_SM4_CTR) {
        uint8_t ctr[SM4_BLOCK_SIZE];
        memcpy(ctr, iv.ptr, SM4_BLOCK_SIZE);
        sm4_ctr_crypt(&this->ctx_enc, ctr, data.ptr, out, data.len);
    } else {
        return FALSE;
    }
    return TRUE;
}

METHOD(crypter_t, decrypt, bool,
    private_sm4_crypter_t *this,
    chunk_t data, chunk_t iv, chunk_t *decrypted)
{
    uint8_t *out;
    if (decrypted) {
        *decrypted = chunk_alloc(data.len);
        out = decrypted->ptr;
    } else {
        out = data.ptr;
    }

    if (this->algo == ENCR_SM4_CBC) {
        sm4_cbc_decrypt(&this->ctx_dec, iv.ptr, data.ptr, out, data.len);
    } else if (this->algo == ENCR_SM4_CTR) {
        uint8_t ctr[SM4_BLOCK_SIZE];
        memcpy(ctr, iv.ptr, SM4_BLOCK_SIZE);
        sm4_ctr_crypt(&this->ctx_enc, ctr, data.ptr, out, data.len);
    } else {
        return FALSE;
    }
    return TRUE;
}

METHOD(crypter_t, get_block_size, size_t,
    private_sm4_crypter_t *this)
{
    return SM4_BLOCK_SIZE;
}

METHOD(crypter_t, get_iv_size, size_t,
    private_sm4_crypter_t *this)
{
    return SM4_BLOCK_SIZE;
}

METHOD(crypter_t, get_key_size, size_t,
    private_sm4_crypter_t *this)
{
    return SM4_KEY_SIZE;
}

METHOD(crypter_t, set_key, bool,
    private_sm4_crypter_t *this, chunk_t key)
{
    if (key.len != SM4_KEY_SIZE)
        return FALSE;
    sm4_set_key_enc(&this->ctx_enc, key.ptr);
    sm4_set_key_dec(&this->ctx_dec, key.ptr);
    return TRUE;
}

METHOD(crypter_t, destroy_crypter, void,
    private_sm4_crypter_t *this)
{
    memset(this, 0, sizeof(*this));
    free(this);
}

crypter_t *gm_sm4_crypter_create(encryption_algorithm_t algo, size_t keylen)
{
    private_sm4_crypter_t *this;

    if (keylen != SM4_KEY_SIZE)
        return NULL;
    if (algo != ENCR_SM4_CBC && algo != ENCR_SM4_CTR)
        return NULL;

    INIT(this,
        .public = {
            .encrypt        = _encrypt,
            .decrypt        = _decrypt,
            .get_block_size = _get_block_size,
            .get_iv_size    = _get_iv_size,
            .get_key_size   = _get_key_size,
            .set_key        = _set_key,
            .destroy        = _destroy_crypter,
        },
        .algo = algo,
    );
    return &this->public;
}
