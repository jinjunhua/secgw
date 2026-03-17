/*
 * SM3 Hasher implementation for strongSwan
 */
#include "gm_sm3_hasher.h"
#include "../../crypto/sm3.h"
#include <utils/debug.h>

typedef struct private_sm3_hasher_t private_sm3_hasher_t;

struct private_sm3_hasher_t {
    hasher_t  public;
    sm3_ctx_t ctx;
};

METHOD(hasher_t, get_hash_size, size_t,
    private_sm3_hasher_t *this)
{
    return SM3_DIGEST_SIZE;
}

METHOD(hasher_t, reset, bool,
    private_sm3_hasher_t *this)
{
    sm3_init(&this->ctx);
    return TRUE;
}

METHOD(hasher_t, get_hash, bool,
    private_sm3_hasher_t *this, chunk_t chunk, uint8_t *hash)
{
    sm3_update(&this->ctx, chunk.ptr, chunk.len);
    if (hash) {
        sm3_ctx_t tmp = this->ctx;
        sm3_final(&tmp, hash);
    }
    return TRUE;
}

METHOD(hasher_t, allocate_hash, bool,
    private_sm3_hasher_t *this, chunk_t chunk, chunk_t *hash)
{
    if (hash) {
        *hash = chunk_alloc(SM3_DIGEST_SIZE);
        return get_hash(this, chunk, hash->ptr);
    }
    return get_hash(this, chunk, NULL);
}

METHOD(hasher_t, destroy_hasher, void,
    private_sm3_hasher_t *this)
{
    memset(this, 0, sizeof(*this));
    free(this);
}

hasher_t *gm_sm3_hasher_create(hash_algorithm_t algo)
{
    private_sm3_hasher_t *this;

    if (algo != HASH_SM3)
        return NULL;

    INIT(this,
        .public = {
            .get_hash_size  = _get_hash_size,
            .reset          = _reset,
            .get_hash       = _get_hash,
            .allocate_hash  = _allocate_hash,
            .destroy        = _destroy_hasher,
        },
    );
    sm3_init(&this->ctx);
    return &this->public;
}
