/*
 * SM2 Key Exchange implementation for strongSwan IKEv2
 *
 * Implements Diffie-Hellman-like key agreement using SM2 ECDH.
 * In IKEv2: each side generates an ephemeral SM2 key pair and
 * exchanges public keys via the KE payload.
 */
#include "gm_sm2_ke.h"
#include "../../crypto/sm2.h"
#include <utils/debug.h>

/* Simple CSPRNG wrapper using /dev/urandom */
#include <fcntl.h>
#include <unistd.h>

static int urandom_rng(uint8_t *buf, size_t len, void *ctx)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, len);
    close(fd);
    return (r == (ssize_t)len) ? 0 : -1;
}

typedef struct {
    key_exchange_t public;
    sm2_key_t local_key;
    uint8_t   shared[SM2_SHARED_KEY_SIZE];
    bool      shared_computed;
} private_sm2_ke_t;

METHOD(key_exchange_t, get_public_key, bool,
    private_sm2_ke_t *this, chunk_t *value)
{
    /* Public key = 04 || Qx || Qy (65 bytes uncompressed) */
    *value = chunk_alloc(1 + SM2_PUBKEY_SIZE);
    value->ptr[0] = 0x04;
    memcpy(value->ptr + 1,  this->local_key.Qx, SM2_KEY_SIZE);
    memcpy(value->ptr + 33, this->local_key.Qy, SM2_KEY_SIZE);
    return TRUE;
}

METHOD(key_exchange_t, set_public_key, bool,
    private_sm2_ke_t *this, chunk_t value)
{
    if (value.len != 1 + SM2_PUBKEY_SIZE || value.ptr[0] != 0x04)
        return FALSE;
    const uint8_t *peer_Qx = value.ptr + 1;
    const uint8_t *peer_Qy = value.ptr + 33;
    if (sm2_ecdh(&this->local_key, peer_Qx, peer_Qy, this->shared) != 0)
        return FALSE;
    this->shared_computed = TRUE;
    return TRUE;
}

METHOD(key_exchange_t, get_shared_secret, bool,
    private_sm2_ke_t *this, chunk_t *secret)
{
    if (!this->shared_computed)
        return FALSE;
    *secret = chunk_clone(chunk_create(this->shared, SM2_SHARED_KEY_SIZE));
    return TRUE;
}

METHOD(key_exchange_t, destroy_ke, void,
    private_sm2_ke_t *this)
{
    memset(this, 0, sizeof(*this));
    free(this);
}

key_exchange_t *gm_sm2_ke_create(key_exchange_method_t method)
{
    private_sm2_ke_t *this;

    if (method != SM2_256)
        return NULL;

    INIT(this,
        .public = {
            .get_public_key  = _get_public_key,
            .set_public_key  = _set_public_key,
            .get_shared_secret = _get_shared_secret,
            .destroy         = _destroy_ke,
        },
        .shared_computed = FALSE,
    );

    if (sm2_generate_key(&this->local_key, urandom_rng, NULL) != 0) {
        free(this);
        return NULL;
    }

    DBG2(DBG_LIB, "SM2 key exchange initialized");
    return &this->public;
}
