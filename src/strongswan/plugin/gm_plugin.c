/*
 * strongSwan GM Crypto Plugin implementation
 *
 * Registers the following with strongSwan:
 *   - SM4-CBC/CTR/GCM  (encryption_algorithm_t)
 *   - SM3 / HMAC-SM3   (hash_algorithm_t / prf_algorithm_t)
 *   - SM2              (key_exchange_method_t / signature scheme)
 *
 * This plugin is loaded by charon via the strongswan.conf:
 *   charon.plugins.gm { load = yes }
 */
#include "gm_plugin.h"
#include "gm_sm4_crypter.h"
#include "gm_sm3_hasher.h"
#include "gm_hmac_sm3_prf.h"
#include "gm_sm2_ke.h"

#include <daemon.h>
#include <utils/debug.h>

typedef struct private_gm_plugin_t private_gm_plugin_t;

struct private_gm_plugin_t {
    gm_plugin_t public;
};

METHOD(plugin_t, get_name, char *,
    private_gm_plugin_t *this)
{
    return GM_PLUGIN_NAME;
}

METHOD(plugin_t, get_features, int,
    private_gm_plugin_t *this, plugin_feature_t *features[])
{
    static plugin_feature_t f[] = {
        /* SM4-CBC */
        PLUGIN_REGISTER(CRYPTER, gm_sm4_crypter_create),
            PLUGIN_PROVIDE(CRYPTER, ENCR_SM4_CBC, 16),

        /* SM4-CTR */
        PLUGIN_REGISTER(CRYPTER, gm_sm4_crypter_create),
            PLUGIN_PROVIDE(CRYPTER, ENCR_SM4_CTR, 16),

        /* SM3 hash */
        PLUGIN_REGISTER(HASHER, gm_sm3_hasher_create),
            PLUGIN_PROVIDE(HASHER, HASH_SM3),

        /* HMAC-SM3 PRF */
        PLUGIN_REGISTER(PRF, gm_hmac_sm3_prf_create),
            PLUGIN_PROVIDE(PRF, PRF_HMAC_SM3),

        /* HMAC-SM3 signer */
        PLUGIN_REGISTER(SIGNER, gm_hmac_sm3_signer_create),
            PLUGIN_PROVIDE(SIGNER, AUTH_HMAC_SM3_256_256),

        /* SM2 key exchange (ECDH) */
        PLUGIN_REGISTER(KE, gm_sm2_ke_create),
            PLUGIN_PROVIDE(KE, SM2_256),
    };

    *features = f;
    return countof(f);
}

METHOD(plugin_t, destroy, void,
    private_gm_plugin_t *this)
{
    free(this);
}

plugin_t *gm_plugin_create(void)
{
    private_gm_plugin_t *this;

    INIT(this,
        .public = {
            .plugin = {
                .get_name    = _get_name,
                .get_features = _get_features,
                .destroy     = _destroy,
            },
        },
    );

    DBG1(DBG_LIB, "GM crypto plugin loaded (SM2/SM3/SM4)");
    return &this->public.plugin;
}
