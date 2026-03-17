/*
 * HMAC-SM3 PRF/Signer for strongSwan
 */
#ifndef GM_HMAC_SM3_PRF_H
#define GM_HMAC_SM3_PRF_H

#include <crypto/prfs/prf.h>
#include <crypto/signers/signer.h>

prf_t    *gm_hmac_sm3_prf_create(pseudo_random_function_t algo);
signer_t *gm_hmac_sm3_signer_create(integrity_algorithm_t algo);

#endif /* GM_HMAC_SM3_PRF_H */
