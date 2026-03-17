/*
 * SM2 Key Exchange for strongSwan IKEv2
 */
#ifndef GM_SM2_KE_H
#define GM_SM2_KE_H

#include <crypto/key_exchange.h>

key_exchange_t *gm_sm2_ke_create(key_exchange_method_t method);

#endif /* GM_SM2_KE_H */
