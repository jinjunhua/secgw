/*
 * SM3 Hasher - strongSwan hasher_t implementation
 */
#ifndef GM_SM3_HASHER_H
#define GM_SM3_HASHER_H

#include <crypto/hashers/hasher.h>

hasher_t *gm_sm3_hasher_create(hash_algorithm_t algo);

#endif /* GM_SM3_HASHER_H */
