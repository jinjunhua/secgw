/*
 * SM2 Elliptic Curve Cryptography
 * Reference: GM/T 0003.1-2012 ~ GM/T 0003.5-2012
 *
 * Uses a portable big-integer implementation for the field arithmetic.
 * For production use, replace with a constant-time implementation or
 * use a hardware-accelerated back-end.
 */
#include "sm2.h"
#include "sm3.h"
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* SM2 curve parameters (256-bit prime field)                          */
/* ------------------------------------------------------------------ */

static const uint8_t SM2_P[32] = {
    0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};
static const uint8_t SM2_A[32] = {
    0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC
};
static const uint8_t SM2_B[32] = {
    0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,
    0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93
};
static const uint8_t SM2_N[32] = {
    0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x72,0x03,0xDF,0x6B,0x21,0xC6,0x05,0x2B,0x53,0xBB,0xF4,0x09,0x39,0xD5,0x45,0x23
};
static const uint8_t SM2_GX[32] = {
    0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,
    0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7
};
static const uint8_t SM2_GY[32] = {
    0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,
    0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0
};

/* ------------------------------------------------------------------ */
/* Portable 256-bit big-integer (8 x uint32_t, big-endian limbs)      */
/* ------------------------------------------------------------------ */

#define BN_LIMBS 8
typedef uint32_t bn256_t[BN_LIMBS];

static void bn_from_bytes(bn256_t r, const uint8_t b[32])
{
    for (int i = 0; i < 8; i++)
        r[i] = ((uint32_t)b[i*4] << 24) | ((uint32_t)b[i*4+1] << 16) |
               ((uint32_t)b[i*4+2] << 8) | (uint32_t)b[i*4+3];
}

static void bn_to_bytes(uint8_t b[32], const bn256_t r)
{
    for (int i = 0; i < 8; i++) {
        b[i*4]   = (uint8_t)(r[i] >> 24);
        b[i*4+1] = (uint8_t)(r[i] >> 16);
        b[i*4+2] = (uint8_t)(r[i] >>  8);
        b[i*4+3] = (uint8_t)(r[i]);
    }
}

static int bn_cmp(const bn256_t a, const bn256_t b)
{
    for (int i = 0; i < BN_LIMBS; i++) {
        if (a[i] > b[i]) return  1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

static int bn_is_zero(const bn256_t a)
{
    for (int i = 0; i < BN_LIMBS; i++)
        if (a[i]) return 0;
    return 1;
}

static void bn_copy(bn256_t dst, const bn256_t src)
{
    memcpy(dst, src, sizeof(bn256_t));
}

static void bn_zero(bn256_t a)
{
    memset(a, 0, sizeof(bn256_t));
}

/* a = a - b (no borrow check), assumes a >= b */
static void bn_sub(bn256_t r, const bn256_t a, const bn256_t b)
{
    int64_t borrow = 0;
    for (int i = BN_LIMBS - 1; i >= 0; i--) {
        int64_t diff = (int64_t)a[i] - (int64_t)b[i] - borrow;
        if (diff < 0) { diff += (int64_t)1 << 32; borrow = 1; }
        else borrow = 0;
        r[i] = (uint32_t)diff;
    }
}

/* r = (a + b) mod m, where a, b < m.
 * Handles the case when a+b overflows 256 bits (carry=1):
 * In that case, r_256 = a+b-2^256, and correct result = a+b-m = r_256 + (2^256-m).
 * We compute 2^256 - m = ~m + 1 (256-bit two's complement).
 */
static void bn_add_mod(bn256_t r, const bn256_t a, const bn256_t b, const bn256_t m)
{
    uint64_t carry = 0;
    for (int i = BN_LIMBS - 1; i >= 0; i--) {
        uint64_t s = (uint64_t)a[i] + b[i] + carry;
        r[i] = (uint32_t)s;
        carry = s >> 32;
    }
    if (carry) {
        /* r = a+b-2^256; want a+b-m = r + (2^256-m) = r + ~m + 1 */
        uint64_t c2 = 1; /* for the +1 in two's complement */
        for (int i = BN_LIMBS - 1; i >= 0; i--) {
            uint64_t s = (uint64_t)r[i] + (uint32_t)~m[i] + c2;
            r[i] = (uint32_t)s;
            c2 = s >> 32;
        }
        /* result is now in [0, m) - no further reduction needed */
    } else if (bn_cmp(r, m) >= 0) {
        bn_sub(r, r, m);
    }
}

/* Correct modular multiplication using binary double-and-add.
 * Computes r = (a * b) mod m. O(256) iterations, each O(256) bits.
 * This is correct for all a, b < m without needing 512-bit intermediates.
 */
static void bn_mul_mod(bn256_t r, const bn256_t a, const bn256_t b, const bn256_t m)
{
    bn256_t result, temp, b_copy;
    bn_zero(result);
    bn_copy(temp, a);
    bn_copy(b_copy, b);

    while (!bn_is_zero(b_copy)) {
        /* if lowest bit of b is set, result += temp (mod m) */
        if (b_copy[BN_LIMBS - 1] & 1u)
            bn_add_mod(result, result, temp, m);
        /* temp = (temp * 2) mod m */
        bn_add_mod(temp, temp, temp, m);
        /* b_copy >>= 1 (logical right shift of the big-endian array) */
        for (int i = BN_LIMBS - 1; i > 0; i--)
            b_copy[i] = (b_copy[i] >> 1) | ((b_copy[i - 1] & 1u) << 31);
        b_copy[0] >>= 1;
    }
    bn_copy(r, result);
}

/* Modular subtraction: r = (a - b) mod m */
static void bn_sub_mod(bn256_t r, const bn256_t a, const bn256_t b, const bn256_t m)
{
    if (bn_cmp(a, b) >= 0) {
        bn_sub(r, a, b);
    } else {
        /* r = a - b + m */
        bn256_t tmp;
        bn_sub(tmp, m, b);        /* m - b */
        bn_add_mod(r, a, tmp, m); /* a + (m - b) mod m */
    }
}

/* Modular inverse using Fermat's little theorem: a^(m-2) mod m
 * Valid only when m is prime (which is the case for SM2 field and order).
 */
static void bn_inv_mod(bn256_t r, const bn256_t a, const bn256_t m)
{
    bn256_t exp, base, result;
    /* exp = m - 2 */
    bn_copy(exp, m);
    uint32_t borrow = 2;
    for (int i = BN_LIMBS - 1; i >= 0 && borrow; i--) {
        if (exp[i] >= borrow) { exp[i] -= borrow; borrow = 0; }
        else { exp[i] += (uint32_t)(0x100000000ULL - borrow); borrow = 1; }
    }
    bn_copy(base, a);
    bn_zero(result); result[BN_LIMBS - 1] = 1; /* result = 1 */

    while (!bn_is_zero(exp)) {
        if (exp[BN_LIMBS - 1] & 1u)
            bn_mul_mod(result, result, base, m);
        bn_mul_mod(base, base, base, m);
        /* exp >>= 1 */
        for (int i = BN_LIMBS - 1; i > 0; i--)
            exp[i] = (exp[i] >> 1) | ((exp[i - 1] & 1u) << 31);
        exp[0] >>= 1;
    }
    bn_copy(r, result);
}

/* ------------------------------------------------------------------ */
/* Elliptic curve point (affine coordinates)                           */
/* ------------------------------------------------------------------ */
typedef struct {
    bn256_t x, y;
    int infinity;
} ec_point_t;

static bn256_t g_p, g_a, g_b, g_n;
static ec_point_t g_G;

static void sm2_init_params(void)
{
    static int initialized = 0;
    if (initialized) return;
    bn_from_bytes(g_p, SM2_P);
    bn_from_bytes(g_a, SM2_A);
    bn_from_bytes(g_b, SM2_B);
    bn_from_bytes(g_n, SM2_N);
    bn_from_bytes(g_G.x, SM2_GX);
    bn_from_bytes(g_G.y, SM2_GY);
    g_G.infinity = 0;
    initialized = 1;
}

static void ec_point_add(ec_point_t *r, const ec_point_t *p, const ec_point_t *q)
{
    if (p->infinity) { *r = *q; return; }
    if (q->infinity) { *r = *p; return; }

    /* Check if p == -q (x equal, y different and non-zero) */
    if (bn_cmp(p->x, q->x) == 0 && bn_cmp(p->y, q->y) != 0) {
        r->infinity = 1;
        return;
    }

    /* Check if p == q (point doubling) */
    if (bn_cmp(p->x, q->x) == 0 && bn_cmp(p->y, q->y) == 0) {
        /* lambda = (3*x^2 + a) / (2*y) mod p */
        bn256_t x2, three_x2, two_y, lam;

        bn_mul_mod(x2, p->x, p->x, g_p);          /* x^2 */
        bn_add_mod(three_x2, x2, x2, g_p);         /* 2*x^2 */
        bn_add_mod(three_x2, three_x2, x2, g_p);   /* 3*x^2 */
        bn_add_mod(three_x2, three_x2, g_a, g_p);  /* 3*x^2 + a */
        bn_add_mod(two_y, p->y, p->y, g_p);        /* 2*y */
        bn_inv_mod(lam, two_y, g_p);               /* (2*y)^-1 mod p */
        bn_mul_mod(lam, three_x2, lam, g_p);       /* lambda */

        /* x_R = lambda^2 - 2*x mod p */
        bn256_t lam2;
        bn_mul_mod(lam2, lam, lam, g_p);
        bn_sub_mod(r->x, lam2, p->x, g_p);
        bn_sub_mod(r->x, r->x, p->x, g_p);

        /* y_R = lambda * (x_P - x_R) - y_P mod p */
        bn256_t dx;
        bn_sub_mod(dx, p->x, r->x, g_p);
        bn_mul_mod(r->y, lam, dx, g_p);
        bn_sub_mod(r->y, r->y, p->y, g_p);

        r->infinity = 0;
        return;
    }

    /* p != q: standard addition */
    bn256_t dy, dx, lam;

    /* lambda = (y_Q - y_P) / (x_Q - x_P) mod p */
    bn_sub_mod(dy, q->y, p->y, g_p);
    bn_sub_mod(dx, q->x, p->x, g_p);
    bn_inv_mod(lam, dx, g_p);
    bn_mul_mod(lam, dy, lam, g_p);

    /* x_R = lambda^2 - x_P - x_Q mod p */
    bn256_t lam2;
    bn_mul_mod(lam2, lam, lam, g_p);
    bn_sub_mod(r->x, lam2, p->x, g_p);
    bn_sub_mod(r->x, r->x, q->x, g_p);

    /* y_R = lambda * (x_P - x_R) - y_P mod p */
    bn256_t t1;
    bn_sub_mod(t1, p->x, r->x, g_p);
    bn_mul_mod(r->y, lam, t1, g_p);
    bn_sub_mod(r->y, r->y, p->y, g_p);

    r->infinity = 0;
}

static void ec_scalar_mul(ec_point_t *r, const ec_point_t *p, const bn256_t k)
{
    ec_point_t result;
    memset(&result, 0, sizeof(result));
    result.infinity = 1;

    /* Double-and-add from MSB to LSB.
     * k[0] = most significant limb (bits 255..224)
     * k[7] = least significant limb (bits 31..0)
     */
    for (int i = 0; i < BN_LIMBS; i++) {
        for (int bit = 31; bit >= 0; bit--) {
            ec_point_t doubled;
            ec_point_add(&doubled, &result, &result);
            result = doubled;
            if ((k[i] >> bit) & 1u) {
                ec_point_t added;
                ec_point_add(&added, &result, p);
                result = added;
            }
        }
    }
    *r = result;
}

/* ------------------------------------------------------------------ */
/* SM2 public API                                                       */
/* ------------------------------------------------------------------ */

void sm2_compute_z(const uint8_t *id, size_t id_len,
                   const uint8_t Qx[SM2_KEY_SIZE],
                   const uint8_t Qy[SM2_KEY_SIZE],
                   uint8_t z[32])
{
    sm3_ctx_t ctx;
    uint8_t entl[2];
    uint16_t bit_len = (uint16_t)(id_len * 8);
    entl[0] = (uint8_t)(bit_len >> 8);
    entl[1] = (uint8_t)(bit_len);

    sm3_init(&ctx);
    sm3_update(&ctx, entl, 2);
    sm3_update(&ctx, id, id_len);
    sm3_update(&ctx, SM2_A, 32);
    sm3_update(&ctx, SM2_B, 32);
    sm3_update(&ctx, SM2_GX, 32);
    sm3_update(&ctx, SM2_GY, 32);
    sm3_update(&ctx, Qx, 32);
    sm3_update(&ctx, Qy, 32);
    sm3_final(&ctx, z);
}

int sm2_generate_key(sm2_key_t *key,
                     int (*rng)(uint8_t *buf, size_t len, void *ctx),
                     void *rng_ctx)
{
    bn256_t d, n_minus_1;
    ec_point_t Q;

    sm2_init_params();

    /* n - 1 */
    bn_copy(n_minus_1, g_n);
    n_minus_1[BN_LIMBS-1]--;

    /* Generate d in [1, n-2] */
    do {
        if (rng(key->d, SM2_KEY_SIZE, rng_ctx) != 0)
            return -1;
        bn_from_bytes(d, key->d);
    } while (bn_is_zero(d) || bn_cmp(d, n_minus_1) >= 0);

    /* Q = d * G */
    ec_scalar_mul(&Q, &g_G, d);
    bn_to_bytes(key->Qx, Q.x);
    bn_to_bytes(key->Qy, Q.y);

    memset(&d, 0, sizeof(d));
    return 0;
}

int sm2_sign(const sm2_key_t *key,
             const uint8_t *id, size_t id_len,
             const uint8_t *msg, size_t msg_len,
             sm2_sig_t *sig,
             int (*rng)(uint8_t *buf, size_t len, void *ctx),
             void *rng_ctx)
{
    uint8_t Z[32], e_bytes[32];
    bn256_t e, k, d, r, s, tmp1, tmp2;
    ec_point_t P1;

    sm2_init_params();
    sm2_compute_z(id, id_len, key->Qx, key->Qy, Z);

    /* e = SM3(Z || M) */
    sm3_ctx_t hctx;
    sm3_init(&hctx);
    sm3_update(&hctx, Z, 32);
    sm3_update(&hctx, msg, msg_len);
    sm3_final(&hctx, e_bytes);
    bn_from_bytes(e, e_bytes);
    bn_from_bytes(d, key->d);

    uint8_t k_bytes[32];
    do {
        do {
            if (rng(k_bytes, 32, rng_ctx) != 0)
                return -1;
            bn_from_bytes(k, k_bytes);
        } while (bn_is_zero(k) || bn_cmp(k, g_n) >= 0);

        /* (x1, y1) = k * G */
        ec_scalar_mul(&P1, &g_G, k);

        /* r = (e + x1 mod n) mod n — note: x1 is in GF(p) so may be >= n */
        bn256_t x1_modn;
        bn_copy(x1_modn, P1.x);
        while (bn_cmp(x1_modn, g_n) >= 0)
            bn_sub(x1_modn, x1_modn, g_n);
        bn_add_mod(r, e, x1_modn, g_n);
        if (bn_is_zero(r)) continue;

        /* check r + k != n */
        bn_add_mod(tmp1, r, k, g_n);
        if (bn_is_zero(tmp1)) continue;

        break;
    } while (1);

    /* s = ((1 + d)^-1 * (k - r*d)) mod n */
    bn256_t one;
    bn_zero(one); one[BN_LIMBS-1] = 1;
    bn_add_mod(tmp1, one, d, g_n);     /* 1 + d */
    bn_inv_mod(tmp2, tmp1, g_n);        /* (1+d)^-1 mod n */

    bn256_t rd;
    bn_mul_mod(rd, r, d, g_n);          /* r*d mod n */
    bn_sub_mod(tmp1, k, rd, g_n);       /* (k - r*d) mod n */
    bn_mul_mod(s, tmp2, tmp1, g_n);     /* s = (1+d)^-1 * (k - r*d) mod n */

    if (bn_is_zero(s)) return -1;

    bn_to_bytes(sig->r, r);
    bn_to_bytes(sig->s, s);

    memset(&k, 0, sizeof(k));
    memset(&d, 0, sizeof(d));
    return 0;
}

int sm2_verify(const sm2_key_t *pub,
               const uint8_t *id, size_t id_len,
               const uint8_t *msg, size_t msg_len,
               const sm2_sig_t *sig)
{
    uint8_t Z[32], e_bytes[32];
    bn256_t r, s, e, t, R;
    ec_point_t P, sG, tQ, point_sum;

    sm2_init_params();
    sm2_compute_z(id, id_len, pub->Qx, pub->Qy, Z);

    sm3_ctx_t hctx;
    sm3_init(&hctx);
    sm3_update(&hctx, Z, 32);
    sm3_update(&hctx, msg, msg_len);
    sm3_final(&hctx, e_bytes);

    bn_from_bytes(e, e_bytes);
    bn_from_bytes(r, sig->r);
    bn_from_bytes(s, sig->s);

    /* Check 1 <= r,s <= n-1 */
    bn256_t one; bn_zero(one); one[BN_LIMBS-1] = 1;
    if (bn_is_zero(r) || bn_cmp(r, g_n) >= 0) return -1;
    if (bn_is_zero(s) || bn_cmp(s, g_n) >= 0) return -1;

    /* t = (r + s) mod n */
    bn_add_mod(t, r, s, g_n);
    if (bn_is_zero(t)) return -1;

    /* P = s*G + t*Q */
    ec_scalar_mul(&sG, &g_G, s);
    bn_from_bytes(P.x, pub->Qx);
    bn_from_bytes(P.y, pub->Qy);
    P.infinity = 0;
    ec_scalar_mul(&tQ, &P, t);
    ec_point_add(&point_sum, &sG, &tQ);
    if (point_sum.infinity) return -1;

    /* R = (e + x1 mod n) mod n  — note: x1 is in GF(p) so may be >= n */
    bn256_t x1_modn;
    bn_copy(x1_modn, point_sum.x);
    while (bn_cmp(x1_modn, g_n) >= 0)
        bn_sub(x1_modn, x1_modn, g_n);
    bn_add_mod(R, e, x1_modn, g_n);

    return (bn_cmp(R, r) == 0) ? 0 : -1;
}

int sm2_ecdh(const sm2_key_t *local_key,
             const uint8_t *peer_Qx, const uint8_t *peer_Qy,
             uint8_t shared[SM2_SHARED_KEY_SIZE])
{
    ec_point_t peer_Q, result;
    bn256_t d;

    sm2_init_params();
    bn_from_bytes(d, local_key->d);
    bn_from_bytes(peer_Q.x, peer_Qx);
    bn_from_bytes(peer_Q.y, peer_Qy);
    peer_Q.infinity = 0;

    ec_scalar_mul(&result, &peer_Q, d);
    if (result.infinity) return -1;

    bn_to_bytes(shared, result.x);
    memset(&d, 0, sizeof(d));
    return 0;
}

int sm2_encrypt(const sm2_key_t *pub,
                const uint8_t *plain, size_t plain_len,
                uint8_t *cipher, size_t *cipher_len,
                int (*rng)(uint8_t *buf, size_t len, void *ctx),
                void *rng_ctx)
{
    /* C = 04 || C1x || C1y || C3 || C2
     * C1 = k*G (random point)
     * C2 = M XOR KDF(x2, y2)
     * C3 = SM3(x2 || M || y2)
     * where (x2,y2) = k * Pub
     */
    ec_point_t C1_pt, S;
    bn256_t k;
    uint8_t k_bytes[32];
    uint8_t x2[32], y2[32];

    sm2_init_params();

    /* Required output size: 1 + 32 + 32 + 32 + plain_len */
    size_t needed = 1 + 64 + 32 + plain_len;
    if (*cipher_len < needed) {
        *cipher_len = needed;
        return -1;
    }

    bn256_t pub_x, pub_y;
    bn_from_bytes(pub_x, pub->Qx);
    bn_from_bytes(pub_y, pub->Qy);

    do {
        do {
            if (rng(k_bytes, 32, rng_ctx) != 0) return -1;
            bn_from_bytes(k, k_bytes);
        } while (bn_is_zero(k) || bn_cmp(k, g_n) >= 0);

        ec_scalar_mul(&C1_pt, &g_G, k);

        /* S = k * Pub */
        ec_point_t pub_pt;
        bn_copy(pub_pt.x, pub_x);
        bn_copy(pub_pt.y, pub_y);
        pub_pt.infinity = 0;
        ec_scalar_mul(&S, &pub_pt, k);
    } while (S.infinity);

    bn_to_bytes(x2, S.x);
    bn_to_bytes(y2, S.y);

    /* KDF: SM3-based key derivation */
    uint8_t *t = cipher + 1 + 64 + 32;
    uint32_t ct_kdf = 1;
    uint8_t ha[SM3_DIGEST_SIZE];
    size_t done = 0;
    while (done < plain_len) {
        uint8_t ct_bytes[4] = {(uint8_t)(ct_kdf>>24),(uint8_t)(ct_kdf>>16),
                               (uint8_t)(ct_kdf>>8),(uint8_t)ct_kdf};
        sm3_ctx_t hctx;
        sm3_init(&hctx);
        sm3_update(&hctx, x2, 32);
        sm3_update(&hctx, y2, 32);
        sm3_update(&hctx, ct_bytes, 4);
        sm3_final(&hctx, ha);
        size_t chunk = (plain_len - done < SM3_DIGEST_SIZE) ? plain_len - done : SM3_DIGEST_SIZE;
        for (size_t i = 0; i < chunk; i++)
            t[done + i] = plain[done + i] ^ ha[i];
        done += chunk;
        ct_kdf++;
    }

    /* C1 */
    cipher[0] = 0x04;
    bn_to_bytes(cipher + 1,      C1_pt.x);
    bn_to_bytes(cipher + 1 + 32, C1_pt.y);

    /* C3 = SM3(x2 || M || y2) */
    sm3_ctx_t hctx;
    sm3_init(&hctx);
    sm3_update(&hctx, x2, 32);
    sm3_update(&hctx, plain, plain_len);
    sm3_update(&hctx, y2, 32);
    sm3_final(&hctx, cipher + 1 + 64);

    *cipher_len = needed;
    memset(&k, 0, sizeof(k));
    return 0;
}

int sm2_decrypt(const sm2_key_t *key,
                const uint8_t *cipher, size_t cipher_len,
                uint8_t *plain, size_t *plain_len)
{
    if (cipher_len < 1 + 64 + 32 + 1) return -1;
    if (cipher[0] != 0x04) return -1;

    size_t msg_len = cipher_len - 1 - 64 - 32;
    if (*plain_len < msg_len) { *plain_len = msg_len; return -1; }

    ec_point_t C1, S;
    bn256_t d;

    sm2_init_params();
    bn_from_bytes(C1.x, cipher + 1);
    bn_from_bytes(C1.y, cipher + 1 + 32);
    C1.infinity = 0;
    bn_from_bytes(d, key->d);

    ec_scalar_mul(&S, &C1, d);
    if (S.infinity) return -1;

    uint8_t x2[32], y2[32];
    bn_to_bytes(x2, S.x);
    bn_to_bytes(y2, S.y);

    const uint8_t *C2 = cipher + 1 + 64 + 32;
    const uint8_t *C3 = cipher + 1 + 64;

    /* KDF */
    uint32_t ct_kdf = 1;
    uint8_t ha[SM3_DIGEST_SIZE];
    size_t done = 0;
    while (done < msg_len) {
        uint8_t ct_bytes[4] = {(uint8_t)(ct_kdf>>24),(uint8_t)(ct_kdf>>16),
                               (uint8_t)(ct_kdf>>8),(uint8_t)ct_kdf};
        sm3_ctx_t hctx;
        sm3_init(&hctx);
        sm3_update(&hctx, x2, 32);
        sm3_update(&hctx, y2, 32);
        sm3_update(&hctx, ct_bytes, 4);
        sm3_final(&hctx, ha);
        size_t chunk = (msg_len - done < SM3_DIGEST_SIZE) ? msg_len - done : SM3_DIGEST_SIZE;
        for (size_t i = 0; i < chunk; i++)
            plain[done + i] = C2[done + i] ^ ha[i];
        done += chunk;
        ct_kdf++;
    }

    /* Verify C3 */
    uint8_t check[SM3_DIGEST_SIZE];
    sm3_ctx_t hctx;
    sm3_init(&hctx);
    sm3_update(&hctx, x2, 32);
    sm3_update(&hctx, plain, msg_len);
    sm3_update(&hctx, y2, 32);
    sm3_final(&hctx, check);

    uint8_t diff = 0;
    for (int i = 0; i < SM3_DIGEST_SIZE; i++)
        diff |= check[i] ^ C3[i];

    *plain_len = msg_len;
    memset(&d, 0, sizeof(d));
    if (diff) return -1;
    return 0;
}
