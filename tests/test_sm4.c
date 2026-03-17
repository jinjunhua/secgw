/*
 * SM4 cipher unit tests
 * Test vectors from GM/T 0002-2012
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#ifndef ALL_TESTS
#include "sm4.h"
#define PASS  "\033[32mPASS\033[0m"
#define FAIL  "\033[31mFAIL\033[0m"
static int test_count  = 0;
static int test_passed = 0;
static void check(const char *name, int ok) {
    test_count++;
    if (ok) { test_passed++; printf("[%s] %s\n", PASS, name); }
    else     { printf("[%s] %s\n", FAIL, name); }
}
static void hex_dump(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}
#else
#include "../src/crypto/sm4.h"
#define PASS "PASS"
#define FAIL "FAIL"
static int test_count = 0, test_passed = 0;
static void check(const char *n, int ok) {
    test_count++; if (ok) test_passed++;
    printf("[%s] SM4: %s\n", ok?PASS:FAIL, n);
}
static void hex_dump(const char *l,const uint8_t *d,size_t n){
    printf("%s: ",l); for(size_t i=0;i<n;i++) printf("%02x",d[i]); printf("\n");
}
#endif

/* ------------------------------------------------------------------ */
/* Test vector from GM/T 0002-2012 Appendix A                          */
/* Key:  0123456789abcdeffedcba9876543210                               */
/* PT:   0123456789abcdeffedcba9876543210                               */
/* CT:   681edf34d206965e86b3e94f536e4246                               */
/* ------------------------------------------------------------------ */
static void test_sm4_ecb_vector(void)
{
    const uint8_t key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    const uint8_t pt[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    const uint8_t expected_ct[16] = {
        0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,
        0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46
    };

    sm4_ctx_t ctx;
    uint8_t ct[16], pt2[16];

    sm4_set_key_enc(&ctx, key);
    sm4_encrypt(&ctx, pt, ct);
    hex_dump("SM4 ECB enc", ct, 16);
    check("SM4 ECB encrypt == expected", memcmp(ct, expected_ct, 16) == 0);

    sm4_set_key_dec(&ctx, key);
    sm4_decrypt(&ctx, ct, pt2);
    hex_dump("SM4 ECB dec", pt2, 16);
    check("SM4 ECB decrypt == plaintext", memcmp(pt2, pt, 16) == 0);
}

/* ------------------------------------------------------------------ */
/* SM4-CBC encrypt/decrypt                                              */
/* ------------------------------------------------------------------ */
static void test_sm4_cbc(void)
{
    const uint8_t key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    const uint8_t pt[32] = {
        'H','e','l','l','o',' ','G','M',' ','I','P','S','e','c','!','!',
        'T','e','s','t',' ','B','l','o','c','k',' ','T','w','o','!','!'
    };

    sm4_ctx_t ctx_enc, ctx_dec;
    uint8_t ct[32], pt2[32];

    sm4_set_key_enc(&ctx_enc, key);
    sm4_cbc_encrypt(&ctx_enc, iv, pt, ct, 32);

    sm4_set_key_dec(&ctx_dec, key);
    sm4_cbc_decrypt(&ctx_dec, iv, ct, pt2, 32);

    hex_dump("SM4-CBC CT", ct, 32);
    check("SM4-CBC decrypt == original", memcmp(pt2, pt, 32) == 0);
    check("SM4-CBC CT != PT", memcmp(ct, pt, 32) != 0);
}

/* ------------------------------------------------------------------ */
/* SM4-CTR                                                              */
/* ------------------------------------------------------------------ */
static void test_sm4_ctr(void)
{
    const uint8_t key[16] = {
        0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
    };
    uint8_t ctr[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
    };
    uint8_t ctr2[16];
    memcpy(ctr2, ctr, 16);

    const uint8_t pt[48] = "The quick brown fox jumps over the lazy dog!!!";
    uint8_t ct[48], pt2[48];

    sm4_ctx_t ctx;
    sm4_set_key_enc(&ctx, key);
    sm4_ctr_crypt(&ctx, ctr, pt, ct, 48);

    sm4_set_key_enc(&ctx, key);
    sm4_ctr_crypt(&ctx, ctr2, ct, pt2, 48);

    check("SM4-CTR decrypt == original", memcmp(pt2, pt, 48) == 0);
    check("SM4-CTR CT != PT", memcmp(ct, pt, 48) != 0);
}

/* ------------------------------------------------------------------ */
/* SM4-GCM encrypt/decrypt                                              */
/* ------------------------------------------------------------------ */
static void test_sm4_gcm(void)
{
    const uint8_t key[16] = {
        0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
        0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
    };
    const uint8_t iv[12] = {
        0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,
        0xde,0xca,0xf8,0x88
    };
    const uint8_t aad[] = "IPSec ESP Header";
    const uint8_t pt[]  = "This is the secret payload data for SM4-GCM!";
    size_t pt_len = sizeof(pt) - 1;

    uint8_t ct[128], pt2[128], tag[16];
    size_t ct_len = pt_len;

    int r = sm4_gcm_encrypt(key, iv, 12, aad, sizeof(aad)-1, pt, pt_len,
                             ct, tag, 16);
    check("SM4-GCM encrypt returns 0", r == 0);

    hex_dump("SM4-GCM tag", tag, 16);
    check("SM4-GCM CT != PT", memcmp(ct, pt, pt_len) != 0);

    r = sm4_gcm_decrypt(key, iv, 12, aad, sizeof(aad)-1, ct, ct_len,
                         pt2, tag, 16);
    check("SM4-GCM decrypt returns 0", r == 0);
    pt2[pt_len] = '\0';
    check("SM4-GCM decrypt == original", memcmp(pt2, pt, pt_len) == 0);

    /* Tamper with tag -> authentication failure */
    tag[0] ^= 0xff;
    r = sm4_gcm_decrypt(key, iv, 12, aad, sizeof(aad)-1, ct, ct_len,
                         pt2, tag, 16);
    check("SM4-GCM tampered tag detected", r != 0);
}

/* ------------------------------------------------------------------ */
/* SM4 key schedule: encrypt/decrypt round-trip of all-zero block      */
/* ------------------------------------------------------------------ */
static void test_sm4_zeros(void)
{
    uint8_t key[16] = {0};
    uint8_t pt[16]  = {0};
    uint8_t ct[16], pt2[16];

    sm4_ctx_t ctx;
    sm4_set_key_enc(&ctx, key);
    sm4_encrypt(&ctx, pt, ct);
    hex_dump("SM4 enc(0, 0)", ct, 16);

    sm4_set_key_dec(&ctx, key);
    sm4_decrypt(&ctx, ct, pt2);
    check("SM4 all-zeros round-trip", memcmp(pt2, pt, 16) == 0);
}

#ifndef ALL_TESTS
int main(void)
{
    printf("=== SM4 Tests ===\n");
    test_sm4_ecb_vector();
    test_sm4_cbc();
    test_sm4_ctr();
    test_sm4_gcm();
    test_sm4_zeros();
    printf("\n%d/%d tests passed\n", test_passed, test_count);
    return (test_passed == test_count) ? 0 : 1;
}
#else
int run_sm4_tests(void)
{
    test_sm4_ecb_vector();
    test_sm4_cbc();
    test_sm4_ctr();
    test_sm4_gcm();
    test_sm4_zeros();
    return test_passed == test_count;
}
#endif
