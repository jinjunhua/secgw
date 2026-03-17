/*
 * SM3 hash algorithm unit tests
 * Test vectors from GM/T 0004-2012
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#ifndef ALL_TESTS
#include "sm3.h"
#define PASS  "\033[32mPASS\033[0m"
#define FAIL  "\033[31mFAIL\033[0m"

static int test_count  = 0;
static int test_passed = 0;

static void check(const char *name, int ok)
{
    test_count++;
    if (ok) { test_passed++; printf("[%s] %s\n", PASS, name); }
    else     { printf("[%s] %s\n", FAIL, name); }
}

static void hex_dump(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}
#else
#include "../src/crypto/sm3.h"
#define PASS  "PASS"
#define FAIL  "FAIL"
static int test_count = 0, test_passed = 0;
static void check(const char *name, int ok) {
    test_count++; if (ok) test_passed++;
    printf("[%s] SM3: %s\n", ok ? PASS : FAIL, name);
}
static void hex_dump(const char *l, const uint8_t *d, size_t n) {
    printf("%s: ", l); for (size_t i=0;i<n;i++) printf("%02x",d[i]); printf("\n");
}
#endif

/* ------------------------------------------------------------------ */
/* Test vector 1: "abc" -> known digest from GM/T 0004-2012            */
/* ------------------------------------------------------------------ */
static void test_sm3_abc(void)
{
    const char *msg = "abc";
    /* Expected: 66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0 */
    const uint8_t expected[32] = {
        0x66,0xc7,0xf0,0xf4,0x62,0xee,0xed,0xd9,
        0xd1,0xf2,0xd4,0x6b,0xdc,0x10,0xe4,0xe2,
        0x41,0x67,0xc4,0x87,0x5c,0xf2,0xf7,0xa2,
        0x29,0x7d,0xa0,0x2b,0x8f,0x4b,0xa8,0xe0
    };
    uint8_t digest[SM3_DIGEST_SIZE];
    sm3((const uint8_t *)msg, 3, digest);
    hex_dump("SM3(\"abc\")", digest, 32);
    check("SM3(\"abc\") == expected", memcmp(digest, expected, 32) == 0);
}

/* ------------------------------------------------------------------ */
/* Test vector 2: "abcd" * 16 (64 bytes) from GM/T 0004-2012 App. A   */
/* Expected: debe9ff922275b8a138604889c18e5a4d6fdb70e5387e5776529...  */
/* ------------------------------------------------------------------ */
static void test_sm3_abcd16(void)
{
    /* "abcd" repeated 16 times = 64 bytes */
    const char *msg = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    /* Expected from GM/T 0004-2012 */
    const uint8_t expected[32] = {
        0xde,0xbe,0x9f,0xf9,0x22,0x75,0xb8,0xa1,
        0x38,0x60,0x48,0x89,0xc1,0x8e,0x5a,0x4d,
        0x6f,0xdb,0x70,0xe5,0x38,0x7e,0x57,0x65,
        0x29,0x3d,0xcb,0xa3,0x9c,0x0c,0x57,0x32
    };
    uint8_t digest[SM3_DIGEST_SIZE];
    sm3((const uint8_t *)msg, 64, digest);
    hex_dump("SM3(\"abcd\"*16)", digest, 32);
    check("SM3(\"abcd\"*16) == expected", memcmp(digest, expected, 32) == 0);
}

/* ------------------------------------------------------------------ */
/* Test vector 3: empty message                                         */
/* ------------------------------------------------------------------ */
static void test_sm3_empty(void)
{
    uint8_t digest[SM3_DIGEST_SIZE];
    sm3(NULL, 0, digest);
    hex_dump("SM3(empty)", digest, 32);
    /* Just check it doesn't crash and produces non-zero output */
    uint8_t zero[SM3_DIGEST_SIZE] = {0};
    check("SM3(empty) != zeros", memcmp(digest, zero, 32) != 0);
}

/* ------------------------------------------------------------------ */
/* HMAC-SM3 test                                                        */
/* ------------------------------------------------------------------ */
static void test_hmac_sm3(void)
{
    const uint8_t key[]  = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                             0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
    const uint8_t data[] = "Hello, GM IPSec!";
    uint8_t mac1[SM3_HMAC_SIZE];
    uint8_t mac2[SM3_HMAC_SIZE];

    sm3_hmac(key, sizeof(key), data, sizeof(data)-1, mac1);
    sm3_hmac(key, sizeof(key), data, sizeof(data)-1, mac2);

    hex_dump("HMAC-SM3", mac1, SM3_HMAC_SIZE);
    check("HMAC-SM3 is deterministic", memcmp(mac1, mac2, SM3_HMAC_SIZE) == 0);

    /* Different data -> different MAC */
    const uint8_t data2[] = "Hello, GM IPSec.";
    sm3_hmac(key, sizeof(key), data2, sizeof(data2)-1, mac2);
    check("HMAC-SM3 different data -> different MAC",
          memcmp(mac1, mac2, SM3_HMAC_SIZE) != 0);
}

/* ------------------------------------------------------------------ */
/* Incremental update test                                              */
/* ------------------------------------------------------------------ */
static void test_sm3_incremental(void)
{
    const char *msg = "abcdefghijklmnopqrstuvwxyz";
    uint8_t d1[SM3_DIGEST_SIZE], d2[SM3_DIGEST_SIZE];

    sm3((const uint8_t *)msg, 26, d1);

    sm3_ctx_t ctx;
    sm3_init(&ctx);
    /* Feed in 1 byte at a time */
    for (int i = 0; i < 26; i++)
        sm3_update(&ctx, (const uint8_t *)msg + i, 1);
    sm3_final(&ctx, d2);

    check("SM3 incremental == one-shot", memcmp(d1, d2, SM3_DIGEST_SIZE) == 0);
}

/* ------------------------------------------------------------------ */
/* Large message (> 1 block) test                                       */
/* ------------------------------------------------------------------ */
static void test_sm3_large(void)
{
    uint8_t msg[256];
    for (int i = 0; i < 256; i++) msg[i] = (uint8_t)i;
    uint8_t d1[SM3_DIGEST_SIZE], d2[SM3_DIGEST_SIZE];

    sm3(msg, 256, d1);

    /* Split at various points */
    sm3_ctx_t ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, msg, 100);
    sm3_update(&ctx, msg + 100, 56);
    sm3_update(&ctx, msg + 156, 100);
    sm3_final(&ctx, d2);

    check("SM3 split update matches", memcmp(d1, d2, SM3_DIGEST_SIZE) == 0);
}

#ifndef ALL_TESTS
int main(void)
{
    printf("=== SM3 Tests ===\n");
    test_sm3_abc();
    test_sm3_abcd16();
    test_sm3_empty();
    test_hmac_sm3();
    test_sm3_incremental();
    test_sm3_large();
    printf("\n%d/%d tests passed\n", test_passed, test_count);
    return (test_passed == test_count) ? 0 : 1;
}
#else
int run_sm3_tests(void)
{
    test_sm3_abc();
    test_sm3_abcd16();
    test_sm3_empty();
    test_hmac_sm3();
    test_sm3_incremental();
    test_sm3_large();
    return test_passed == test_count;
}
#endif
