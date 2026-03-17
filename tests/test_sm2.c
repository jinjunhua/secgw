/*
 * SM2 unit tests
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#ifndef ALL_TESTS
#include "sm2.h"
#include "sm3.h"
#define PASS  "\033[32mPASS\033[0m"
#define FAIL  "\033[31mFAIL\033[0m"
static int test_count  = 0;
static int test_passed = 0;
static void check(const char *name, int ok) {
    test_count++;
    if (ok) { test_passed++; printf("[%s] %s\n", PASS, name); }
    else     { printf("[%s] %s\n", FAIL, name); }
}
static void hex_dump(const char *l, const uint8_t *d, size_t n) {
    printf("%s: ", l); for (size_t i=0;i<n;i++) printf("%02x",d[i]); printf("\n");
}
#else
#include "../src/crypto/sm2.h"
#include "../src/crypto/sm3.h"
#define PASS "PASS"
#define FAIL "FAIL"
static int test_count = 0, test_passed = 0;
static void check(const char *n, int ok) {
    test_count++; if (ok) test_passed++;
    printf("[%s] SM2: %s\n", ok?PASS:FAIL, n);
}
static void hex_dump(const char *l,const uint8_t *d,size_t n){
    printf("%s: ",l); for(size_t i=0;i<n;i++) printf("%02x",d[i]); printf("\n");
}
#endif

/* CSPRNG wrapper */
static int test_rng(uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, len);
    close(fd);
    return (r == (ssize_t)len) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Key generation test                                                  */
/* ------------------------------------------------------------------ */
static void test_sm2_keygen(void)
{
    sm2_key_t key;
    int r = sm2_generate_key(&key, test_rng, NULL);
    check("SM2 key generation succeeds", r == 0);

    /* Public key should be non-zero */
    uint8_t zero[32] = {0};
    check("SM2 Qx != zero", memcmp(key.Qx, zero, 32) != 0);
    check("SM2 Qy != zero", memcmp(key.Qy, zero, 32) != 0);
    check("SM2 d  != zero", memcmp(key.d,  zero, 32) != 0);

    hex_dump("SM2 d ", key.d,  32);
    hex_dump("SM2 Qx", key.Qx, 32);
    hex_dump("SM2 Qy", key.Qy, 32);
}

/* ------------------------------------------------------------------ */
/* Sign / verify test                                                   */
/* ------------------------------------------------------------------ */
static void test_sm2_sign_verify(void)
{
    sm2_key_t key;
    sm2_sig_t sig;
    const uint8_t id[]  = "1234567812345678";  /* 16-byte user ID */
    const uint8_t msg[] = "This is a test message for SM2 signing";

    int r = sm2_generate_key(&key, test_rng, NULL);
    check("SM2 keygen for sign", r == 0);
    if (r != 0) return;

    r = sm2_sign(&key, id, 16, msg, sizeof(msg)-1, &sig, test_rng, NULL);
    check("SM2 sign succeeds", r == 0);
    if (r != 0) return;

    hex_dump("SM2 sig.r", sig.r, 32);
    hex_dump("SM2 sig.s", sig.s, 32);

    r = sm2_verify(&key, id, 16, msg, sizeof(msg)-1, &sig);
    check("SM2 verify correct sig", r == 0);

    /* Tamper with signature */
    sig.r[0] ^= 0x01;
    r = sm2_verify(&key, id, 16, msg, sizeof(msg)-1, &sig);
    check("SM2 verify tampered sig fails", r != 0);

    /* Tamper with message */
    sig.r[0] ^= 0x01; /* restore */
    const uint8_t msg2[] = "This is a different message";
    r = sm2_verify(&key, id, 16, msg2, sizeof(msg2)-1, &sig);
    check("SM2 verify wrong message fails", r != 0);
}

/* ------------------------------------------------------------------ */
/* Z value computation test                                             */
/* ------------------------------------------------------------------ */
static void test_sm2_z_value(void)
{
    sm2_key_t key;
    sm2_generate_key(&key, test_rng, NULL);

    uint8_t z1[32], z2[32];
    const uint8_t id[] = "ALICE";
    sm2_compute_z(id, 5, key.Qx, key.Qy, z1);
    sm2_compute_z(id, 5, key.Qx, key.Qy, z2);

    hex_dump("SM2 Z", z1, 32);
    check("SM2 Z is deterministic", memcmp(z1, z2, 32) == 0);

    /* Different ID -> different Z */
    const uint8_t id2[] = "ALICE2";
    sm2_compute_z(id2, 6, key.Qx, key.Qy, z2);
    check("SM2 Z differs for different ID", memcmp(z1, z2, 32) != 0);
}

/* ------------------------------------------------------------------ */
/* Encryption / decryption test                                         */
/* ------------------------------------------------------------------ */
static void test_sm2_encrypt_decrypt(void)
{
    sm2_key_t key;
    sm2_generate_key(&key, test_rng, NULL);

    const uint8_t plain[] = "Secret IPSec key material!";
    size_t plain_len = sizeof(plain) - 1;

    /* Estimate cipher length */
    size_t cipher_len = 1 + 64 + 32 + plain_len;
    uint8_t *cipher = malloc(cipher_len);
    uint8_t *out    = malloc(plain_len + 1);

    int r = sm2_encrypt(&key, plain, plain_len, cipher, &cipher_len,
                         test_rng, NULL);
    check("SM2 encrypt succeeds", r == 0);

    size_t out_len = plain_len + 1;
    r = sm2_decrypt(&key, cipher, cipher_len, out, &out_len);
    check("SM2 decrypt succeeds", r == 0);
    check("SM2 decrypt == original",
          out_len == plain_len && memcmp(out, plain, plain_len) == 0);

    /* Tamper with ciphertext */
    cipher[10] ^= 0xff;
    r = sm2_decrypt(&key, cipher, cipher_len, out, &out_len);
    check("SM2 decrypt detects tampering", r != 0);

    free(cipher);
    free(out);
}

/* ------------------------------------------------------------------ */
/* ECDH key agreement                                                   */
/* ------------------------------------------------------------------ */
static void test_sm2_ecdh(void)
{
    sm2_key_t alice, bob;
    uint8_t shared_a[SM2_SHARED_KEY_SIZE];
    uint8_t shared_b[SM2_SHARED_KEY_SIZE];

    sm2_generate_key(&alice, test_rng, NULL);
    sm2_generate_key(&bob,   test_rng, NULL);

    /* Alice computes shared secret using Bob's public key */
    int r_a = sm2_ecdh(&alice, bob.Qx, bob.Qy, shared_a);
    /* Bob computes shared secret using Alice's public key */
    int r_b = sm2_ecdh(&bob, alice.Qx, alice.Qy, shared_b);

    check("SM2 ECDH Alice succeeds", r_a == 0);
    check("SM2 ECDH Bob succeeds",   r_b == 0);
    check("SM2 ECDH shared secrets match",
          memcmp(shared_a, shared_b, SM2_SHARED_KEY_SIZE) == 0);

    hex_dump("SM2 ECDH shared", shared_a, SM2_SHARED_KEY_SIZE);
}

#ifndef ALL_TESTS
int main(void)
{
    printf("=== SM2 Tests ===\n");
    test_sm2_keygen();
    test_sm2_sign_verify();
    test_sm2_z_value();
    test_sm2_encrypt_decrypt();
    test_sm2_ecdh();
    printf("\n%d/%d tests passed\n", test_passed, test_count);
    return (test_passed == test_count) ? 0 : 1;
}
#else
int run_sm2_tests(void)
{
    test_sm2_keygen();
    test_sm2_sign_verify();
    test_sm2_z_value();
    test_sm2_encrypt_decrypt();
    test_sm2_ecdh();
    return test_passed == test_count;
}
#endif
