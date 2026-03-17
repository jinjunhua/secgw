/*
 * IPSec ESP + IKE integration tests
 *
 * Tests the software-path ESP encapsulation / decapsulation using
 * SM4-GCM-128 and HMAC-SM3, simulating what the VPP plugin and
 * DPDK crypto PMD would do in the data plane.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef ALL_TESTS
#include "../src/crypto/sm4.h"
#include "../src/crypto/sm3.h"
#include "../src/crypto/sm2.h"
#include "../src/dpdk/dpdk_gm_crypto.h"
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
#include "../src/crypto/sm4.h"
#include "../src/crypto/sm3.h"
#include "../src/crypto/sm2.h"
#include "../src/dpdk/dpdk_gm_crypto.h"
#define PASS "PASS"
#define FAIL "FAIL"
static int test_count = 0, test_passed = 0;
static void check(const char *n, int ok) {
    test_count++; if (ok) test_passed++;
    printf("[%s] IPSec: %s\n", ok?PASS:FAIL, n);
}
static void hex_dump(const char *l, const uint8_t *d, size_t n) {
    printf("%s: ", l); for(size_t i=0;i<n;i++) printf("%02x",d[i]); printf("\n");
}
#endif

/* ------------------------------------------------------------------ */
/* Simulated ESP packet structures                                      */
/* ------------------------------------------------------------------ */
#define ESP_SPI_SIZE    4
#define ESP_SEQ_SIZE    4
#define ESP_IV_SIZE    12
#define ESP_HDR_SIZE    8
#define ESP_ICV_SIZE   16

typedef struct __attribute__((packed)) {
    uint32_t spi;
    uint32_t seq;
    uint8_t  iv[ESP_IV_SIZE];
} esp_hdr_t;

/* SA parameters */
typedef struct {
    uint32_t spi;
    uint8_t  enc_key[16];
    uint8_t  iv_base[12];
    uint32_t seq;
} test_sa_t;

/* ------------------------------------------------------------------ */
/* ESP encapsulation (software)                                         */
/* ------------------------------------------------------------------ */
static int esp_encap(const test_sa_t *sa,
                     const uint8_t *payload, size_t payload_len,
                     uint8_t *esp_pkt, size_t *esp_len)
{
    size_t needed = ESP_HDR_SIZE + ESP_IV_SIZE + payload_len + ESP_ICV_SIZE;
    if (*esp_len < needed) { *esp_len = needed; return -1; }

    esp_hdr_t *hdr = (esp_hdr_t *)esp_pkt;
    uint32_t seq   = ((test_sa_t *)sa)->seq + 1;
    hdr->spi = __builtin_bswap32(sa->spi);
    hdr->seq = __builtin_bswap32(seq);

    /* IV = base_iv XOR (seq in last 4 bytes) */
    memcpy(hdr->iv, sa->iv_base, 12);
    uint32_t *iv_seq = (uint32_t *)(hdr->iv + 8);
    *iv_seq ^= __builtin_bswap32(seq);

    /* AAD = SPI || SEQ (first 8 bytes of ESP header) */
    uint8_t aad[8];
    memcpy(aad, esp_pkt, 8);

    uint8_t *ct  = esp_pkt + ESP_HDR_SIZE + ESP_IV_SIZE;
    uint8_t *tag = ct + payload_len;

    int r = sm4_gcm_encrypt(sa->enc_key,
                             hdr->iv, 12,
                             aad, 8,
                             payload, payload_len,
                             ct, tag, ESP_ICV_SIZE);
    if (r != 0) return r;

    ((test_sa_t *)sa)->seq = seq;
    *esp_len = needed;
    return 0;
}

/* ------------------------------------------------------------------ */
/* ESP decapsulation (software)                                         */
/* ------------------------------------------------------------------ */
static int esp_decap(const test_sa_t *sa,
                     const uint8_t *esp_pkt, size_t esp_len,
                     uint8_t *payload, size_t *payload_len)
{
    if (esp_len < (size_t)(ESP_HDR_SIZE + ESP_IV_SIZE + ESP_ICV_SIZE))
        return -1;

    const esp_hdr_t *hdr = (const esp_hdr_t *)esp_pkt;

    /* Verify SPI */
    uint32_t spi = __builtin_bswap32(hdr->spi);
    if (spi != sa->spi) return -1;

    size_t ct_len = esp_len - ESP_HDR_SIZE - ESP_IV_SIZE - ESP_ICV_SIZE;
    if (*payload_len < ct_len) { *payload_len = ct_len; return -1; }

    const uint8_t *ct  = esp_pkt + ESP_HDR_SIZE + ESP_IV_SIZE;
    const uint8_t *tag = ct + ct_len;
    uint8_t aad[8];
    memcpy(aad, esp_pkt, 8);

    int r = sm4_gcm_decrypt(sa->enc_key,
                             hdr->iv, 12,
                             aad, 8,
                             ct, ct_len,
                             payload, tag, ESP_ICV_SIZE);
    if (r != 0) return r;

    *payload_len = ct_len;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 1: Basic ESP encap/decap round-trip                             */
/* ------------------------------------------------------------------ */
static void test_esp_roundtrip(void)
{
    test_sa_t sa = {
        .spi     = 0x12345678,
        .enc_key = {0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,
                    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10},
        .iv_base = {0x00,0x01,0x02,0x03,0x04,0x05,
                    0x06,0x07,0x08,0x09,0x0a,0x0b},
        .seq     = 0,
    };

    const uint8_t payload[] = "10.0.0.1 -> 10.0.0.2: Hello from GM IPSec!";
    size_t payload_len = sizeof(payload) - 1;

    uint8_t esp_buf[512];
    size_t  esp_len = sizeof(esp_buf);

    int r = esp_encap(&sa, payload, payload_len, esp_buf, &esp_len);
    check("ESP encap succeeds", r == 0);
    check("ESP packet longer than payload",
          esp_len > payload_len);

    hex_dump("ESP pkt (first 24 bytes)", esp_buf, 24);

    uint8_t dec_buf[512];
    size_t  dec_len = sizeof(dec_buf);

    r = esp_decap(&sa, esp_buf, esp_len, dec_buf, &dec_len);
    check("ESP decap succeeds", r == 0);
    check("ESP decap == original payload",
          dec_len == payload_len && memcmp(dec_buf, payload, payload_len) == 0);
}

/* ------------------------------------------------------------------ */
/* Test 2: Authentication failure on tampered packet                    */
/* ------------------------------------------------------------------ */
static void test_esp_tamper(void)
{
    test_sa_t sa = {
        .spi     = 0xdeadbeef,
        .enc_key = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
                    0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00},
        .iv_base = {0xca,0xfe,0xba,0xbe,0xfa,0xce,
                    0xdb,0xad,0xde,0xca,0xf8,0x88},
        .seq     = 0,
    };

    const uint8_t payload[] = "Top-secret payload";
    uint8_t esp_buf[512];
    size_t esp_len = sizeof(esp_buf);

    esp_encap(&sa, payload, sizeof(payload)-1, esp_buf, &esp_len);

    /* Flip a byte in the ciphertext */
    esp_buf[ESP_HDR_SIZE + ESP_IV_SIZE + 5] ^= 0x42;

    uint8_t dec_buf[512];
    size_t dec_len = sizeof(dec_buf);
    int r = esp_decap(&sa, esp_buf, esp_len, dec_buf, &dec_len);
    check("ESP tampered packet rejected", r != 0);
}

/* ------------------------------------------------------------------ */
/* Test 3: Wrong SPI rejected                                           */
/* ------------------------------------------------------------------ */
static void test_esp_wrong_spi(void)
{
    test_sa_t sa = {
        .spi     = 0x11111111,
        .enc_key = {0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,
                    0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99},
        .iv_base = {0,1,2,3,4,5,6,7,8,9,10,11},
        .seq     = 0,
    };
    test_sa_t sa2 = sa;
    sa2.spi = 0x22222222;

    const uint8_t payload[] = "Test";
    uint8_t esp_buf[256];
    size_t esp_len = sizeof(esp_buf);
    esp_encap(&sa, payload, sizeof(payload)-1, esp_buf, &esp_len);

    uint8_t dec_buf[256];
    size_t dec_len = sizeof(dec_buf);
    int r = esp_decap(&sa2, esp_buf, esp_len, dec_buf, &dec_len);
    check("ESP wrong SPI rejected", r != 0);
}

/* ------------------------------------------------------------------ */
/* Test 4: Multiple packets (sequence number increment)                 */
/* ------------------------------------------------------------------ */
static void test_esp_multi_seq(void)
{
    test_sa_t sa = {
        .spi     = 0xaabbccdd,
        .enc_key = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff},
        .iv_base = {0,0,0,0,0,0,0,0,0,0,0,0},
        .seq     = 0,
    };

    int all_ok = 1;
    for (int i = 0; i < 5; i++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Packet %d: test data", i);
        size_t msg_len = strlen(msg);

        uint8_t esp_buf[512];
        size_t esp_len = sizeof(esp_buf);
        uint8_t dec_buf[512];
        size_t dec_len = sizeof(dec_buf);

        esp_encap(&sa, (const uint8_t *)msg, msg_len, esp_buf, &esp_len);
        int r = esp_decap(&sa, esp_buf, esp_len, dec_buf, &dec_len);
        if (r != 0 || dec_len != msg_len || memcmp(dec_buf, msg, msg_len) != 0)
            all_ok = 0;
    }
    check("ESP multiple packets all pass", all_ok);
    printf("  SA seq after 5 packets: %u\n", sa.seq);
}

/* ------------------------------------------------------------------ */
/* Test 5: DPDK software crypto path                                    */
/* ------------------------------------------------------------------ */
static void test_dpdk_sw_crypto(void)
{
    gm_sm4_cbc_session_t enc_sess = {
        .key = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10},
        .iv  = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
        .encrypt = 1,
    };
    gm_sm4_cbc_session_t dec_sess = enc_sess;
    dec_sess.encrypt = 0;

    uint8_t pt[32] = "Test plaintext 16 16 bytes here";
    uint8_t ct[32], pt2[32];

    int r = gm_sw_process_cipher(&enc_sess, pt, ct, 32);
    check("DPDK SW SM4-CBC encrypt", r == 0);

    r = gm_sw_process_cipher(&dec_sess, ct, pt2, 32);
    check("DPDK SW SM4-CBC decrypt", r == 0);
    check("DPDK SW SM4-CBC round-trip", memcmp(pt, pt2, 32) == 0);

    /* HMAC-SM3 */
    gm_hmac_sm3_session_t auth_sess = {
        .key = {0xde,0xad,0xbe,0xef,0xca,0xfe,0xba,0xbe},
        .key_len = 8,
    };
    uint8_t mac1[SM3_HMAC_SIZE], mac2[SM3_HMAC_SIZE];
    const uint8_t data[] = "IPSec packet data for integrity check";

    gm_sw_process_auth(&auth_sess, data, sizeof(data)-1, mac1);
    gm_sw_process_auth(&auth_sess, data, sizeof(data)-1, mac2);
    check("DPDK SW HMAC-SM3 deterministic", memcmp(mac1, mac2, SM3_HMAC_SIZE) == 0);

    hex_dump("DPDK SW HMAC-SM3", mac1, SM3_HMAC_SIZE);
}

/* ------------------------------------------------------------------ */
/* Test 6: SM4-GCM AEAD via gm_sw_process_aead                         */
/* ------------------------------------------------------------------ */
static void test_dpdk_sw_aead(void)
{
    gm_sm4_gcm_session_t enc_sess = {
        .key     = {0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
                    0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08},
        .iv      = {0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88},
        .tag_len = 16,
        .encrypt = 1,
    };
    gm_sm4_gcm_session_t dec_sess = enc_sess;
    dec_sess.encrypt = 0;

    const uint8_t aad[]  = "ESP-AAD-SPI-SEQ";
    const uint8_t pt[]   = "The AEAD payload for GM-IPSec ESP";
    size_t pt_len = sizeof(pt) - 1;
    uint8_t ct[128], pt2[128], tag[16];

    int r = gm_sw_process_aead(&enc_sess, aad, sizeof(aad)-1,
                                pt, ct, pt_len, tag, 16);
    check("DPDK SW SM4-GCM encrypt", r == 0);

    r = gm_sw_process_aead(&dec_sess, aad, sizeof(aad)-1,
                             ct, pt2, pt_len, tag, 16);
    check("DPDK SW SM4-GCM decrypt", r == 0);
    check("DPDK SW SM4-GCM round-trip", memcmp(pt2, pt, pt_len) == 0);

    /* Tamper */
    ct[0] ^= 0xff;
    r = gm_sw_process_aead(&dec_sess, aad, sizeof(aad)-1,
                             ct, pt2, pt_len, tag, 16);
    check("DPDK SW SM4-GCM tamper detected", r != 0);
}

#ifndef ALL_TESTS
int main(void)
{
    printf("=== IPSec / Crypto Integration Tests ===\n");
    test_esp_roundtrip();
    test_esp_tamper();
    test_esp_wrong_spi();
    test_esp_multi_seq();
    test_dpdk_sw_crypto();
    test_dpdk_sw_aead();
    printf("\n%d/%d tests passed\n", test_passed, test_count);
    return (test_passed == test_count) ? 0 : 1;
}
#else
int run_ipsec_tests(void)
{
    test_esp_roundtrip();
    test_esp_tamper();
    test_esp_wrong_spi();
    test_esp_multi_seq();
    test_dpdk_sw_crypto();
    test_dpdk_sw_aead();
    return test_passed == test_count;
}
#endif
