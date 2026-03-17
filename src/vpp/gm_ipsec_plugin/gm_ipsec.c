/*
 * GM IPSec VPP Plugin implementation
 *
 * ESP packet format (RFC 4303):
 *  0                   1                   2                   3
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |               Security Parameters Index (SPI)                 |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                      Sequence Number                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  IV (12 bytes for GCM)                                        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Payload (encrypted)                                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  ICV (16 bytes for SM4-GCM-128)                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#include "gm_ipsec.h"
#include "../../crypto/sm4.h"
#include "../../crypto/sm3.h"
#include <vnet/ipsec/esp.h>
#include <vppinfra/string.h>

gm_ipsec_main_t gm_ipsec_main;

/* ------------------------------------------------------------------ */
/* ESP Header / Trailer structures                                      */
/* ------------------------------------------------------------------ */
#define ESP_ICV_SIZE    16  /* SM4-GCM tag size */
#define ESP_IV_SIZE     12  /* GCM IV size */
#define ESP_HDR_SIZE     8  /* SPI(4) + SEQ(4) */
#define ESP_OVERHEAD    (ESP_HDR_SIZE + ESP_IV_SIZE + ESP_ICV_SIZE)

typedef struct __attribute__((packed)) {
    uint32_t spi;
    uint32_t seq;
    uint8_t  iv[ESP_IV_SIZE];
} gm_esp_hdr_t;

/* ------------------------------------------------------------------ */
/* Encrypt node                                                         */
/* ------------------------------------------------------------------ */

typedef enum {
    GM_ESP_ENC_NEXT_INTERFACE_OUTPUT,
    GM_ESP_ENC_NEXT_DROP,
    GM_ESP_ENC_N_NEXT,
} gm_esp_enc_next_t;

static uword
gm_esp4_encrypt_fn(vlib_main_t *vm,
                   vlib_node_runtime_t *node,
                   vlib_frame_t *frame)
{
    u32 n_left_from, *from, *to_next;
    gm_esp_enc_next_t next_index = GM_ESP_ENC_NEXT_INTERFACE_OUTPUT;
    gm_ipsec_main_t *im = &gm_ipsec_main;

    from = vlib_frame_vector_args(frame);
    n_left_from = frame->n_vectors;

    while (n_left_from > 0) {
        u32 n_left_to_next;
        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0) {
            vlib_buffer_t *b;
            u32 bi, next;
            ip4_header_t *ip4;
            gm_esp_hdr_t *esp;
            u8 *payload;
            u16 payload_len;
            u8 tag[ESP_ICV_SIZE];
            gm_sa_ctx_t *sa;

            bi = from[0];
            from++;
            n_left_from--;
            to_next[0] = bi;
            to_next++;
            n_left_to_next--;

            b = vlib_get_buffer(vm, bi);
            next = GM_ESP_ENC_NEXT_INTERFACE_OUTPUT;

            /* Get SA from buffer opaque (set by policy lookup) */
            u32 sa_idx = vnet_buffer(b)->ipsec.sad_index;
            if (sa_idx >= vec_len(im->sa_pool)) {
                b->error = node->errors[GM_IPSEC_ERROR_BAD_SPI];
                next = GM_ESP_ENC_NEXT_DROP;
                goto done;
            }
            sa = &im->sa_pool[sa_idx];

            /* Original IP header */
            ip4 = vlib_buffer_get_current(b);
            payload = (u8 *)(ip4 + 1);
            payload_len = clib_net_to_host_u16(ip4->length) - sizeof(*ip4);

            /* Make room for ESP header + IV */
            vlib_buffer_advance(b, -(i32)(ESP_HDR_SIZE + ESP_IV_SIZE));
            esp = vlib_buffer_get_current(b);
            esp->spi = clib_host_to_net_u32(sa->spi);
            esp->seq = clib_host_to_net_u32(++sa->seq);

            /* Build GCM IV: base_iv XOR seq */
            uint8_t iv[ESP_IV_SIZE];
            clib_memcpy(iv, sa->iv, ESP_IV_SIZE);
            uint32_t *iv_seq = (uint32_t *)(iv + 8);
            *iv_seq ^= clib_host_to_net_u32(sa->seq);
            clib_memcpy(esp->iv, iv, ESP_IV_SIZE);

            /* AAD = SPI || SEQ (8 bytes) */
            uint8_t aad[8];
            clib_memcpy(aad, esp, 8);

            /* Encrypt in-place using SM4-GCM */
            u8 *enc_out = (u8 *)(esp + 1) + ESP_IV_SIZE;
            /* Note: payload is after ESP header + IV */
            if (sm4_gcm_encrypt(sa->enc_key,
                                iv, ESP_IV_SIZE,
                                aad, 8,
                                payload, payload_len,
                                enc_out, tag, ESP_ICV_SIZE) != 0) {
                b->error = node->errors[GM_IPSEC_ERROR_ENCRYPT_FAILED];
                next = GM_ESP_ENC_NEXT_DROP;
                goto done;
            }

            /* Append ICV */
            u8 *icv = vlib_buffer_get_current(b) + ESP_HDR_SIZE + ESP_IV_SIZE + payload_len;
            clib_memcpy(icv, tag, ESP_ICV_SIZE);
            b->current_length = ESP_HDR_SIZE + ESP_IV_SIZE + payload_len + ESP_ICV_SIZE;

done:
            vlib_validate_buffer_enqueue_x1(vm, node, next_index,
                                             to_next, n_left_to_next,
                                             bi, next);
        }
        vlib_put_next_frame(vm, node, next_index, n_left_to_next);
    }

    return frame->n_vectors;
}

/* ------------------------------------------------------------------ */
/* Decrypt node                                                         */
/* ------------------------------------------------------------------ */

typedef enum {
    GM_ESP_DEC_NEXT_IP4_INPUT,
    GM_ESP_DEC_NEXT_DROP,
    GM_ESP_DEC_N_NEXT,
} gm_esp_dec_next_t;

static uword
gm_esp4_decrypt_fn(vlib_main_t *vm,
                   vlib_node_runtime_t *node,
                   vlib_frame_t *frame)
{
    u32 n_left_from, *from, *to_next;
    gm_esp_dec_next_t next_index = GM_ESP_DEC_NEXT_IP4_INPUT;
    gm_ipsec_main_t *im = &gm_ipsec_main;

    from = vlib_frame_vector_args(frame);
    n_left_from = frame->n_vectors;

    while (n_left_from > 0) {
        u32 n_left_to_next;
        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0) {
            vlib_buffer_t *b;
            u32 bi, next;
            gm_esp_hdr_t *esp;
            gm_sa_ctx_t *sa;
            u32 sa_idx;

            bi = from[0];
            from++;
            n_left_from--;
            to_next[0] = bi;
            to_next++;
            n_left_to_next--;

            b = vlib_get_buffer(vm, bi);
            next = GM_ESP_DEC_NEXT_IP4_INPUT;

            esp = vlib_buffer_get_current(b);
            u32 spi = clib_net_to_host_u32(esp->spi);

            /* SPI lookup */
            sa_idx = ~0;
            for (u32 i = 0; i < vec_len(im->sa_pool); i++) {
                if (im->sa_pool[i].spi == spi) {
                    sa_idx = i;
                    break;
                }
            }
            if (sa_idx == ~0u) {
                b->error = node->errors[GM_IPSEC_ERROR_BAD_SPI];
                next = GM_ESP_DEC_NEXT_DROP;
                goto dec_done;
            }
            sa = &im->sa_pool[sa_idx];

            /* Extract fields */
            u32 seq = clib_net_to_host_u32(esp->seq);
            u8 *iv  = esp->iv;
            u16 payload_len = b->current_length
                              - ESP_HDR_SIZE - ESP_IV_SIZE - ESP_ICV_SIZE;

            /* AAD */
            uint8_t aad[8];
            clib_memcpy(aad, esp, 8);

            u8 *ct  = (u8 *)esp + ESP_HDR_SIZE + ESP_IV_SIZE;
            u8 *icv = ct + payload_len;

            /* Decrypt in-place */
            u8 plain[4096];
            if (payload_len > sizeof(plain)) {
                b->error = node->errors[GM_IPSEC_ERROR_DECRYPT_FAILED];
                next = GM_ESP_DEC_NEXT_DROP;
                goto dec_done;
            }
            if (sm4_gcm_decrypt(sa->enc_key,
                                iv, ESP_IV_SIZE,
                                aad, 8,
                                ct, payload_len,
                                plain, icv, ESP_ICV_SIZE) != 0) {
                b->error = node->errors[GM_IPSEC_ERROR_AUTH_FAILED];
                next = GM_ESP_DEC_NEXT_DROP;
                goto dec_done;
            }

            /* Reconstruct inner IP packet */
            vlib_buffer_advance(b, ESP_HDR_SIZE + ESP_IV_SIZE);
            clib_memcpy(vlib_buffer_get_current(b), plain, payload_len);
            b->current_length = payload_len;
            (void)seq;

dec_done:
            vlib_validate_buffer_enqueue_x1(vm, node, next_index,
                                             to_next, n_left_to_next,
                                             bi, next);
        }
        vlib_put_next_frame(vm, node, next_index, n_left_to_next);
    }

    return frame->n_vectors;
}

/* ------------------------------------------------------------------ */
/* Node registrations                                                   */
/* ------------------------------------------------------------------ */

/* clang-format off */
VLIB_REGISTER_NODE(gm_esp4_encrypt_node) = {
    .function   = gm_esp4_encrypt_fn,
    .name       = GM_IPSEC_ESP_ENC_NODE,
    .vector_size = sizeof(u32),
    .format_trace = NULL,
    .type       = VLIB_NODE_TYPE_INTERNAL,
    .n_errors   = GM_IPSEC_N_ERROR,
    .error_strings = (char *[]) {
#define _(sym, str) str,
        foreach_gm_ipsec_error
#undef _
    },
    .n_next_nodes = GM_ESP_ENC_N_NEXT,
    .next_nodes = {
        [GM_ESP_ENC_NEXT_INTERFACE_OUTPUT] = "interface-output",
        [GM_ESP_ENC_NEXT_DROP]             = "error-drop",
    },
};

VLIB_REGISTER_NODE(gm_esp4_decrypt_node) = {
    .function   = gm_esp4_decrypt_fn,
    .name       = GM_IPSEC_ESP_DEC_NODE,
    .vector_size = sizeof(u32),
    .format_trace = NULL,
    .type       = VLIB_NODE_TYPE_INTERNAL,
    .n_errors   = GM_IPSEC_N_ERROR,
    .error_strings = (char *[]) {
#define _(sym, str) str,
        foreach_gm_ipsec_error
#undef _
    },
    .n_next_nodes = GM_ESP_DEC_N_NEXT,
    .next_nodes = {
        [GM_ESP_DEC_NEXT_IP4_INPUT] = "ip4-input",
        [GM_ESP_DEC_NEXT_DROP]      = "error-drop",
    },
};
/* clang-format on */

/* ------------------------------------------------------------------ */
/* Plugin init                                                          */
/* ------------------------------------------------------------------ */

clib_error_t *gm_ipsec_init(vlib_main_t *vm)
{
    gm_ipsec_main_t *im = &gm_ipsec_main;
    clib_memset(im, 0, sizeof(*im));
    im->vlib_main  = vm;
    im->vnet_main  = vnet_get_main();
    im->enc_node_index = gm_esp4_encrypt_node.index;
    im->dec_node_index = gm_esp4_decrypt_node.index;
    vec_validate(im->sa_pool, 0);

    clib_warning("GM IPSec plugin initialized "
                 "(enc=%u dec=%u)",
                 im->enc_node_index, im->dec_node_index);
    return 0;
}

VLIB_INIT_FUNCTION(gm_ipsec_init);

VLIB_PLUGIN_REGISTER() = {
    .version     = "1.0.0",
    .description = "GM IPSec (SM4-GCM + HMAC-SM3) Plugin",
};
