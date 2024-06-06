#include "crypto_utils.h"
#include "hsm.h"
#include "asn1.h"
#include "kek.h"
#include "files.h"

extern uint8_t get_key_domain(file_t *fkey);

int hsm_key_wrap() {
    int key_id = P1(apdu), r = 0;
    if (P2(apdu) != 0x92) {
        return SW_WRONG_P1P2();
    }
    if (!isUserAuthenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    file_t *ef = search_dynamic_file((KEY_PREFIX << 8) | key_id);
    if (!ef) {
        return SW_FILE_NOT_FOUND();
    }
    uint8_t kdom = get_key_domain(ef);
    if (kdom == 0xff) {
        return SW_REFERENCE_NOT_FOUND();
    }
    file_t *tf_kd = search_by_fid(FILE_KEY_DOMAIN, NULL, SPECIFY_EF);
    uint8_t *kdata = file_get_data(tf_kd), dkeks = kdata ? kdata[2 * kdom] : 0,
            current_dkeks = kdata ? kdata[2 * kdom + 1] : 0;
    if (dkeks != current_dkeks || dkeks == 0 || dkeks == 0xff) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (key_has_purpose(ef, ALGO_WRAP) == false) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    file_t *prkd = search_dynamic_file((PRKD_PREFIX << 8) | key_id);
    if (!prkd) {
        return SW_FILE_NOT_FOUND();
    }
    const uint8_t *dprkd = file_get_data(prkd);
    size_t wrap_len = MAX_DKEK_ENCODE_KEY_BUFFER;
    size_t tag_len = 0;
    const uint8_t *meta_tag = get_meta_tag(ef, 0x91, &tag_len);
    if (*dprkd == P15_KEYTYPE_RSA) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        r = load_private_key_rsa(&ctx, ef);
        if (r != CCID_OK) {
            mbedtls_rsa_free(&ctx);
            if (r == CCID_VERIFICATION_FAILED) {
                return SW_SECURE_MESSAGE_EXEC_ERROR();
            }
            return SW_EXEC_ERROR();
        }
        r = dkek_encode_key(kdom, &ctx, PICO_KEYS_KEY_RSA, res_APDU, &wrap_len, meta_tag, tag_len);
        mbedtls_rsa_free(&ctx);
    }
    else if (*dprkd == P15_KEYTYPE_ECC) {
        mbedtls_ecdsa_context ctx;
        mbedtls_ecdsa_init(&ctx);
        r = load_private_key_ecdsa(&ctx, ef);
        if (r != CCID_OK) {
            mbedtls_ecdsa_free(&ctx);
            if (r == CCID_VERIFICATION_FAILED) {
                return SW_SECURE_MESSAGE_EXEC_ERROR();
            }
            return SW_EXEC_ERROR();
        }
        r = dkek_encode_key(kdom, &ctx, PICO_KEYS_KEY_EC, res_APDU, &wrap_len, meta_tag, tag_len);
        mbedtls_ecdsa_free(&ctx);
    }
    else if (*dprkd == P15_KEYTYPE_AES) {
        uint8_t kdata[64]; //maximum AES key size
        if (wait_button_pressed() == true) { //timeout
            return SW_SECURE_MESSAGE_EXEC_ERROR();
        }

        int key_size = file_get_size(ef), aes_type = PICO_KEYS_KEY_AES;
        memcpy(kdata, file_get_data(ef), key_size);
        if (mkek_decrypt(kdata, key_size) != 0) {
            return SW_EXEC_ERROR();
        }
        if (key_size == 64) {
            aes_type = PICO_KEYS_KEY_AES_512;
        }
        else if (key_size == 32) {
            aes_type = PICO_KEYS_KEY_AES_256;
        }
        else if (key_size == 24) {
            aes_type = PICO_KEYS_KEY_AES_192;
        }
        else if (key_size == 16) {
            aes_type = PICO_KEYS_KEY_AES_128;
        }
        r = dkek_encode_key(kdom, kdata, aes_type, res_APDU, &wrap_len, meta_tag, tag_len);
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
    }
    if (r != CCID_OK) {
        return SW_EXEC_ERROR();
    }
    res_APDU_size = wrap_len;
    return SW_OK();
}
