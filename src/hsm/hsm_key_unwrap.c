#include "common.h"
#include "crypto_utils.h"
#include "hsm.h"
#include "kek.h"
#include "cvc.h"

int hsm_key_unwrap() {
    int key_id = P1(apdu), r = 0;
    if (P2(apdu) != 0x93) {
        return SW_WRONG_P1P2();
    }
    if (!isUserAuthenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    int key_type = dkek_type_key(apdu.data);
    uint8_t kdom = -1, *allowed = NULL, prkd_buf[128];
    size_t allowed_len = 0, prkd_len = 0;
    if (key_type == 0x0) {
        return SW_DATA_INVALID();
    }
    if (key_type & PICO_KEYS_KEY_RSA) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        do {
            r = dkek_decode_key(++kdom, &ctx, apdu.data, apdu.nc, NULL, &allowed, &allowed_len);
        } while ((r == CCID_ERR_FILE_NOT_FOUND || r == CCID_WRONG_DKEK) && kdom < MAX_KEY_DOMAINS);
        if (r != CCID_OK) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        r = store_keys(&ctx, PICO_KEYS_KEY_RSA, key_id);
        if ((res_APDU_size = asn1_cvc_aut(&ctx, PICO_KEYS_KEY_RSA, res_APDU, 4096, NULL, 0)) == 0) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        int key_size = ctx.len;
        mbedtls_rsa_free(&ctx);
        if (r != CCID_OK) {
            return SW_EXEC_ERROR();
        }
        prkd_len = asn1_build_prkd_ecc(NULL, 0, NULL, 0, key_size * 8, prkd_buf, sizeof(prkd_buf));
    }
    else if (key_type & PICO_KEYS_KEY_EC) {
        mbedtls_ecdsa_context ctx;
        mbedtls_ecdsa_init(&ctx);
        do {
            r = dkek_decode_key(++kdom, &ctx, apdu.data, apdu.nc, NULL, &allowed, &allowed_len);
        } while ((r == CCID_ERR_FILE_NOT_FOUND || r == CCID_WRONG_DKEK) && kdom < MAX_KEY_DOMAINS);
        if (r != CCID_OK) {
            mbedtls_ecdsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        r = store_keys(&ctx, PICO_KEYS_KEY_EC, key_id);
        if ((res_APDU_size = asn1_cvc_aut(&ctx, PICO_KEYS_KEY_EC, res_APDU, 4096, NULL, 0)) == 0) {
            mbedtls_ecdsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        int key_size = ctx.grp.nbits;
        mbedtls_ecdsa_free(&ctx);
        if (r != CCID_OK) {
            return SW_EXEC_ERROR();
        }
        prkd_len = asn1_build_prkd_ecc(NULL, 0, NULL, 0, key_size, prkd_buf, sizeof(prkd_buf));
    }
    else if (key_type & PICO_KEYS_KEY_AES) {
        uint8_t aes_key[64];
        int key_size = 0, aes_type = 0;
        do {
            r = dkek_decode_key(++kdom,
                                aes_key,
                                apdu.data,
                                apdu.nc,
                                &key_size,
                                &allowed,
                                &allowed_len);
        } while ((r == CCID_ERR_FILE_NOT_FOUND || r == CCID_WRONG_DKEK) && kdom < MAX_KEY_DOMAINS);
        if (r != CCID_OK) {
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
        else {
            return SW_EXEC_ERROR();
        }
        r = store_keys(aes_key, aes_type, key_id);
        if (r != CCID_OK) {
            return SW_EXEC_ERROR();
        }
        prkd_len = asn1_build_prkd_aes(NULL, 0, NULL, 0, key_size * 8, prkd_buf, sizeof(prkd_buf));
    }
    if ((allowed != NULL && allowed_len > 0) || kdom >= 0) {
        size_t meta_len = (allowed_len > 0 ? 2 + allowed_len : 0) + (kdom >= 0 ? 3 : 0);
        uint8_t *meta = (uint8_t *) calloc(1, meta_len), *m = meta;
        if (allowed_len > 0) {
            *m++ = 0x91;
            *m++ = allowed_len;
            memcpy(m, allowed, allowed_len); m += allowed_len;
        }
        if (kdom >= 0) {
            *m++ = 0x92;
            *m++ = 1;
            *m++ = kdom;
        }
        r = meta_add((KEY_PREFIX << 8) | key_id, meta, meta_len);
        free(meta);
        if (r != CCID_OK) {
            return r;
        }
    }
    if (prkd_len > 0) {
        file_t *fpk = file_new((PRKD_PREFIX << 8) | key_id);
        r = flash_write_data_to_file(fpk, prkd_buf, prkd_len);
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
    }
    if (res_APDU_size > 0) {
        file_t *fpk = file_new((EE_CERTIFICATE_PREFIX << 8) | key_id);
        r = flash_write_data_to_file(fpk, res_APDU, res_APDU_size);
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
        res_APDU_size = 0;
    }
    low_flash_available();
    return SW_OK();
}
