#include "crypto_utils.h"
#include "hsm.h"
#include "random.h"

int hsm_key_gen() {
    uint8_t key_id = P1(apdu);
    uint8_t p2 = P2(apdu);
    uint8_t key_size = 32;
    int r;
    if (!isUserAuthenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (p2 == 0xB3) {
        key_size = 64;
    }
    else if (p2 == 0xB2) {
        key_size = 32;
    }
    else if (p2 == 0xB1) {
        key_size = 24;
    }
    else if (p2 == 0xB0) {
        key_size = 16;
    }
    //at this moment, we do not use the template, as only CBC is supported by the driver (encrypt, decrypt and CMAC)
    uint8_t aes_key[64]; //maximum AES key size
    memcpy(aes_key, random_bytes_get(key_size), key_size);
    int aes_type = 0x0;
    if (key_size == 16) {
        aes_type = PICO_KEYS_KEY_AES_128;
    }
    else if (key_size == 24) {
        aes_type = PICO_KEYS_KEY_AES_192;
    }
    else if (key_size == 32) {
        aes_type = PICO_KEYS_KEY_AES_256;
    }
    else if (key_size == 64) {
        aes_type = PICO_KEYS_KEY_AES_512;
    }
    r = store_keys(aes_key, aes_type, key_id);
    if (r != CCID_OK) {
        return SW_MEMORY_FAILURE();
    }
    if (find_and_store_meta_key(key_id) != CCID_OK) {
        return SW_EXEC_ERROR();
    }
    low_flash_available();
    return SW_OK();
}
