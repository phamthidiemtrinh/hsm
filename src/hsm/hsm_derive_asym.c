#include "common.h"
#include "mbedtls/ecdsa.h"
#include "crypto_utils.h"
#include "hsm.h"
#include "cvc.h"

#define MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED -0x006E
#define MOD_ADD(N)                                                    \
    while (mbedtls_mpi_cmp_mpi(&(N), &grp->P) >= 0)                  \
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_abs(&(N), &(N), &grp->P))
static inline int mbedtls_mpi_add_mod(const mbedtls_ecp_group *grp,
                                      mbedtls_mpi *X,
                                      const mbedtls_mpi *A,
                                      const mbedtls_mpi *B) {
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(X, A, B));
    MOD_ADD(*X);
cleanup:
    return ret;
}

int hsm_derive_asym() {
    uint8_t key_id = P1(apdu);
    uint8_t dest_id = P2(apdu);
    file_t *fkey;
    if (!isUserAuthenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (!(fkey = search_dynamic_file((KEY_PREFIX << 8) | key_id)) || !file_has_data(fkey)) {
        return SW_FILE_NOT_FOUND();
    }
    if (key_has_purpose(fkey, ALGO_EC_DERIVE) == false) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (apdu.nc == 0) {
        return SW_WRONG_LENGTH();
    }
    if (apdu.data[0] == ALGO_EC_DERIVE) {
        mbedtls_ecdsa_context ctx;
        mbedtls_ecdsa_init(&ctx);

        int r;
        r = load_private_key_ecdsa(&ctx, fkey);
        if (r != CCID_OK) {
            mbedtls_ecdsa_free(&ctx);
            if (r == CCID_VERIFICATION_FAILED) {
                return SW_SECURE_MESSAGE_EXEC_ERROR();
            }
            return SW_EXEC_ERROR();
        }
        mbedtls_mpi a, nd;
        mbedtls_mpi_init(&a);
        mbedtls_mpi_init(&nd);
        r = mbedtls_mpi_read_binary(&a, apdu.data + 1, apdu.nc - 1);
        if (r != 0) {
            mbedtls_ecdsa_free(&ctx);
            mbedtls_mpi_free(&a);
            mbedtls_mpi_free(&nd);
            return SW_DATA_INVALID();
        }
        r = mbedtls_mpi_add_mod(&ctx.grp, &nd, &ctx.d, &a);
        mbedtls_mpi_free(&a);
        if (r != 0) {
            mbedtls_ecdsa_free(&ctx);
            mbedtls_mpi_free(&nd);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_mpi_copy(&ctx.d, &nd);
        mbedtls_mpi_free(&nd);
        if (r != 0) {
            mbedtls_ecdsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        r = store_keys(&ctx, PICO_KEYS_KEY_EC, dest_id);
        if (r != CCID_OK) {
            mbedtls_ecdsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        mbedtls_ecdsa_free(&ctx);
    }
    else {
        return SW_WRONG_DATA();
    }
    return SW_OK();
}
