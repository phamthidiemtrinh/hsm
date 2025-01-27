#ifndef _DKEK_H_
#define _DKEK_H_

#include "crypto_utils.h"
#ifdef ENABLE_EMULATION
#include <stdbool.h>
#endif

extern int load_mkek(uint8_t *);
extern int store_mkek(const uint8_t *);
extern int save_dkek_key(uint8_t, const uint8_t *key);
extern int store_dkek_key(uint8_t, uint8_t *);
extern void init_mkek();
extern void release_mkek(uint8_t *);
extern int import_dkek_share(uint8_t, const uint8_t *share);
extern int dkek_kcv(uint8_t, uint8_t *kcv);
extern int mkek_encrypt(uint8_t *data, size_t len);
extern int mkek_decrypt(uint8_t *data, size_t len);
extern int dkek_encode_key(uint8_t,
                           void *key_ctx,
                           int key_type,
                           uint8_t *out,
                           size_t *out_len,
                           const uint8_t *,
                           size_t);
extern int dkek_type_key(const uint8_t *in);
extern int dkek_decode_key(uint8_t,
                           void *key_ctx,
                           const uint8_t *in,
                           size_t in_len,
                           int *key_size_out,
                           uint8_t **,
                           size_t *);

#define MAX_DKEK_ENCODE_KEY_BUFFER (8 + 1 + 12 + 6 + (8 + 2 * 4 + 2 * 4096 / 8 + 3 + 13) + 16)

#define MAX_KEY_DOMAINS 16

#define MKEK_IV_SIZE     (IV_SIZE)
#define MKEK_KEY_SIZE    (32)
#define MKEK_KEY_CS_SIZE (4)
#define MKEK_SIZE        (MKEK_IV_SIZE + MKEK_KEY_SIZE + MKEK_KEY_CS_SIZE)
#define MKEK_IV(p)       (p)
#define MKEK_KEY(p)      (MKEK_IV(p) + MKEK_IV_SIZE)
#define MKEK_CHECKSUM(p) (MKEK_KEY(p) + MKEK_KEY_SIZE)
#define DKEK_KEY_SIZE    (32)

extern uint8_t mkek_mask[MKEK_KEY_SIZE];
extern bool has_mkek_mask;

typedef struct mse {
    uint8_t Qpt[65];
    uint8_t key_enc[12 + 32];
    bool init;
} mse_t;
extern mse_t mse;

extern int mse_decrypt_ct(uint8_t *, size_t);

extern uint8_t pending_save_dkek;

#endif
