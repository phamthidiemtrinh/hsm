#include "hsm.h"
#include "files.h"

int hsm_list_keys() {
    /* First we send DEV private key */
    /* Both below conditions should be always TRUE */
    if (search_by_fid(FILE_PRKD_DEV, NULL, SPECIFY_EF)) {
        res_APDU[res_APDU_size++] = FILE_PRKD_DEV >> 8;
        res_APDU[res_APDU_size++] = FILE_PRKD_DEV & 0xff;
    }
    if (search_by_fid(FILE_KEY_DEV, NULL, SPECIFY_EF)) {
        res_APDU[res_APDU_size++] = FILE_KEY_DEV >> 8;
        res_APDU[res_APDU_size++] = FILE_KEY_DEV & 0xff;
    }
    //first CC
    for (int i = 0; i < dynamic_files; i++) {
        file_t *f = &dynamic_file[i];
        if ((f->fid & 0xff00) == (KEY_PREFIX << 8)) {
            res_APDU[res_APDU_size++] = KEY_PREFIX;
            res_APDU[res_APDU_size++] = f->fid & 0xff;
        }
    }
    for (int i = 0; i < dynamic_files; i++) {
        file_t *f = &dynamic_file[i];
        if ((f->fid & 0xff00) == (PRKD_PREFIX << 8)) {
            res_APDU[res_APDU_size++] = PRKD_PREFIX;
            res_APDU[res_APDU_size++] = f->fid & 0xff;
        }
    }
    //second CD
    for (int i = 0; i < dynamic_files; i++) {
        file_t *f = &dynamic_file[i];
        if ((f->fid & 0xff00) == (CD_PREFIX << 8)) {
            res_APDU[res_APDU_size++] = CD_PREFIX;
            res_APDU[res_APDU_size++] = f->fid & 0xff;
        }
    }

    for (int i = 0; i < dynamic_files; i++) {
        file_t *f = &dynamic_file[i];
        if ((f->fid & 0xff00) == (DCOD_PREFIX << 8)) {
            res_APDU[res_APDU_size++] = DCOD_PREFIX;
            res_APDU[res_APDU_size++] = f->fid & 0xff;
        }
    }
    return SW_OK();
}
