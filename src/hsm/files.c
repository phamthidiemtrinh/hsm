#include "files.h"

extern const uint8_t sc_hsm_aid[];
extern int parse_token_info(const file_t *f, int mode);

file_t file_entries[] = {
        { .fid = 0x3f00, .parent = 0xff, .name = NULL, .type = FILE_TYPE_DF, .data = NULL,
                    .file_struct = 0, .acl = { 0 } },
        { .fid = 0x2f00, .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0 } },
        { .fid = 0x2f01, .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0 } },
        { .fid = FILE_TERMCA, .parent = 0, .name = NULL,
                    .type = FILE_TYPE_WORKING | FILE_DATA_FLASH | FILE_PERSISTENT, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0 } },
        { .fid = 0x2f03, .parent = 5, .name = NULL,
                    .type = FILE_TYPE_WORKING | FILE_DATA_FUNC, .data = (uint8_t *) parse_token_info,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0 } },
        { .fid = 0x5015, .parent = 0, .name = NULL, .type = FILE_TYPE_DF, .data = NULL,
                    .file_struct = 0, .acl = { 0 } },
        { .fid = 0x5031, .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0 } },
        { .fid = 0x5032, .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0 } },
        { .fid = 0x5033, .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0 } },
        { .fid = 0x1081, .parent = 5, .name = NULL,
                    .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0xff } },
        { .fid = 0x1082, .parent = 5, .name = NULL,
                    .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0xff } },
        { .fid = 0x1083, .parent = 5, .name = NULL,
                    .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0xff } },
        { .fid = 0x1088, .parent = 5, .name = NULL,
                    .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0xff } },
        { .fid = 0x1089, .parent = 5, .name = NULL,
                    .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0xff } },
        { .fid = 0x108A, .parent = 5, .name = NULL,
                    .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0xff } },
        { .fid = FILE_DEVOPS, .parent = 5, .name = NULL,
                    .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0xff } },
        { .fid = FILE_PRKDFS, .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING,
                    .data = NULL, .file_struct = FILE_TRANSPARENT, .acl = { 0 } },
        { .fid = FILE_PUBKEYDFS, .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING,
                    .data = NULL, .file_struct = FILE_TRANSPARENT, .acl = { 0 } },
        { .fid = FILE_CDFS, .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING,
                    .data = NULL, .file_struct = FILE_TRANSPARENT, .acl = { 0 } },
        { .fid = FILE_AODFS, .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING,
                    .data = NULL, .file_struct = FILE_TRANSPARENT, .acl = { 0 } },
        { .fid = FILE_DODFS, .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING,
                    .data = NULL, .file_struct = FILE_TRANSPARENT, .acl = { 0 } },
        { .fid = FILE_SKDFS, .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING,
                    .data = NULL, .file_struct = FILE_TRANSPARENT, .acl = { 0 } },
        { .fid = FILE_KEY_DOMAIN, .parent = 5, .name = NULL,
                    .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0xff } },
        { .fid = FILE_META, .parent = 5, .name = NULL,
                    .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0xff } },
        { .fid = FILE_PUBKEYAUT, .parent = 5, .name = NULL,
                    .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0xff } },                                                                                                           //Public Key Authentication
        { .fid = FILE_KEY_DEV, .parent = 5, .name = NULL,
                    .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH | FILE_PERSISTENT, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0xff } },                                                                                                                              //Device Key
        { .fid = FILE_PRKD_DEV, .parent = 5, .name = NULL,
                    .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH | FILE_PERSISTENT, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0xff } },                                                                                                                               //PrKD Device
        { .fid = FILE_EE_DEV, .parent = 5, .name = NULL,
                    .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH | FILE_PERSISTENT, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0xff } },                                                                                                                             //End Entity Certificate Device
        { .fid = FILE_MKEK, .parent = 5, .name = NULL,
                    .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH | FILE_PERSISTENT, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0xff } },                                                                                                                            //MKEK
        { .fid = FILE_MKEK_SO, .parent = 5, .name = NULL,
                    .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH | FILE_PERSISTENT, .data = NULL,
                    .file_struct = FILE_TRANSPARENT, .acl = { 0xff } },                                                                                                                               //MKEK with SO-PIN
        { .fid = 0x0000, .parent = 5, .name = sc_hsm_aid, .type = FILE_TYPE_WORKING,
                    .data = NULL, .file_struct = FILE_TRANSPARENT, .acl = { 0 } },
        { .fid = 0x0000, .parent = 0xff, .name = NULL, .type = FILE_TYPE_UNKNOWN, .data = NULL,
                    .file_struct = 0, .acl = { 0 } }
};

const file_t *MF = &file_entries[0];
const file_t *file_last = &file_entries[sizeof(file_entries) / sizeof(file_t) - 1];
const file_t *file_openpgp = &file_entries[sizeof(file_entries) / sizeof(file_t) - 3];
const file_t *file_sc_hsm = &file_entries[sizeof(file_entries) / sizeof(file_t) - 2];
file_t *file_pin1 = NULL;
file_t *file_retries_pin1 = NULL;
file_t *file_sopin = NULL;
file_t *file_retries_sopin = NULL;
