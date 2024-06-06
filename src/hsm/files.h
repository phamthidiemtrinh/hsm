#ifndef _FILES_H_
#define _FILES_H_

#include "file.h"

#define FILE_DEVOPS       0x100E
#define FILE_MKEK         0x100A
#define FILE_MKEK_SO      0x100B
#define FILE_XKEK         0x1080
#define FILE_DKEK         0x1090
#define FILE_KEY_DOMAIN   0x10A0
#define FILE_PUBKEYAUT       0x10C0
#define FILE_PUBKEY          0x10D0
#define FILE_MASTER_SEED  0x1110
#define FILE_PRKDFS       0x6040
#define FILE_PUBKEYDFS       0x6041
#define FILE_CDFS         0x6042
#define FILE_AODFS        0x6043
#define FILE_DODFS        0x6044
#define FILE_SKDFS        0x6045

#define FILE_KEY_DEV      0xCC00
#define FILE_PRKD_DEV     0xC400
#define FILE_EE_DEV       0xCE00

#define FILE_TERMCA       0x2F02
#define FILE_TOKENINFO    0x2F03
#define FILE_STATICTOKEN  0xCB00

extern file_t *file_pin1;
extern file_t *file_retries_pin1;
extern file_t *file_sopin;
extern file_t *file_retries_sopin;

#endif
