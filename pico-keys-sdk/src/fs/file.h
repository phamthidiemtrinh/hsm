/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef _FILE_H_
#define _FILE_H_

#include <stdlib.h>
#ifndef ENABLE_EMULATION
#include "pico/stdlib.h"
#else
#include <stdbool.h>
#include <stdint.h>
#endif

#define FILE_TYPE_UNKNOWN       0x00
#define FILE_TYPE_DF            0x04
#define FILE_TYPE_INTERNAL_EF   0x03
#define FILE_TYPE_WORKING    0x01
#define FILE_TYPE_BSO           0x10
#define FILE_PERSISTENT         0x20
#define FILE_DATA_FLASH         0x40
#define FILE_DATA_FUNC          0x80

/* EF structures */
#define FILE_UNKNOWN             0x00
#define FILE_TRANSPARENT         0x01
#define FILE_LINEAR_FIXED        0x02
#define FILE_LINEAR_FIXED_TLV    0x03
#define FILE_LINEAR_VARIABLE     0x04
#define FILE_LINEAR_VARIABLE_TLV 0x05
#define FILE_CYCLIC              0x06
#define FILE_CYCLIC_TLV          0x07

#define ACL_OP_DELETE_SELF      0x00
#define ACL_OP_CREATE_DF        0x01
#define ACL_OP_CREATE_EF        0x02
#define ACL_OP_DELETE_CHILD     0x03
#define ACL_OP_WRITE            0x04
#define ACL_OP_UPDATE_ERASE     0x05
#define ACL_OP_READ_SEARCH      0x06

#define SPECIFY_EF 0x1
#define SPECIFY_DF 0x2
#define SPECIFY_ANY 0x3

#define FILE_PRKDFS   0x6040
#define FILE_PUKDFS   0x6041
#define FILE_CDFS     0x6042
#define FILE_AODFS    0x6043
#define FILE_DODFS    0x6044
#define FILE_SKDFS    0x6045
#define FILE_META     0xE010

#define MAX_DEPTH 4

typedef struct file {
    const uint16_t fid;
    const uint8_t parent; //entry number in the whole table!!
    const uint8_t *name;
    const uint8_t type;
    const uint8_t file_struct;
    uint8_t *data; //should include 2 bytes len at begining
    const uint8_t acl[7];
} __attribute__((packed)) file_t;

extern bool file_has_data(file_t *);

extern file_t *currentEF;
extern file_t *currentDF;
extern const file_t *selected_applet;

extern const file_t *MF;
extern const file_t *file_last;
extern const file_t *file_openpgp;
extern const file_t *file_sc_hsm;
extern bool card_terminated;
extern file_t *file_pin1;
extern file_t *file_retries_pin1;
extern file_t *file_sopin;
extern file_t *file_retries_sopin;

extern file_t *search_by_fid(const uint16_t fid, const file_t *parent, const uint8_t sp);
extern file_t *search_by_name(uint8_t *name, uint16_t namelen);
extern file_t *search_by_path(const uint8_t *pe_path, uint8_t pathlen, const file_t *parent);
extern bool authenticate_action(const file_t *ef, uint8_t op);
extern void process_fci(const file_t *pe, int fmd);
extern void scan_flash();
extern void initialize_flash(bool);

extern file_t file_entries[];

extern uint8_t *file_read(const uint8_t *addr);
extern uint16_t file_read_uint16(const uint8_t *addr);
extern uint8_t file_read_uint8(const uint8_t *addr);
extern uint8_t *file_get_data(const file_t *tf);
extern uint16_t file_get_size(const file_t *tf);
extern file_t *file_new(uint16_t);
file_t *get_parent(file_t *f);

extern uint16_t dynamic_files;
extern file_t dynamic_file[];
extern file_t *search_dynamic_file(uint16_t);
extern int delete_dynamic_file(file_t *f);

extern bool isUserAuthenticated;

extern int meta_find(uint16_t, uint8_t **out);
extern int meta_delete(uint16_t fid);
extern int meta_add(uint16_t fid, const uint8_t *data, uint16_t len);
extern int delete_file(file_t *ef);

#endif
