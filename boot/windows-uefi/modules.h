#pragma once

#include <stdint.h>

#define DC_PBA_MAGIC 0x44504342u
#define DC_INT_BLOCK_IO_SIGN 0x44434942u

typedef struct DcPbaConfig {
    uint32_t magic;
    uint16_t version;
    uint16_t reserved;
    uint64_t header_lba;
} DcPbaConfig;

typedef struct DcHook {
    uint32_t sign;
    int installed;
    void *crypt_info;
} DcHook;

typedef struct DcBootLock {
    int locked;
} DcBootLock;

int dc_pba_config_ok(const DcPbaConfig *cfg);
int dc_boot_start(const DcPbaConfig *cfg);
int dc_hook_install(DcHook *hook);
int dc_hook_remove(DcHook *hook);
int dc_int_start(DcHook *hook, const DcPbaConfig *cfg);
int dc_re_header_ok(const uint8_t *header, uint32_t len);
int dc_cfg_load(const uint8_t *bytes, uint32_t len, DcPbaConfig *out);
int dc_bml_lock(DcBootLock *lock);
uint16_t dc_info_version(void);
