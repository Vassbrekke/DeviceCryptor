/*
 * Host-side contracts for the EFI modules. This is not an EDK2 image and it
 * does not touch a disk. Firmware chain-load stays out of this file.
 */
#include "modules.h"

#include <string.h>

int dc_pba_config_ok(const DcPbaConfig *cfg) {
    if (cfg == 0) {
        return 0;
    }
    if (cfg->magic != DC_PBA_MAGIC || cfg->version != 1) {
        return 0;
    }
    return cfg->header_lba != 0;
}

int dc_boot_start(const DcPbaConfig *cfg) {
    return dc_pba_config_ok(cfg) ? 0 : -1;
}

int dc_hook_install(DcHook *hook) {
    if (hook == 0 || hook->sign != DC_INT_BLOCK_IO_SIGN || hook->installed) {
        return -1;
    }
    hook->installed = 1;
    return 0;
}

int dc_hook_remove(DcHook *hook) {
    if (hook == 0 || hook->sign != DC_INT_BLOCK_IO_SIGN || !hook->installed) {
        return -1;
    }
    hook->installed = 0;
    hook->crypt_info = 0;
    return 0;
}

int dc_int_start(DcHook *hook, const DcPbaConfig *cfg) {
    if (!dc_pba_config_ok(cfg)) {
        return -1;
    }
    return dc_hook_install(hook);
}

int dc_re_header_ok(const uint8_t *header, uint32_t len) {
    if (header == 0 || len < 512) {
        return 0;
    }
    return 1;
}

int dc_cfg_load(const uint8_t *bytes, uint32_t len, DcPbaConfig *out) {
    if (bytes == 0 || out == 0 || len < sizeof(DcPbaConfig)) {
        return -1;
    }
    memcpy(out, bytes, sizeof(DcPbaConfig));
    if (!dc_pba_config_ok(out)) {
        memset(out, 0, sizeof(*out));
        return -1;
    }
    return 0;
}

int dc_bml_lock(DcBootLock *lock) {
    if (lock == 0 || lock->locked) {
        return -1;
    }
    lock->locked = 1;
    return 0;
}

uint16_t dc_info_version(void) {
    return 1;
}
