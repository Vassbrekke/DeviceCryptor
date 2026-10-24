#include "modules.h"

#include <stdio.h>
#include <string.h>

static int fail(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    return 1;
}

int main(void) {
    DcPbaConfig cfg;
    DcHook hook;
    DcBootLock lock;
    uint8_t raw[sizeof(DcPbaConfig)];
    uint8_t header[512];

    memset(&cfg, 0, sizeof(cfg));
    if (dc_boot_start(&cfg) == 0) {
        return fail("empty config must fail");
    }
    cfg.magic = DC_PBA_MAGIC;
    cfg.version = 1;
    cfg.header_lba = 1;
    if (dc_boot_start(&cfg) != 0) {
        return fail("boot start");
    }

    memset(&hook, 0, sizeof(hook));
    hook.sign = DC_INT_BLOCK_IO_SIGN;
    if (dc_int_start(&hook, &cfg) != 0 || !hook.installed) {
        return fail("int start");
    }
    if (dc_hook_install(&hook) == 0) {
        return fail("second install");
    }
    if (dc_hook_remove(&hook) != 0 || hook.installed) {
        return fail("remove");
    }

    memset(header, 0, sizeof(header));
    if (dc_re_header_ok(header, 511)) {
        return fail("short header");
    }
    if (!dc_re_header_ok(header, 512)) {
        return fail("header length");
    }

    memcpy(raw, &cfg, sizeof(cfg));
    memset(&cfg, 0, sizeof(cfg));
    if (dc_cfg_load(raw, sizeof(raw), &cfg) != 0 || cfg.header_lba != 1) {
        return fail("cfg load");
    }

    memset(&lock, 0, sizeof(lock));
    if (dc_bml_lock(&lock) != 0 || !lock.locked) {
        return fail("bml");
    }
    if (dc_bml_lock(&lock) == 0) {
        return fail("bml twice");
    }
    if (dc_info_version() != 1) {
        return fail("info");
    }
    return 0;
}
