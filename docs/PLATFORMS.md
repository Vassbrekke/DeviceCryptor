# Supported platforms

This is what the code builds, not a certification of every distribution.

| Platform | Create a container | Mount | System / device encryption |
|----------|--------------------|-------|----------------------------|
| Linux | Yes | FAT checkout (default). Live FAT FUSE with `--live` when `/dev/fuse` is usable. ext4 via loop only as root. | `sudo dc attach` is in the tree and was not run on a disk |
| macOS | Not a tested build | No mount backend | No |
| Windows | Not a tested build | No mount backend | No |

Checked on this machine: Linux, aarch64, FAT checkout and opt-in live FUSE. ext4 loop was not run as root. `dc attach` was not pointed at a disk. The disks on this machine are LUKS.

`dc platforms` prints the same facts for the binary you are running.
