# Supported platforms

This is what the code builds, not a certification of every distribution.

| Platform | Create a container | Mount | System / device encryption |
|----------|--------------------|-------|----------------------------|
| Linux | Yes | FAT checkout (default). Live FAT FUSE with `--live` when `/dev/fuse` is usable. ext4 via loop only as root. | No |
| macOS | Not a tested build | No mount backend | No |
| Windows | Not a tested build | No mount backend | No |

Checked on this machine: Linux, aarch64, FAT checkout and opt-in live FUSE. ext4 loop was not run as root. Select Device and Auto-Mount Devices stay visible and say system encryption is not in this build.

`dc platforms` prints the same facts for the binary you are running.
