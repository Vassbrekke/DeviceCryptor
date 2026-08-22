#!/usr/bin/env bash
# DeviceCryptor Linux end-to-end test harness (unprivileged FAT checkout path).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
DC="${DC:-$ROOT/target/debug/dc}"
# Always rebuild so the harness exercises the current tree (not a stale binary).
echo "building dc…"
cargo build -p dc-cli
DC="$ROOT/target/debug/dc"

WORKDIR="${WORKDIR:-$ROOT/testdata/linux-e2e}"
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"/{mnt,mnt2,mnt-outer,mnt-hidden,mnt-ch}

PASS='linux-e2e-pass-phrase'
HPASS='hidden-e2e-pass-phrase'
NEWPASS='linux-e2e-new-pass'
KF="$WORKDIR/keyfile.bin"
dd if=/dev/urandom of="$KF" bs=1024 count=4 status=none

echo "== create FAT32 volume with keyfile (human size) =="
"$DC" create "$WORKDIR/vol.dc" --size 16M --password "$PASS" --fs fat32 --keyfile "$KF"

echo "== info =="
"$DC" info "$WORKDIR/vol.dc" --password "$PASS" --keyfile "$KF"

echo "== mount / write / dismount =="
"$DC" mount "$WORKDIR/vol.dc" "$WORKDIR/mnt" --password "$PASS" --keyfile "$KF" --id e2e1
echo 'hello from linux e2e' > "$WORKDIR/mnt/readme.txt"
mkdir -p "$WORKDIR/mnt/docs"
echo 'nested' > "$WORKDIR/mnt/docs/a.txt"
"$DC" status | grep -q e2e1
# Dismount: id only — no password/keyfile (session from mount)
"$DC" dismount --id e2e1

echo "== remount verify persistence =="
"$DC" mount "$WORKDIR/vol.dc" "$WORKDIR/mnt2" --password "$PASS" --keyfile "$KF" --id e2e2
grep -q 'hello from linux e2e' "$WORKDIR/mnt2/readme.txt"
grep -q 'nested' "$WORKDIR/mnt2/docs/a.txt"
"$DC" dismount --id e2e2

echo "== wrong password rejected =="
if "$DC" info "$WORKDIR/vol.dc" --password 'wrong-password' --keyfile "$KF" 2>/dev/null; then
  echo "ERROR: wrong password should fail" >&2
  exit 1
fi
echo "ok (rejected)"

echo "== header backup / chpasswd / restore =="
"$DC" header backup "$WORKDIR/vol.dc" "$WORKDIR/vol.hdrbak"
"$DC" chpasswd "$WORKDIR/vol.dc" --password "$PASS" --new-password "$NEWPASS" --keyfile "$KF"
if "$DC" info "$WORKDIR/vol.dc" --password "$PASS" --keyfile "$KF" 2>/dev/null; then
  echo "ERROR: old password should fail after chpasswd" >&2
  exit 1
fi
"$DC" info "$WORKDIR/vol.dc" --password "$NEWPASS" --keyfile "$KF" >/dev/null
"$DC" mount "$WORKDIR/vol.dc" "$WORKDIR/mnt-ch" --password "$NEWPASS" --keyfile "$KF" --id e2e-ch
grep -q 'hello from linux e2e' "$WORKDIR/mnt-ch/readme.txt"
"$DC" dismount --id e2e-ch
# Restore pre-chpasswd headers
"$DC" header restore "$WORKDIR/vol.dc" "$WORKDIR/vol.hdrbak"
"$DC" info "$WORKDIR/vol.dc" --password "$PASS" --keyfile "$KF" >/dev/null
echo "ok (chpasswd + header backup/restore)"

echo "== hidden volume =="
"$DC" create "$WORKDIR/hidden.dc" --size 32M --password "$PASS" --fs fat32 \
  --hidden-size 8M --hidden-password "$HPASS"
"$DC" mount "$WORKDIR/hidden.dc" "$WORKDIR/mnt-outer" --password "$PASS" --id outer1 --fs fat32
echo 'outer-visible' > "$WORKDIR/mnt-outer/outer.txt"
"$DC" dismount --id outer1
"$DC" mount "$WORKDIR/hidden.dc" "$WORKDIR/mnt-hidden" --password "$HPASS" --id hid1 --fs fat32
echo 'secret-hidden' > "$WORKDIR/mnt-hidden/secret.txt"
"$DC" dismount --id hid1
"$DC" mount "$WORKDIR/hidden.dc" "$WORKDIR/mnt-hidden" --password "$HPASS" --id hid2 --fs fat32
grep -q 'secret-hidden' "$WORKDIR/mnt-hidden/secret.txt"
"$DC" dismount --id hid2
"$DC" mount "$WORKDIR/hidden.dc" "$WORKDIR/mnt-outer" --password "$PASS" --id outer2 --fs fat32
grep -q 'outer-visible' "$WORKDIR/mnt-outer/outer.txt"
# Outer must not show hidden file
if [[ -e "$WORKDIR/mnt-outer/secret.txt" ]]; then
  echo "ERROR: hidden file visible in outer mount" >&2
  exit 1
fi
"$DC" dismount --id outer2

echo "== unit tests =="
cargo test -p dc-crypto -p dc-format -p dc-volume -p dc-cli -- --test-threads=1

echo
echo "ALL LINUX E2E CHECKS PASSED"
echo "Artifacts: $WORKDIR"
