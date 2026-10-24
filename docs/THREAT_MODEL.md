# Threat Model — DeviceCryptor

**Maintainer sign-off, 2026-10-24.** This matches the Linux file-container feature set that ships. It is not an external review and it is not a proof of the properties below.

System encryption, a privileged dm-crypt/ublk helper, initramfs attach, Windows mounts, and EFI PBA are not in this build and are not covered here.

## Assets

- Volume master keys (XTS key pair)
- User passwords, PIM, keyfile contents
- Plaintext data at rest inside unlocked volumes
- Header integrity (detect tampering of salt or the encrypted header)
- Header backup files (encrypted header slots; they do not hold the password or a clear master key)
- Optional ML-KEM-768 wrapped key export

## What this build does

- FAT checkout and checkin, unprivileged. Live FAT (`--live`) writes through only while that process stays open.
- Keyfiles are mixed into the KDF input. `dc keyfile` writes them mode `0600`.
- Hidden volumes and protect-hidden on checkout writes. Deniability on SSDs is not claimed.
- Password change re-seals the header. It does not re-encrypt the data area.
- While mounted, the master key sits in the user kernel keyring when `keyctl` can round-trip it, otherwise in `~/.local/state/devicecryptor/<id>.session` (mode `0600`). Dismount wipes that store. See [SECURITY.md](SECURITY.md).

## Adversaries

| Adversary | Capability | Goal |
|-----------|------------|------|
| Offline disk thief | Full ciphertext + headers | Recover plaintext without password |
| Malware on the live OS | The user account, process memory, the user keyring, the session file | Steal keys while a volume is mounted |
| Quantum-capable offline | Grover on AES; Shor on public-key | Break a wrapped export key or weaken AES |
| Coercive inspection | See “empty” free space | Detect a hidden volume |

## Intended properties (not proven)

- Without password and keyfiles, DC01 ciphertext should look like random data.
- Bulk encryption is AES-256-XTS. Grover reduces the search space. It does not make XTS post-quantum.
- Password stretching uses Argon2id for DC01, and the VeraCrypt PIM mapping for legacy volumes.
- Optional key export wrapping uses ML-KEM-768. The volume itself is not hybrid post-quantum encryption.
- The DC01 header MAC fails closed on tampering.
- No network I/O in crypto paths. No telemetry.

## Non-guarantees

- Cold-boot, DMA, or evil-maid against an unlocked machine
- SSD TRIM and wear-leveling versus hidden-volume deniability
- A compromised kernel, or any process that can read the user keyring or the session file, while a volume is mounted
- Side-channel resistance. An internal note is in [ASSURANCE.md](ASSURANCE.md). A lab review is still open.
- System encryption

## Trust boundary

```
[unprivileged dc or devicecryptor process]
        |
        +-- password, keyfiles, header MAC, sector crypto
        +-- FAT checkout directory, or live FUSE while the process stays open
        +-- session master key: user kernel keyring, or mode-0600 session file
```

There is no privileged mount helper and no IPC boundary in this build. The GUI and the CLI are the same user. A raw device attach (`dc attach`) validates the request shape and then refuses.
