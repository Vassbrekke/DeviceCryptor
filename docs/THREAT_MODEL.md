# Threat Model — DeviceCryptor

**Draft.** Design intent for the Linux file-container path. Not an audited or signed-off model. Pre-1.0 system encryption, Windows drivers, and EFI PBA are out of scope until those paths exist.

## Assets

- Volume master keys (XTS key pair)
- User passwords, PIM, keyfile contents
- Plaintext data at rest inside unlocked volumes
- Header integrity (detect tampering of salt/encrypted header)

## Adversaries

| Adversary | Capability | Goal |
|-----------|------------|------|
| Offline disk thief | Full ciphertext + headers | Recover plaintext without password |
| Malware on live OS | Process memory, root | Steal keys from RAM / mount helper |
| Quantum-capable offline | Grover on AES; Shor on public-key | Break wrapped keys / weaken AES |
| Coercive inspection | See “empty” free space | Detect hidden volume |

## Intended properties (not proven)

- Without password/keyfiles, DC01 ciphertext should look like random data. Hidden-volume deniability is **not** claimed on SSDs (TRIM/wear-leveling).
- Bulk encryption is AES-256-XTS (classical; Grover reduces the effective search space, it does not make XTS post-quantum).
- Password stretching uses Argon2id (DC01 default) with VeraCrypt-compatible PIM mapping for legacy volumes.
- Optional **key export** wrapping uses ML-KEM-768; volumes themselves are not hybrid-PQ.
- No network I/O in crypto paths; no telemetry by default.

## Non-guarantees

- Cold-boot / DMA / evil-maid against an unlocked system
- SSD TRIM / wear-leveling vs plausible deniability (documented like VeraCrypt)
- Compromised OS kernel while volume is mounted
- Pre-1.0 system encryption without external audit

## Trust boundaries

```
[GUI unprivileged] --IPC--> [mount helper / driver privileged] --> [block device]
                                      |
                                 [dc-crypto keys in locked memory]
```
