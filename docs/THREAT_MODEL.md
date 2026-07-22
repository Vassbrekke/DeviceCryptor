# Threat Model — DeviceCryptor

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

## Guarantees (design intent)

- Without password/keyfiles, ciphertext is indistinguishable from random (DC01 and VeraCrypt-compatible volumes).
- AES-256-XTS remains primary bulk cipher (≈128-bit post-Grover).
- Password stretching uses Argon2id (DC01 default) with VeraCrypt-compatible PIM mapping for legacy volumes.
- Key export uses ML-KEM-768; no RSA/ECC.
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
