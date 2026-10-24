# Fuzz targets

See [docs/TESTING.md](../docs/TESTING.md) for how to run these and the crash policy.

CI runs these for 10000 executions each. They do not derive a password key.

```bash
cargo +nightly fuzz run sector_xts -- -runs=10000
cargo +nightly fuzz run header_payload -- -runs=10000
```

`header_parse` calls the real header open and pays a full KDF. Keep it local. Do not add it to CI.
