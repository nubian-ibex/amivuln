# Offline database signing keys

`amivuln.pub` is the project minisign public key. The nightly
`.github/workflows/offline-db.yml` signs `offline-db.tar.zst` with the
matching secret key, and every consumer should verify the signature before
the archive is trusted:

```bash
gh release download offline-db -o ./offline-db/ \
  --pattern offline-db.tar.zst --pattern offline-db.tar.zst.minisig
tar --zstd -xf offline-db.tar.zst manifest.json
amivuln db verify offline-db.tar.zst \
  --key contrib/offline-db/amivuln.pub --sig offline-db.minisig
```

The private key lives only in the repository secret `MINISIGN_SECRET_KEY`
with password in `MINISIGN_PASSWORD` — never on a developer's machine and
never committed. ADR-0010 and ADR-0013 explain the format and the merging
rules.
