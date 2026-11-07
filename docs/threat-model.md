# Threat model

Initial version, derived from the project plan. It will be revised as code lands.

## Assets

- Correctness of results (a false negative treated as success is the worst outcome).
- Privacy of the host: only ecosystem, package name and version may leave it.
- Integrity of the released binaries and of the offline database.

## Threats and mitigations

- Malicious advisory data (ANSI/OSC sequences, oversized payloads, pathological JSON): sanitize terminal output, cap response sizes, limit parser depth.
- Malicious target binary (malformed ELF, code execution through `--version`): static, fuzzed parsing; no execution by default; opt-in probe inside a sandbox.
- Symlink and race conditions between resolution and read: open with no-follow semantics where available and `fstat` on the opened descriptor.
- MITM or poisoned mirror: rustls, TLS 1.2 or newer, explicit CA support, signed offline database.
- Offline database rollback: persisted monotonic timestamp, explicit rejection.
- Privacy leaks: per-source allowlist of sent fields, enforced by a test that inspects every request.
- Project supply chain: cargo-vet, cargo-deny, cargo-audit, actions pinned by SHA, hardened runners, attested and reproducible releases.
- Credentials: masked in debug output; secret files must be mode 0600.

## Out of scope

Compromise of the host itself, malicious root users, and attacks on upstream advisory publishers beyond integrity checks the sources offer.
