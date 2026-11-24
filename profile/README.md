# susanbdev

**Hardware-rooted Zero-Trust systems, kernel-enforced AI agent confinement, and zero-runtime-overhead interfaces.**

`susanbdev` builds security-critical developer infrastructure from first principles: pure `#![forbid(unsafe_code)]` Rust, hardware FIDO2 (`sk-ssh-ed25519@openssh.com`) custody, zero ambient plaintext secrets, cryptographic provenance ledgers, and deterministic offline verification.

---

## Public Repositories

| Repository | Focus | Highlights |
| :--- | :--- | :--- |
| [**dotagent**](https://github.com/susanbdev/dotagent) | Zero-Trust AI Agent Security Kernel | Landlock LSM + macOS Seatbelt sandboxing, 128-bit untrusted data spotlighting, prompt-injection halt gates, `< 150 us` warm hook daemon, Ed25519 `StopReceipt` attestation, and deterministic multi-harness compilation. |
| [**vespoli-ui**](https://github.com/susanbdev/vespoli-ui) | Zero-Runtime-CSS React UI System | `66` stateless `1-in -> 1-out` native HTML primitives, pure-Rust `@vespoli/styled-compiler` (`styled -> SCSS/CSS`), strict `style-src 'self'` CSP (`0` inline styles, `0` vector bloat), and `100k+` point `OffscreenCanvas` telemetry rendering. |

---

## Architectural Planes

### 1. Stone Host-Custody & Agent Execution Plane
Standalone, zero-coupled Rust systems enforcing least privilege on developer hosts and ephemeral VMs:

- **`dotagent`** -- Host and workspace security kernel mediating tool calls, filesystem traversal ceilings, and kernel sandboxes across AI coding harnesses.
- **`sims`** -- Mountless microVM sandbox engine with hardware-staked `AGTVLT01` vaults, multi-wave DAG swarm execution, `AF_VSOCK` bridges, and FIDO2 Git quarantine.
- **`s`** -- Out-of-host Userland-SIP plane mounting verified, immutable binaries over read-only `nosuid,nodev` volumes backed by an air-gapped `Noise_IK` sibling VM.
- **`Trustless`** -- Remote credential broker with FIDO2 `SSHSIG` session admission, single-use `60s` atomic grants, mTLS transparent proxying, and chunk-safe secret scrubbing.
- **`agora`** -- Uniform MCP connector engine with Ed25519 Proof-of-Possession, RFC 9449 DPoP, `AES-256-GCM` static credential sealing, Merkle provenance, and UCB1 routing.
- **`envctl`** -- Digest-pinned DHI OCI image builder, SLSA v1.0 / OpenVEX verifier, rootless `seccomp` runtime supervisor, and streaming multi-encoding secret redactor.
- **`toolbox`** -- Hardware-key operator CLI suite for host hardening, Cloudflare Zero-Trust posture audits, DNS/router management, and guarded chaos drills.

### 2. Ring-0 Governance & Zero-Trust Cloud Control Plane
Capability-separated edge, storage, and SDLC services:

- **`policy-hub`** -- Ring-0 constitutional authority compiling hardware-signed OpenTofu rulesets, OPA/Rego gates, and Cedar policy bundles.
- **`shared`** -- Polyglot contract compiler and zero-unsafe cryptographic, Merkle, WORM, and W3C `traceparent` primitives across Rust, Wasm, TypeScript, Python, and C11.
- **`infra` & `environments`** -- Declarative Cloudflare Zero-Trust perimeters, cross-jurisdiction WORM R2 object-lock pairs, digest-pinned `65532:65532` shell-less containers, and `tunnel-ca` mTLS bridges.
- **`webhooks`, `api`, `mcp`, & `control-center`** -- WORM-backed ingress, HKDF-sealed Vault Durable Objects, RFC 9449 DPoP + WebAuthn Passkey (`UP+UV`) consent, and a `< 55 KB` brotli operator console.
- **`automation` & `jobs`** -- Capability-separated `main + 1` shadow-branch promotion, immutable provenance tagging, air-gapped Git snapshot backups, and hourly Merkle parity witnesses.

---

## Engineering Non-Negotiables

1. **Zero Ambient Plaintext Secrets** -- Credentials never touch `argv`, environment variables, `.env` files, browser storage, or unredacted logs.
2. **Hardware-Rooted Custody** -- Privileged mutations, Ring-0 policy updates, and promotion grants bind to physical FIDO2 `UP+UV` hardware signatures.
3. **Memory Safety & Deterministic Gates** -- `#![forbid(unsafe_code)]` across Rust workspaces, strict 7-bit ASCII source hygiene, and single-command `./scripts/check` verification.

---

## Licensing

Repositories published under `susanbdev` are **free for personal, educational, and individual non-commercial use**. Commercial and enterprise use requires a paid commercial license -- see each repository's `LICENSE` file for terms.
