# Security Policy (`susanbdev`)

`susanbdev` engineers hardware-rooted Zero-Trust infrastructure, kernel-confined AI agent runtimes, cryptographic provenance ledgers, and zero-runtime-overhead interfaces from first principles. This document defines the organization-wide security architecture, custody boundaries, hardware signing requirements, OIDC supply-chain controls, and coordinated vulnerability disclosure process across [`github.com/susanbdev`](https://github.com/susanbdev).

---

## 1. Security Architecture & Core Invariants

1. **Memory Safety & Pure 7-Bit ASCII Hygiene**:
   - Rust workspaces enforce `#![forbid(unsafe_code)]` with deterministic offline `./scripts/check` verification gates.
   - Tracked source, policy, workflow, and documentation files enforce strict 7-bit printable ASCII (`< 0x80`), eliminating Bidi Trojan-Source overrides, Unicode Tag smuggling (`U+E0000..U+E007F`), Variation Selectors, zero-width characters, and homoglyph spoofing.
2. **Untrusted Data Spotlighting & Confined Execution**:
   - Every external payload, repository file, PR diff, webhook body, commit message, and tool output is treated as untrusted passive data bounded by randomized `<<<UNTRUSTED_ASCII_DATA_<nonce>>>>` quarantine markers.
   - Agent and build workloads run inside Linux Landlock LSM, `seccomp-bpf` (`SCMP_ACT_ERRNO` default-deny), macOS Seatbelt, or mountless microVMs under non-root UID/GID `65532:65532` with read-only root filesystems.
3. **Cryptographic Provenance & WORM Storage**:
   - State transitions, audit receipts, webhook deliveries, and Git snapshot backups are recorded in Ed25519-signed SHA-256 hash chains and Merkle transparency trees backed by cross-jurisdiction WORM object-locked storage.

---

## 2. Custody Rings & Trust Boundaries

| Plane / Ring | Repositories | Custody & Promotion Boundary |
| :--- | :--- | :--- |
| **Ring 0 (Constitutional Authority)** | `policy-hub` | Compiles signed OpenTofu rulesets, OPA/Rego gates, and Cedar policy ceilings (`Org ID: 355701240`). Strictly human-only merge custody via manual Human Owner PR merge + `100%` green status checks, with **zero** autonomous bot or agent promotion grants (and zero hardware-key signature requirement on commits or PRs). |
| **Ring 1 (Zero-Trust Cloud & Governance Plane)** | `.github`, `shared`, `infra`, `environments`, `webhooks`, `api`, `mcp`, `control-center`, `automation`, `jobs` | Capability-separated edge Workers, HKDF-sealed Vault Durable Objects, RFC 9449 DPoP + WebAuthn Passkey (`UP+UV`) consent, and `main + 1` shadow-branch promotion. Requires `100%` green checks, clean secret/Unicode scans, an independent pinned Human Owner `APPROVED` PR review (`reviewer != author`), and automated Vault Ed25519 commit and immutable `prov/seq-*` provenance signing. |
| **Stone Plane & UI System** | `dotagent`, `sims`, `s`, `Trustless`, `agora`, `envctl`, `toolbox`, `vespoli-ui` | Standalone, zero-coupled host confinement kernels, mountless microVM quarantine, Userland-SIP `/s` binary mounts, single-use credential brokers, digest-pinned `dhi.io` OCI supervisors, and strict-CSP (`style-src 'self'`) native HTML primitives. |

---

## 3. Release-Tag Hardware FIDO2 Signing Policy (`sk-ssh-ed25519@openssh.com`)

1. **Exclusive Annotated `v*` Release-Tag Scope**:
   - Across Git repositories, human hardware FIDO2 OpenSSH `SSHSIG` v1 signing (`sk-ssh-ed25519@openssh.com`, `namespace = "git"`) is required **exclusively** on annotated `v*` Git release tags (`refs/tags/v*`).
   - Git commits (`HEAD`), pull requests, Ring-0 manual owner PR merges, Ring-1 automated Vault Ed25519 promotions/provenance tags (`prov/seq-*`), and CI workflows require **zero** human hardware-key (`sk-ssh-*`) commit signatures. Lightweight `v*` tags pointing directly to commit objects are unconditionally rejected.
2. **User Presence (`UP`) + User Verification (`UV`)**:
   - Release-tag verifiers inspect the annotated Git tag object and raw `SSHSIG` authenticator flags byte, enforcing the enrolled Human Owner `sk-ssh-ed25519@openssh.com` public key plus physical touch (`flags & 0x01 != 0`) and on-authenticator PIN/biometric verification (`flags & 0x04 != 0`).
   - Unsigned or lightweight `v*` tags, software `ssh-ed25519`/RSA/PGP keys, unverified hardware touches lacking `UV`, and synthetic test keys are unconditionally rejected.

---

## 4. Zero-Static-Secret & Ephemeral OIDC CI Architecture

1. **Zero Ambient Plaintext Secrets**:
   - Credentials, API keys, signing keys, and session tokens are never stored in GitHub Actions `secrets.*`, `.env*` files, `argv`, process environment exports, browser storage (`localStorage`, `sessionStorage`, `IndexedDB`, cookies), or logs.
2. **Hardened GitHub Actions Supply Chain**:
   - Every `uses:` action in `.github/workflows/` and `workflow-templates/` is pinned to an immutable 40-character lowercase hex commit SHA with `persist-credentials: false` and hardened `$HOME/.gitconfig` (`core.hooksPath = /dev/null`, `core.attributesFile = /dev/null`, `core.fsmonitor = false`).
   - Workflows default to `permissions: contents: read` and prohibit chained cross-workflow triggers (`workflow_run`, `workflow_call`, `repository_dispatch`).
   - Deployment templates exchange short-lived GitHub OIDC tokens (`id-token: write`) for capability-scoped ephemeral leases (`TTL <= 900s`) delivered over stdin/memory only, paired with an unconditional (`if: always()`) post-step lease revocation.

---

## 5. Supported Versions & Scope

| Target | Supported |
| :--- | :--- |
| Latest `main` branch tip, current `prov/seq-*` tags & signed `v*` release tags | Yes |
| Historical commits or unmerged feature branches | No |

**Out of Scope**: Social engineering, physical attacks against operator hardware, volumetric denial-of-service against third-party CDNs/GitHub, and domains outside `susanbdev` (`susanb.dev` / `github.com/susanbdev`).

---

## 6. Coordinated Vulnerability Reporting

**Do NOT open public GitHub issues, pull requests, or discussions for undisclosed security vulnerabilities.**

1. **Reporting Channel**:
   - Submit reports privately via **GitHub Private Vulnerability Reporting** (`Security -> Advisories -> Report a vulnerability`) on the affected `susanbdev` repository, or on [`susanbdev/.github`](https://github.com/susanbdev/.github/security/advisories/new) for organization-wide findings.
2. **Required Report Contents**:
   - Affected repository name, file path(s), and exact 40-hex commit SHA.
   - Minimal, deterministic pure-ASCII reproduction steps or proof-of-concept test case.
   - Clear description of the security boundary crossed and concrete impact.
   - **Never** execute destructive probes against live endpoints, bypass CAPTCHA/access gates, or retain/transmit real credential material.
3. **Response SLAs & Safe Harbor**:
   - **Acknowledgment**: Within `48 hours` of receipt.
   - **Triage & Remediation Plan**: Within `7 calendar days`.
   - **Disclosure**: Coordinated disclosure following verified patch promotion. Good-faith research conducted strictly within this policy is authorized and will not face legal action from `susanbdev`.
