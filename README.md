# susanbdev/.github

Organization-wide governance authority, security policy, OIDC workflow starter templates, and public profile for [`susanbdev`](https://github.com/susanbdev).

## Repository Layout

- [`AGENTS.md`](./AGENTS.md) -- Ring-1 operating authority and Zero-Trust supply-chain invariants for `susanbdev/.github`.
- [`SECURITY.md`](./SECURITY.md) -- Organization-wide security architecture, Ring-0/Ring-1/Stone custody boundaries, annotated `v*` release-tag FIDO2 `SSHSIG` (`UP+UV`) policy, and coordinated vulnerability disclosure.
- [`profile/README.md`](./profile/README.md) -- Public GitHub organization profile rendered on [`github.com/susanbdev`](https://github.com/susanbdev).
- [`workflow-templates/`](./workflow-templates) -- SHA-pinned, zero-static-secret GitHub Actions CI and ephemeral OIDC (`TTL <= 900s`) starter templates.
- [`scripts/check`](./scripts/check) & [`scripts/verify-release-tag-sshsig.sh`](./scripts/verify-release-tag-sshsig.sh) -- Deterministic 7-bit ASCII, workflow supply-chain, and annotated `v*` release-tag FIDO2 `sk-ssh-ed25519@openssh.com` verification suite (`make check`).
- [`LICENSE`](./LICENSE) -- `susanbdev` Personal & Non-Commercial Source License v1.0.

## Verification

```sh
./scripts/check
```
