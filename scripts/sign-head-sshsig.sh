#!/bin/sh
set -eu

# Compatibility entrypoint delegating to annotated v* release-tag SSHSIG verifier.
# Human hardware sk-ssh-ed25519@openssh.com signatures are required exclusively on refs/tags/v*.
SCRIPT_DIR=$(dirname "$0")
exec "${SCRIPT_DIR}/verify-release-tag-sshsig.sh" "$@"
