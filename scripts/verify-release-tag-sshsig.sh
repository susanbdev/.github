#!/bin/sh
set -eu

exec python3 - "$@" <<'PY'
import base64
import hashlib
import hmac
import os
import re
import struct
import subprocess
import sys

BEGIN_ARMOR = "-----BEGIN SSH SIGNATURE-----"
END_ARMOR = "-----END SSH SIGNATURE-----"
REQUIRED_KEY_TYPE = b"sk-ssh-ed25519@openssh.com"
SOFTWARE_KEY_TYPE = b"ssh-ed25519"
OWNER_SK_ED25519_PUBKEY_HEX = "5b56456ae15f81b3a84eb9d34007714b494e4cc6013d823dd79042dd13fee826"
RELEASE_TAG_RE = re.compile(r"^v[0-9A-Za-z][0-9A-Za-z._+-]*$")


def read_ssh_str(buf: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(buf):
        raise ValueError("truncated SSH wire string length")
    (length,) = struct.unpack(">I", buf[offset : offset + 4])
    end = offset + 4 + length
    if end > len(buf):
        raise ValueError("truncated SSH wire string body")
    return buf[offset + 4 : end], end


def ssh_str(raw: bytes) -> bytes:
    return struct.pack(">I", len(raw)) + raw


def normalize_release_tag(raw_ref: str) -> tuple[str, str]:
    if not raw_ref or raw_ref != raw_ref.strip():
        raise ValueError("empty or whitespace-padded release tag ref")
    tag_name = raw_ref[len("refs/tags/") :] if raw_ref.startswith("refs/tags/") else raw_ref
    if not tag_name.startswith("v"):
        raise ValueError(
            f"human hardware SSHSIG applies exclusively to annotated v* release tags (got {raw_ref!r})"
        )
    if (
        not RELEASE_TAG_RE.fullmatch(tag_name)
        or ".." in tag_name
        or "@{" in tag_name
        or tag_name.endswith((".lock", "."))
    ):
        raise ValueError(f"invalid annotated v* release tag name: {tag_name!r}")
    return tag_name, f"refs/tags/{tag_name}"


def validate_tag_object_type(obj_type: str, tag_ref: str) -> None:
    actual = obj_type.strip()
    if actual != "tag":
        raise ValueError(
            f"{tag_ref} resolves to git object type {actual!r}; lightweight v* tags and bare commits are rejected"
        )


def extract_tag_sig(raw_tag: bytes, expected_tag: str | None = None) -> tuple[bytes, str]:
    nl = raw_tag.find(b"\n\n")
    if nl < 0:
        raise ValueError("malformed git tag object: missing header boundary")
    header_lines = raw_tag[:nl].split(b"\n")
    headers: dict[bytes, bytes] = {}
    for line in header_lines:
        if b" " not in line:
            raise ValueError("malformed git tag header line")
        key, val = line.split(b" ", 1)
        if key in (b"tree", b"parent", b"author", b"committer", b"gpgsig"):
            raise ValueError("expected annotated git tag object, got commit object (lightweight v* tags are forbidden)")
        if key in headers:
            raise ValueError(f"duplicate git tag header: {key.decode('ascii', errors='replace')}")
        headers[key] = val
    for req in (b"object", b"type", b"tag", b"tagger"):
        if not headers.get(req):
            raise ValueError(f"malformed git tag object: missing {req.decode('ascii')} header")
    try:
        hdr_tag = headers[b"tag"].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("non-ASCII tag name in git tag header") from exc
    tag_name, _ = normalize_release_tag(hdr_tag)
    if expected_tag is not None and tag_name != expected_tag:
        raise ValueError(f"annotated tag header {tag_name!r} does not match expected release tag {expected_tag!r}")

    trimmed = raw_tag[:-1] if raw_tag.endswith(b"\n") else raw_tag
    end_marker = b"\n" + END_ARMOR.encode("ascii")
    if not trimmed.endswith(end_marker):
        raise ValueError(
            "annotated v* release tag lacks trailing OpenSSH SSHSIG block (run: git tag -s vX.Y.Z -m 'Release vX.Y.Z')"
        )
    begin_marker = BEGIN_ARMOR.encode("ascii") + b"\n"
    sig_start = trimmed.rfind(begin_marker)
    if sig_start < nl + 2 or trimmed[sig_start - 1 : sig_start] != b"\n":
        raise ValueError("annotated v* release tag lacks valid OpenSSH SSHSIG boundary")
    payload = trimmed[:sig_start]
    try:
        armored = trimmed[sig_start:].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("non-ASCII bytes in SSHSIG armor") from exc
    return payload, armored


def verify_sshsig(payload: bytes, armored: str, allowed_pubkey_hex: str | None = None) -> tuple[int, str]:
    lines = [ln.strip() for ln in armored.strip().splitlines() if ln.strip()]
    if len(lines) < 3 or lines[0] != BEGIN_ARMOR or lines[-1] != END_ARMOR:
        raise ValueError("tag signature is not an OpenSSH SSHSIG armored block")
    blob = base64.b64decode("".join(lines[1:-1]), validate=True)
    if len(blob) < 10 or blob[:6] != b"SSHSIG":
        raise ValueError("invalid SSHSIG magic preamble")
    (version,) = struct.unpack(">I", blob[6:10])
    if version != 1:
        raise ValueError(f"unsupported SSHSIG version: {version}")
    pubkey_blob, off = read_ssh_str(blob, 10)
    namespace, off = read_ssh_str(blob, off)
    reserved, off = read_ssh_str(blob, off)
    hash_alg, off = read_ssh_str(blob, off)
    sig_blob, off = read_ssh_str(blob, off)
    if off != len(blob):
        raise ValueError("trailing bytes in SSHSIG envelope")
    if namespace != b"git":
        raise ValueError(f"unexpected SSHSIG namespace: {namespace!r}")

    key_type, pk_off = read_ssh_str(pubkey_blob, 0)
    if key_type != REQUIRED_KEY_TYPE:
        raise ValueError("SSHSIG public key must be hardware sk-ssh-ed25519@openssh.com")
    pubkey_raw, pk_off = read_ssh_str(pubkey_blob, pk_off)
    application, pk_off = read_ssh_str(pubkey_blob, pk_off)
    if len(pubkey_raw) != 32 or pk_off != len(pubkey_blob):
        raise ValueError("invalid sk-ssh-ed25519@openssh.com public key wire layout")
    if not application.startswith(b"ssh:"):
        raise ValueError("SSHSIG FIDO2 application string must start with 'ssh:'")

    pinned = (
        allowed_pubkey_hex
        if allowed_pubkey_hex is not None
        else OWNER_SK_ED25519_PUBKEY_HEX
    ).strip().lower()
    if len(pinned) != 64 or any(ch not in "0123456789abcdef" for ch in pinned):
        raise ValueError("pinned Ed25519 public key must be 64-char lowercase hex")
    if not hmac.compare_digest(pubkey_raw.hex(), pinned):
        raise ValueError("signer public key is not enrolled in OWNER_SK_ED25519_PUBKEY_HEX")

    sig_type, sg_off = read_ssh_str(sig_blob, 0)
    if sig_type != REQUIRED_KEY_TYPE:
        raise ValueError("SSHSIG signature must be hardware sk-ssh-ed25519@openssh.com")
    ed_sig, sg_off = read_ssh_str(sig_blob, sg_off)
    if len(ed_sig) != 64 or sg_off + 5 != len(sig_blob):
        raise ValueError("invalid sk-ssh-ed25519@openssh.com signature wire layout")
    flags = sig_blob[sg_off]
    (counter,) = struct.unpack(">I", sig_blob[sg_off + 1 : sg_off + 5])
    if (flags & 0x05) != 0x05:
        raise ValueError(f"FIDO2 UP+UV required (got flags=0x{flags:02x})")

    if hash_alg == b"sha512":
        msg_digest = hashlib.sha512(payload).digest()
    elif hash_alg == b"sha256":
        msg_digest = hashlib.sha256(payload).digest()
    else:
        raise ValueError(f"unsupported SSHSIG hash algorithm: {hash_alg!r}")

    to_sign = b"SSHSIG" + ssh_str(namespace) + ssh_str(reserved) + ssh_str(hash_alg) + ssh_str(msg_digest)
    fido_signed = (
        hashlib.sha256(application).digest()
        + bytes([flags])
        + struct.pack(">I", counter)
        + hashlib.sha256(to_sign).digest()
    )
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise ValueError("python3 cryptography package required for fail-closed Ed25519 verification") from exc
    Ed25519PublicKey.from_public_bytes(pubkey_raw).verify(ed_sig, fido_signed)
    return counter, pubkey_raw.hex()


def build_test_sk_armor(
    priv_seed: bytes, payload: bytes, app: bytes = b"ssh:", flags: int = 0x05, namespace: bytes = b"git"
) -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.from_private_bytes(priv_seed)
    pk = sk.public_key().public_bytes_raw()
    msg_digest = hashlib.sha512(payload).digest()
    to_sign = b"SSHSIG" + ssh_str(namespace) + ssh_str(b"") + ssh_str(b"sha512") + ssh_str(msg_digest)
    fido_signed = hashlib.sha256(app).digest() + bytes([flags]) + struct.pack(">I", 1) + hashlib.sha256(to_sign).digest()
    ed_sig = sk.sign(fido_signed)
    pubkey_blob = ssh_str(REQUIRED_KEY_TYPE) + ssh_str(pk) + ssh_str(app)
    sig_blob = ssh_str(REQUIRED_KEY_TYPE) + ssh_str(ed_sig) + bytes([flags]) + struct.pack(">I", 1)
    wire = (
        b"SSHSIG"
        + struct.pack(">I", 1)
        + ssh_str(pubkey_blob)
        + ssh_str(namespace)
        + ssh_str(b"")
        + ssh_str(b"sha512")
        + ssh_str(sig_blob)
    )
    b64 = base64.b64encode(wire).decode("ascii")
    return f"{BEGIN_ARMOR}\n{b64}\n{END_ARMOR}", pk.hex()


def build_test_software_ed25519_armor(priv_seed: bytes, payload: bytes) -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.from_private_bytes(priv_seed)
    pk = sk.public_key().public_bytes_raw()
    msg_digest = hashlib.sha512(payload).digest()
    to_sign = b"SSHSIG" + ssh_str(b"git") + ssh_str(b"") + ssh_str(b"sha512") + ssh_str(msg_digest)
    ed_sig = sk.sign(to_sign)
    pubkey_blob = ssh_str(SOFTWARE_KEY_TYPE) + ssh_str(pk)
    sig_blob = ssh_str(SOFTWARE_KEY_TYPE) + ssh_str(ed_sig)
    wire = (
        b"SSHSIG"
        + struct.pack(">I", 1)
        + ssh_str(pubkey_blob)
        + ssh_str(b"git")
        + ssh_str(b"")
        + ssh_str(b"sha512")
        + ssh_str(sig_blob)
    )
    b64 = base64.b64encode(wire).decode("ascii")
    return f"{BEGIN_ARMOR}\n{b64}\n{END_ARMOR}", pk.hex()


def run_self_test() -> int:
    tag_payload = (
        b"object "
        + (b"a" * 40)
        + b"\ntype commit\ntag v1.2.3\ntagger Owner <owner@susanb.dev> 1700000000 +0000\n\nRelease v1.2.3\n"
    )

    for bad_ref in ("HEAD", "main", "1.2.3", "refs/tags/prov/seq-0000000001/main", "v1..2"):
        try:
            normalize_release_tag(bad_ref)
            raise SystemExit(f"self-test failed to reject non-v* or malformed ref {bad_ref!r}")
        except ValueError:
            pass

    for bad_type in ("commit", "blob", "tree", ""):
        try:
            validate_tag_object_type(bad_type, "refs/tags/v1.2.3")
            raise SystemExit("self-test failed to reject lightweight v* tag object type")
        except ValueError:
            pass

    for bad_raw in [
        tag_payload,
        tag_payload + b"-----BEGIN PGP SIGNATURE-----\nAA==\n-----END PGP SIGNATURE-----\n",
        b"tree " + (b"b" * 40) + b"\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\ncommit msg\n",
    ]:
        try:
            p, s = extract_tag_sig(bad_raw, expected_tag="v1.2.3")
            verify_sshsig(p, s)
            raise SystemExit("self-test failed to reject unsigned, PGP, or lightweight commit object")
        except ValueError:
            pass

    sw_armor, sw_pub = build_test_software_ed25519_armor(bytes(range(32)), tag_payload)
    sw_tag = tag_payload + sw_armor.encode("ascii") + b"\n"
    try:
        p, s = extract_tag_sig(sw_tag, expected_tag="v1.2.3")
        verify_sshsig(p, s, allowed_pubkey_hex=sw_pub)
        raise SystemExit("self-test failed to reject non-sk software ssh-ed25519 v* tag")
    except ValueError:
        pass

    valid_armor, valid_pub = build_test_sk_armor(bytes(range(32)), tag_payload, b"ssh:", 0x05, b"git")
    valid_tag = tag_payload + valid_armor.encode("ascii") + b"\n"

    try:
        extract_tag_sig(valid_tag, expected_tag="v9.9.9")
        raise SystemExit("self-test failed to reject mismatched annotated tag header")
    except ValueError:
        pass

    prev_env_pk = os.environ.get("ALLOWED_SK_PUBKEY_HEX")
    os.environ["ALLOWED_SK_PUBKEY_HEX"] = valid_pub
    try:
        p, s = extract_tag_sig(valid_tag, expected_tag="v1.2.3")
        verify_sshsig(p, s)
        raise SystemExit("self-test failed to reject un-enrolled sk-ssh-ed25519 key under ambient ALLOWED_SK_PUBKEY_HEX")
    except ValueError:
        pass
    finally:
        if prev_env_pk is None:
            os.environ.pop("ALLOWED_SK_PUBKEY_HEX", None)
        else:
            os.environ["ALLOWED_SK_PUBKEY_HEX"] = prev_env_pk

    for bad_flags in (0x00, 0x01, 0x04):
        bad_fl_armor, bad_fl_pub = build_test_sk_armor(bytes(range(32)), tag_payload, b"ssh:", bad_flags, b"git")
        try:
            verify_sshsig(tag_payload, bad_fl_armor, allowed_pubkey_hex=bad_fl_pub)
            raise SystemExit("self-test failed to reject sk-ssh-ed25519 signature lacking UP+UV")
        except ValueError:
            pass

    for bad_app, bad_ns in ((b"https://evil", b"git"), (b"ssh:", b"file")):
        bad_env_armor, bad_env_pub = build_test_sk_armor(bytes(range(32)), tag_payload, bad_app, 0x05, bad_ns)
        try:
            verify_sshsig(tag_payload, bad_env_armor, allowed_pubkey_hex=bad_env_pub)
            raise SystemExit("self-test failed to reject invalid FIDO2 app prefix or SSHSIG namespace")
        except ValueError:
            pass

    parsed_payload, parsed_armor = extract_tag_sig(valid_tag, expected_tag="v1.2.3")
    if parsed_payload != tag_payload:
        raise SystemExit("self-test extracted wrong annotated tag payload")
    cnt, verified_pub = verify_sshsig(parsed_payload, parsed_armor, allowed_pubkey_hex=valid_pub)
    if cnt != 1 or verified_pub != valid_pub:
        raise SystemExit("self-test failed positive enrolled sk-ssh-ed25519 v* release tag verification")
    return 0


def verify_git_release_tag(raw_ref: str) -> int:
    tag_name, tag_ref = normalize_release_tag(raw_ref)
    type_proc = subprocess.run(["git", "cat-file", "-t", tag_ref], capture_output=True, text=True)
    if type_proc.returncode != 0:
        raise ValueError(f"annotated release tag ref not found: {tag_ref}")
    validate_tag_object_type(type_proc.stdout, tag_ref)
    raw_tag = subprocess.check_output(["git", "cat-file", "tag", tag_ref])
    payload, armored = extract_tag_sig(raw_tag, expected_tag=tag_name)
    counter, pub_hex = verify_sshsig(payload, armored)
    print(
        f"[OK] Verified FIDO2 sk-ssh-ed25519@openssh.com SSHSIG (UP+UV, counter={counter}, key={pub_hex[:16]}...) on {tag_ref}"
    )
    return 0


def main(argv: list[str]) -> int:
    if argv and argv[0] in ("-h", "--help"):
        print("Usage: ./scripts/verify-release-tag-sshsig.sh [--verify <vX.Y.Z|refs/tags/vX.Y.Z> | --self-test]")
        print("Create hardware-signed release tag: git tag -s vX.Y.Z -m 'Release vX.Y.Z'")
        return 0
    if argv == ["--self-test"]:
        return run_self_test()
    target: str | None = None
    if len(argv) == 2 and argv[0] == "--verify":
        target = argv[1]
    elif len(argv) == 1 and not argv[0].startswith("-"):
        target = argv[0]
    elif not argv and os.environ.get("GITHUB_REF", "").startswith("refs/tags/v"):
        target = os.environ["GITHUB_REF"]
    if not target:
        print(
            "[SSHSIG FAIL] expected --self-test or annotated v* release tag (--verify vX.Y.Z)",
            file=sys.stderr,
        )
        return 1
    try:
        return verify_git_release_tag(target)
    except (ValueError, subprocess.CalledProcessError) as exc:
        print(f"[SSHSIG FAIL] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
PY
