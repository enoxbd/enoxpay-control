#!/usr/bin/env python3
"""Validates all control/*.json files, increments monotonic revision, and signs dist/signed_control.json."""

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

APP_ID = "com.enox.enoxpay.bmdxyz"
EXPECTED_PUBLIC_KEY_SPKI_B64 = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXQpJa5yPyZa3J9gq/5rEeo/SkpLe"
    "vj6XdwZZrHDeWfsSHS02NgpKZjPC9z8DikjL4X7+0PydAO/zM4/S0ATRig=="
)

REQUIRED_FILES = {
    "appStatus": "control/app_status.json",
    "update": "control/update.json",
    "features": "control/features.json",
    "announcement": "control/announcement.json",
    "security": "control/security.json",
    "links": "control/links.json",
    "appConfig": "control/app_config.json",
}


def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def read_previous_revision() -> int:
    rev = 0
    if os.path.exists("dist/revision.txt"):
        with open("dist/revision.txt", "r", encoding="utf-8") as f:
            raw = f.read().strip()
            if raw.isdigit():
                rev = max(rev, int(raw))
    if os.path.exists("dist/signed_control.json"):
        try:
            prev = load_json("dist/signed_control.json")
            rev = max(rev, int(prev.get("revision", 0)))
        except Exception:
            pass
    return rev


def main() -> int:
    signing_key_pem = os.environ.get("ENOX_CONTROL_SIGNING_KEY", "").strip()
    if "BEGIN" not in signing_key_pem:
        print("ERROR: ENOX_CONTROL_SIGNING_KEY env var is missing or invalid PEM", file=sys.stderr)
        return 1

    bundle_sections = {}
    file_hashes = {}
    for key, path in REQUIRED_FILES.items():
        bundle_sections[key] = load_json(path)
        with open(path, "rb") as f:
            file_hashes[key] = hashlib.sha256(f.read()).hexdigest()

    # Basic semantic sanity checks so bad edits never break the Android client
    assert isinstance(bundle_sections["appStatus"].get("appEnabled"), bool), "appStatus.appEnabled must be boolean"
    assert int(bundle_sections["update"].get("latestVersionCode", 0)) >= 1, "update.latestVersionCode must be >= 1"
    assert int(bundle_sections["security"].get("offlineGraceMinutes", 60)) >= 1, "security.offlineGraceMinutes must be >= 1"

    next_revision = read_previous_revision() + 1
    signed_at_ms = int(time.time() * 1000)

    payload_obj = {
        "schema": 1,
        "appId": APP_ID,
        "revision": next_revision,
        "signedAtEpochMs": signed_at_ms,
        "fileSha256": file_hashes,
        **bundle_sections,
    }
    canonical_payload = json.dumps(payload_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = base64.b64encode(canonical_payload).decode("ascii")

    pub_pem = (
        "-----BEGIN PUBLIC KEY-----\n"
        + "\n".join(
            EXPECTED_PUBLIC_KEY_SPKI_B64[i : i + 64]
            for i in range(0, len(EXPECTED_PUBLIC_KEY_SPKI_B64), 64)
        )
        + "\n-----END PUBLIC KEY-----\n"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        priv_path = os.path.join(tmpdir, "priv.pem")
        pub_path = os.path.join(tmpdir, "pub.pem")
        payload_path = os.path.join(tmpdir, "payload.bin")
        sig_path = os.path.join(tmpdir, "payload.sig")

        with open(priv_path, "w", encoding="utf-8") as f:
            f.write(signing_key_pem + "\n")
        os.chmod(priv_path, 0o600)
        with open(pub_path, "w", encoding="utf-8") as f:
            f.write(pub_pem)
        with open(payload_path, "wb") as f:
            f.write(canonical_payload)

        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", priv_path, "-out", sig_path, payload_path],
            check=True,
        )
        verify = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", pub_path, "-signature", sig_path, payload_path],
            check=True,
            capture_output=True,
            text=True,
        )
        print("OpenSSL verification:", verify.stdout.strip())

        with open(sig_path, "rb") as f:
            sig_b64 = base64.b64encode(f.read()).decode("ascii")

    os.makedirs("dist", exist_ok=True)
    envelope = {
        "schema": 1,
        "algorithm": "SHA256withECDSA",
        "revision": next_revision,
        "signedAtEpochMs": signed_at_ms,
        "payloadBase64": payload_b64,
        "signatureBase64": sig_b64,
    }
    with open("dist/signed_control.json", "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2)
        f.write("\n")

    with open("dist/revision.txt", "w", encoding="utf-8") as f:
        f.write(f"{next_revision}\n")

    print(f"Signed control bundle revision={next_revision} payloadBytes={len(canonical_payload)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
