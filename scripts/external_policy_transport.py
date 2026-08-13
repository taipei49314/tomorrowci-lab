#!/usr/bin/env python3
"""Fetch a candidate-specific authorization policy from a pinned external transport.

The policy locator is derived only from bytes already verified in the candidate
artifact.  It is never a dispatch input and it is never read from the caller's
authorization bundle.  HTTPS transport is deliberately strict: no proxy,
cookie, redirect, credential, content-coding, or ambiguous response is
accepted.  The fetched policy is also verified with the repository-pinned
auditor key before it can be consumed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import external_authorization as authorization

KIND = "tomorrowci.external-policy-transport.v1"
RECEIPT_KIND = "tomorrowci.external-policy-transport-receipt.v1"
MAX_BYTES = 1024 * 1024
SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/+\-]{0,199}$")
_TEMPLATE = re.compile(r"\{(candidate_commit|candidate_manifest_sha256_hex)\}")


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    import hashlib

    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _snapshot(path: Path, label: str) -> authorization._Snapshot:
    return authorization._snapshot(path, label)


def _url_template(value: object, label: str) -> str:
    if type(value) is not str or len(value) > 2048:
        raise ValueError(f"invalid {label}")
    fields = _TEMPLATE.findall(value)
    if sorted(fields) != ["candidate_commit", "candidate_manifest_sha256_hex"]:
        raise ValueError(f"{label} must contain each candidate identity field exactly once")
    if _TEMPLATE.sub("", value).find("{") >= 0 or _TEMPLATE.sub("", value).find("}") >= 0:
        raise ValueError(f"{label} has an unknown template field")
    parsed = urllib.parse.urlsplit(value.replace("{candidate_commit}", "a" * 40).replace("{candidate_manifest_sha256_hex}", "b" * 64))
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or "/../" in f"/{parsed.path}/"
        or "//" in parsed.path
    ):
        raise ValueError(f"{label} must be a direct canonical HTTPS URL")
    return value


def load_transport(config: Path, allowed_signers: Path) -> tuple[dict, authorization._Snapshot, authorization._Snapshot]:
    config_snapshot = _snapshot(config, "external policy transport configuration")
    allowed_snapshot = _snapshot(allowed_signers, "allowed signers trust root")
    value = authorization._load_json(config_snapshot)
    authorization._object(value, {"kind", "schema_version", "transport", "trust"}, "external policy transport")
    if value["kind"] != KIND or value["schema_version"] != 1:
        raise ValueError("external policy transport identity mismatch")
    trust = authorization._object(value["trust"], {"allowed_signers_sha256", "auditor_principal", "namespace"}, "external policy transport trust")
    if trust["namespace"] != authorization.NAMESPACE:
        raise ValueError("external policy transport namespace mismatch")
    if type(trust["auditor_principal"]) is not str or not TOKEN.fullmatch(trust["auditor_principal"]):
        raise ValueError("external policy transport auditor principal is invalid")
    if type(trust["allowed_signers_sha256"]) is not str or not SHA256.fullmatch(trust["allowed_signers_sha256"]):
        raise ValueError("external policy transport trust digest is invalid")
    if allowed_snapshot.sha256 != trust["allowed_signers_sha256"]:
        raise ValueError("external policy transport trust root digest mismatch")
    authorization._validate_allowed_signers(allowed_snapshot, trust["auditor_principal"], trust["allowed_signers_sha256"])
    transport = authorization._object(value["transport"], {"maximum_bytes", "policy_url_template", "signature_url_template"}, "external policy transport endpoint")
    if type(transport["maximum_bytes"]) is not int or not 1 <= transport["maximum_bytes"] <= MAX_BYTES:
        raise ValueError("external policy transport maximum bytes is invalid")
    policy_template = _url_template(transport["policy_url_template"], "policy URL template")
    signature_template = _url_template(transport["signature_url_template"], "policy signature URL template")
    if policy_template == signature_template:
        raise ValueError("policy and signature URLs must differ")
    return value, config_snapshot, allowed_snapshot


def _candidate_identity(candidate_manifest: Path) -> tuple[str, str, str]:
    snapshot = _snapshot(candidate_manifest, "candidate manifest")
    manifest = authorization._load_json(snapshot, canonical=False)
    authorization._object(manifest, {"build", "kind", "payload", "promotion", "schema_version", "source", "status", "version", "workflow"}, "candidate manifest")
    source = authorization._object(manifest["source"], {"commit", "dirty", "ref", "repository"}, "candidate manifest source")
    if type(source["repository"]) is not str or not authorization.SLUG.fullmatch(source["repository"]):
        raise ValueError("candidate manifest repository is invalid")
    if type(source["commit"]) is not str or not SHA.fullmatch(source["commit"]):
        raise ValueError("candidate manifest commit is invalid")
    if source["dirty"] is not False or source["ref"] != "refs/heads/master":
        raise ValueError("candidate manifest source is not a clean master candidate")
    return source["repository"], source["commit"], snapshot.sha256


def render_urls(config: dict, *, candidate_commit: str, candidate_manifest_sha256: str) -> tuple[str, str]:
    if not SHA.fullmatch(candidate_commit) or not SHA256.fullmatch(candidate_manifest_sha256):
        raise ValueError("candidate identity is malformed")
    values = {"candidate_commit": candidate_commit, "candidate_manifest_sha256_hex": candidate_manifest_sha256.removeprefix("sha256:")}
    def render(template: str) -> str:
        url = _TEMPLATE.sub(lambda item: values[item.group(1)], template)
        # The template was prevalidated, but parse again after rendering to make
        # this boundary explicit and prevent future token changes from widening it.
        _url_template(template, "policy transport URL template")
        if urllib.parse.urlsplit(url).hostname != urllib.parse.urlsplit(template.replace("{candidate_commit}", "a" * 40).replace("{candidate_manifest_sha256_hex}", "b" * 64)).hostname:
            raise ValueError("rendered external policy authority changed")
        return url
    transport = config["transport"]
    return render(transport["policy_url_template"]), render(transport["signature_url_template"])


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise urllib.error.HTTPError(req.full_url, code, "redirects are forbidden", headers, fp)


def _fetch(url: str, *, maximum_bytes: int, opener: object | None = None) -> bytes:
    active_opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(url, headers={"Accept": "application/octet-stream", "Cache-Control": "no-cache", "Pragma": "no-cache", "User-Agent": "TomorrowCI-external-policy-transport/1"})
    try:
        with active_opener.open(request, timeout=30) as response:  # type: ignore[union-attr]
            if response.status != 200 or response.geturl() != url:
                raise ValueError("external policy transport response identity mismatch")
            if response.headers.get("Content-Encoding") not in (None, "identity"):
                raise ValueError("external policy transport content encoding is forbidden")
            length = response.headers.get("Content-Length")
            if length is None or not length.isdecimal() or int(length) > maximum_bytes:
                raise ValueError("external policy transport content length is invalid")
            data = response.read(maximum_bytes + 1)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise ValueError("external policy transport fetch failed") from exc
    if len(data) != int(length) or not data or len(data) > maximum_bytes:
        raise ValueError("external policy transport response bytes are invalid")
    return data


def _write_new(path: Path, data: bytes, label: str) -> None:
    parent = path.absolute().parent
    if not parent.is_dir() or parent.is_symlink() or path.exists() or path.is_symlink():
        raise ValueError(f"refusing non-new {label} output")
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(0o600)


def fetch_policy(*, config: Path, allowed_signers: Path, candidate_manifest: Path, output_policy: Path, output_signature: Path, opener: object | None = None) -> dict:
    transport, config_snapshot, allowed_snapshot = load_transport(config, allowed_signers)
    repository, commit, manifest_sha256 = _candidate_identity(candidate_manifest)
    policy_url, signature_url = render_urls(transport, candidate_commit=commit, candidate_manifest_sha256=manifest_sha256)
    maximum = transport["transport"]["maximum_bytes"]
    # Keep this immutable parsed value local before any network IO.
    policy_data = _fetch(policy_url, maximum_bytes=maximum, opener=opener)
    signature_data = _fetch(signature_url, maximum_bytes=maximum, opener=opener)
    policy_snapshot = authorization._Snapshot("externally transported authorization policy", output_policy.absolute(), policy_data, _sha256(policy_data))
    signature_snapshot = authorization._Snapshot("externally transported policy signature", output_signature.absolute(), signature_data, _sha256(signature_data))
    policy = authorization._load_policy(policy_snapshot)
    expected_candidate = policy["candidate"]
    if expected_candidate["repository"] != repository or expected_candidate["commit"] != commit or expected_candidate["manifest_sha256"] != manifest_sha256:
        raise ValueError("external policy does not bind the exact verified candidate")
    trust = transport["trust"]
    if policy["trust"] != {"allowed_signers_sha256": trust["allowed_signers_sha256"], "namespace": trust["namespace"]}:
        raise ValueError("external policy trust does not match pinned transport trust")
    if policy["external"]["auditor_principal"] != trust["auditor_principal"]:
        raise ValueError("external policy auditor does not match pinned transport identity")
    authorization._verify_signature(authorization=policy_snapshot, signature=signature_snapshot, allowed_signers=allowed_snapshot, principal=trust["auditor_principal"], ssh_keygen="ssh-keygen")
    _write_new(output_policy, policy_data, "policy")
    _write_new(output_signature, signature_data, "policy signature")
    return {"candidate": {"commit": commit, "manifest_sha256": manifest_sha256, "repository": repository}, "config_sha256": config_snapshot.sha256, "kind": RECEIPT_KIND, "policy": {"sha256": policy_snapshot.sha256, "url": policy_url}, "signature": {"sha256": signature_snapshot.sha256, "url": signature_url}, "status": "FETCHED_FROM_EXTERNAL_SIGNED_TRANSPORT_ONLY", "trust": trust}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fetch")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--allowed-signers", type=Path, required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--output-policy", type=Path, required=True)
    parser.add_argument("--output-signature", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        receipt = fetch_policy(**{key: value for key, value in vars(args).items() if key != "fetch"})
        sys.stdout.buffer.write(_canonical_bytes(receipt))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"external-policy-transport: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
