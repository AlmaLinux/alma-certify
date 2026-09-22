"""Minimal stdlib HTTPS helpers: JSON POST and multipart/form-data POST."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, Optional, Tuple

from alma_certify import __version__

# What this suite calls itself on the wire.
#
# Nothing set one before, so every request went out as ``Python-urllib/3.9`` on AlmaLinux 9 and
# ``Python-urllib/3.12`` on 8 and 10 - urllib's own default. That is one of the most widely
# blocked user agents there is: it appears in Cloudflare's managed bot rules and in most
# off-the-shelf WAF configurations, and a catalog behind one of those refuses the submission
# before it reaches the application. Reported as exactly that.
#
# It also could not be allowed *through* safely. Whoever runs the catalog had nothing to permit
# but "Python-urllib/3.9", which is every Python script on the internet rather than this suite.
# A product name and version is something an operator can allow precisely, and something their
# logs can attribute.
#
# **No "Python-urllib" anywhere in it, deliberately.** Those rules match the substring, so
# carrying the underlying stack along for diagnostics would re-earn the ban the moment it was
# lifted. The ``+URL`` is the long-standing convention for telling an operator who is calling
# and where to read about it.
USER_AGENT = "alma-certify/%s (+https://github.com/AlmaLinux/alma-certify)" % __version__

# Whether to verify the server's certificate. True is the only value anything should ship with; the
# other exists because a self-signed certificate is a normal thing for a staging or dev catalog to
# have, and refusing to talk to one at all means the people testing the suite against a dev server
# cannot use the suite.
#
# Module-level rather than a parameter threaded through register, ensure_token, check_token and
# submit_run: it is one process-wide decision made once from configuration, and passing it through
# four signatures to reach one ``ssl`` call would put the flag in more places than it belongs. Set
# it through ``allow_self_signed`` and read it back with ``verifying`` - never assign it directly.
_VERIFY = True


def allow_self_signed(enabled: bool) -> None:
    """Stop verifying the catalog's TLS certificate.

    This does not merely accept self-signed certificates: it accepts **any** certificate, from
    anyone who can answer on that address, and it stops checking that the name matches. That is the
    honest description, and it is why the CLI prints a warning every time it is used and why nothing
    turns it on by default. For a server whose certificate is self-signed but known, the safer
    arrangement is to add that certificate to the host's trust store and leave this alone.
    """
    global _VERIFY
    _VERIFY = not enabled


def verifying() -> bool:
    """Whether certificates are being verified. For the warning, and for tests."""
    return _VERIFY


def _context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not _VERIFY:
        # Both, and in this order: check_hostname must go first, because setting verify_mode to
        # CERT_NONE while it is still on raises rather than doing what was asked.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _open(req: urllib.request.Request, timeout: float) -> Tuple[int, Any]:
    # Set here rather than beside each ``Accept``: every request in this module goes through
    # this function, so a fourth caller added later cannot forget it and quietly go back to
    # identifying itself as urllib.
    req.add_header("User-Agent", USER_AGENT)
    ctx = _context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        status = exc.code
    try:
        parsed = json.loads(body) if body else {}
    except json.JSONDecodeError:
        parsed = {"raw": body}
    return status, parsed


def get_json(
    url: str,
    token: Optional[str] = None,
    timeout: float = 10,
) -> Tuple[int, Any]:
    """GET returning (status, parsed-json).

    Short default timeout: the only caller is the pre-run token check, and a run must not
    stall for thirty seconds because the catalog is unreachable. A network problem there is
    not a reason to refuse to test hardware.
    """
    req = urllib.request.Request(url, method="GET")
    req.add_header("Accept", "application/json")
    if token:
        req.add_header("Authorization", "Bearer %s" % token)
    return _open(req, timeout)


def post_json(
    url: str,
    payload: Dict[str, Any],
    token: Optional[str] = None,
    timeout: float = 30,
) -> Tuple[int, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    if token:
        req.add_header("Authorization", "Bearer %s" % token)
    return _open(req, timeout)


def post_multipart(
    url: str,
    fields: Dict[str, str],
    file_field: str,
    file_path: str,
    token: Optional[str] = None,
    timeout: float = 600,
    content_type: str = "application/zstd",
) -> Tuple[int, Any]:
    boundary = uuid.uuid4().hex
    parts = []
    for name, value in fields.items():
        parts.append(
            (
                "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                % (boundary, name, value)
            ).encode("utf-8")
        )
    filename = file_path.rsplit("/", 1)[-1]
    parts.append(
        (
            "--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
            "Content-Type: %s\r\n\r\n" % (boundary, file_field, filename, content_type)
        ).encode("utf-8")
    )
    with open(file_path, "rb") as fh:
        parts.append(fh.read())
    parts.append(("\r\n--%s--\r\n" % boundary).encode("utf-8"))
    body = b"".join(parts)

    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "multipart/form-data; boundary=%s" % boundary)
    req.add_header("Accept", "application/json")
    if token:
        req.add_header("Authorization", "Bearer %s" % token)
    return _open(req, timeout)
