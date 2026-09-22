"""What this suite calls itself on the wire.

Reported from a deployment: Cloudflare was refusing submissions because the user agent was
banned. Nothing set one, so every request went out as urllib's default - ``Python-urllib/3.9``
on AlmaLinux 9, ``Python-urllib/3.12`` on 8 and 10 - which is in Cloudflare's managed bot rules
and most off-the-shelf WAF configurations.

It could not be allowed through safely either: the catalog's operator had nothing to permit but
"Python-urllib/3.9", which is every Python script on the internet rather than this suite.

These hold the three things that matter: it identifies itself, it does so on every request, and
its name contains nothing a bot rule matches on.
"""

import urllib.request

import pytest

from alma_certify import __version__
from alma_certify.submit import http


class _Response:
    status = 200

    def read(self):
        return b"{}"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def sent(monkeypatch):
    """Capture the request each helper would put on the wire."""
    captured = []

    def fake_urlopen(req, timeout=None, context=None):
        captured.append(req)
        return _Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return captured


def test_it_says_what_it_is_and_which_version():
    """A version is what lets an operator tell "the suite" from "the suite before the fix"."""
    assert http.USER_AGENT.startswith("alma-certify/")
    assert __version__ in http.USER_AGENT


def test_it_does_not_call_itself_urllib():
    """The load-bearing one. Those rules match the substring, so carrying the underlying stack
    along for diagnostics would re-earn the ban the moment it was lifted."""
    assert "urllib" not in http.USER_AGENT.lower()
    assert "python" not in http.USER_AGENT.lower()


def test_it_points_at_something_an_operator_can_read():
    """The ``+URL`` convention: somebody looking at a blocked request in their logs can find out
    who is calling without having to ask."""
    assert "+https://github.com/AlmaLinux/alma-certify" in http.USER_AGENT


def test_every_request_carries_it(sent, tmp_path):
    """Set in ``_open`` rather than at each call site, so this covers a caller added later. All
    three would otherwise have to remember, and the one that forgot would be the one that
    submits the bundle."""
    bundle = tmp_path / "run.tar.zst"
    bundle.write_bytes(b"x")

    http.get_json("https://catalog.invalid/api/v1/whoami")
    http.post_json("https://catalog.invalid/api/v1/register", {"a": 1})
    http.post_multipart(
        "https://catalog.invalid/api/v1/runs", fields={"f": "v"},
        file_field="bundle", file_path=str(bundle),
    )

    assert len(sent) == 3
    for req in sent:
        assert req.get_header("User-agent") == http.USER_AGENT


def test_urllib_does_not_substitute_its_own(sent):
    """urllib only supplies its default when the request has not set one. That is the mechanism
    this relies on, so it is worth pinning rather than assuming."""
    http.get_json("https://catalog.invalid/api/v1/whoami")

    assert sent[0].has_header("User-agent")
    opener_default = dict(urllib.request.build_opener().addheaders)
    assert sent[0].get_header("User-agent") != opener_default.get("User-agent")
