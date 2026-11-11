"""Egress layer: registered secrets do not leave, and outbound URLs are controlled.

Canary matching works on a squashed view of the text (lowercase, letters and
digits only) after normalize(), plus a percent-decoded view. Needles cover the
secret plain, reversed, rot13, hex and base64 (all three alignments, standard
and urlsafe alphabets). Findings never echo the secret, only its label.

URL control: every URL host must be allowlisted; every image (markdown or
HTML) must be https from an allowlisted host.

Limitations: single-layer encodings only (no base64-of-hex, no base32);
fragments separated by words are not matched; secrets under 8 letters/digits
are rejected because they cannot be matched without false positives; an
allowlisted host can still receive data in its query string; each message is
checked on its own, so a secret split across messages is not caught; only text
is inspected (no DNS or other side channels).
"""
import base64
import codecs
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from .normalize import normalize

_SQUASH = re.compile(r"[^a-z0-9]")
_URL = re.compile(r"(?i)https?://[^\s)\]>\"'<]+")
_MD_IMG = re.compile(r"!\[[^\]]*\]\(\s*<?([^)\s>]+)")
_HTML_IMG = re.compile(r"(?i)<img\b[^>]*?\bsrc\s*=\s*[\"']?([^\"'\s>]+)")
_URLSAFE = str.maketrans("+/", "-_")
_MIN_SECRET = 8
_MIN_NEEDLE = 8


def _squash(s):
    return _SQUASH.sub("", s.lower())


def _b64_bodies(raw):
    # The secret may sit at any byte offset inside a larger base64 blob, so keep
    # only the characters that do not depend on neighbouring bytes.
    for offset in (0, 1, 2):
        enc = base64.b64encode(b"\x00" * offset + raw).decode()
        body = enc.rstrip("=")
        if (offset + len(raw)) % 3:
            body = body[:-1]
        body = body[(0, 2, 3)[offset]:]
        yield body
        yield body.translate(_URLSAFE)


def _variants(secret):
    raw = secret.encode()
    yield "plain", secret
    yield "reversed", secret[::-1]
    yield "rot13", codecs.encode(secret, "rot13")
    yield "hex", raw.hex()
    for body in _b64_bodies(raw):
        yield "base64", body


def _parse(url):
    try:
        parts = urlsplit(url)
        return parts.scheme.lower(), (parts.hostname or "").lower()
    except ValueError:
        return "", ""


@dataclass(frozen=True)
class EgressFinding:
    kind: str
    detail: str


@dataclass(frozen=True)
class EgressResult:
    allowed: bool
    findings: tuple = ()

    @property
    def kinds(self):
        return frozenset(f.kind for f in self.findings)


class Egress:
    def __init__(self, canaries, allowed_hosts):
        self._needles = []
        for label, secret in canaries.items():
            if len(_squash(secret)) < _MIN_SECRET:
                raise ValueError(f"canary {label!r} is too short to match reliably")
            for variant, needle in _variants(secret):
                n = _squash(needle)
                if len(n) >= _MIN_NEEDLE:
                    self._needles.append((label, variant, n))
        self._hosts = frozenset(h.lower() for h in allowed_hosts)

    def check(self, text):
        norm = normalize(text).text
        findings, seen = [], set()

        def add(kind, detail):
            key = (kind, detail)
            if key not in seen:
                seen.add(key)
                findings.append(EgressFinding(kind, detail[:80]))

        views = (_squash(norm), _squash(unquote(norm)))
        hit = set()
        for label, variant, needle in self._needles:
            if label not in hit and any(needle in v for v in views):
                hit.add(label)
                add("CANARY", f"{label} via {variant}")

        for url in _URL.findall(norm):
            _, host = _parse(url)
            if host not in self._hosts:
                add("URL_HOST", host or "no-host")

        for url in _MD_IMG.findall(norm) + _HTML_IMG.findall(norm):
            scheme, host = _parse(url)
            if not (scheme == "https" and host in self._hosts):
                add("IMAGE_HOST", host or "no-host")

        return EgressResult(not findings, tuple(findings))
