"""Provenance layer: untrusted text can never be promoted to instruction.

Invariant: taint is derived from the spans you added, never set by hand.
Limitation: fencing labels DATA unforgeably; it cannot force a model to obey the label.
"""
import re
import secrets
from dataclasses import dataclass

_ORIGIN_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")


class InvariantViolation(Exception):
    """A structural invariant was broken. Never a guess about intent."""


@dataclass(frozen=True)
class Origin:
    source: str
    ref: str

    def __post_init__(self):
        for value in (self.source, self.ref):
            if not isinstance(value, str) or not _ORIGIN_RE.fullmatch(value):
                raise ValueError(f"bad origin field: {value!r}")


@dataclass(frozen=True)
class Span:
    role: str
    text: str
    origin: Origin | None = None


@dataclass(frozen=True)
class Rendered:
    text: str
    nonce: str


@dataclass(frozen=True)
class Context:
    _spans: tuple = ()

    def _add(self, span):
        return Context(self._spans + (span,))

    def system(self, text):
        return self._add(Span("system", text))

    def user(self, text):
        return self._add(Span("user", text))

    def data(self, text, origin):
        if not isinstance(origin, Origin):
            raise TypeError("data spans require an Origin")
        return self._add(Span("data", text, origin))

    @property
    def spans(self):
        return self._spans

    @property
    def tainted_by(self):
        return tuple(s.origin for s in self._spans if s.role == "data")

    @property
    def tainted(self):
        return bool(self.tainted_by)

    def render(self, nonce=None):
        nonce = nonce or secrets.token_hex(8)
        parts = []
        for s in self._spans:
            if s.role == "data":
                if nonce in s.text:
                    raise InvariantViolation(
                        f"nonce present in DATA from {s.origin.source}:{s.origin.ref}"
                    )
                parts.append(
                    f"<<<UNTRUSTED-{nonce} origin={s.origin.source}:{s.origin.ref}>>>\n"
                    f"{s.text}\n<<<END-{nonce}>>>"
                )
            else:
                parts.append(f"[{s.role.upper()}]\n{s.text}")
        return Rendered("\n\n".join(parts), nonce)
