"""Normalize layer: reveal what the text hides. Reports, never decides.

Known tradeoffs: stripping U+200D breaks joined emoji; NFKC rewrites some
harmless characters; the confusables map is tiny and only applies inside words
that already contain a Latin letter, so a word made purely of lookalikes is
not mapped.
"""
import re
import unicodedata
from dataclasses import dataclass

_TAG_RANGE = range(0xE0000, 0xE0080)
_ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}
_BIDI = (
    {"\u200e", "\u200f"}
    | {chr(c) for c in range(0x202A, 0x202F)}
    | {chr(c) for c in range(0x2066, 0x206A)}
)
_CONFUSABLES = {
    # Cyrillic lowercase
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0455": "s", "\u0458": "j",
    # Cyrillic uppercase
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0425": "X",
    # Greek
    "\u03bf": "o", "\u03bd": "v", "\u03b1": "a",
}
_WORD = re.compile(r"\w+")


@dataclass(frozen=True)
class Finding:
    kind: str
    count: int
    detail: str = ""


@dataclass(frozen=True)
class NormalizeResult:
    text: str
    findings: tuple = ()

    @property
    def kinds(self):
        return frozenset(f.kind for f in self.findings)


def normalize(text):
    findings = []
    out, hidden = [], []
    n_tag = n_zw = n_bidi = 0

    for ch in text:
        cp = ord(ch)
        if cp in _TAG_RANGE:
            n_tag += 1
            if 0xE0020 <= cp <= 0xE007E:
                visible = chr(cp - 0xE0000)
                hidden.append(visible)
                out.append(visible)
        elif ch in _ZERO_WIDTH:
            n_zw += 1
        elif ch in _BIDI:
            n_bidi += 1
        else:
            out.append(ch)
    s = "".join(out)

    if n_tag:
        findings.append(Finding("tag_chars", n_tag, "".join(hidden)))
    if n_zw:
        findings.append(Finding("zero_width", n_zw))
    if n_bidi:
        findings.append(Finding("bidi", n_bidi))

    n_nfkc = sum(1 for ch in s if unicodedata.normalize("NFKC", ch) != ch)
    if n_nfkc:
        s = unicodedata.normalize("NFKC", s)
        findings.append(Finding("nfkc", n_nfkc))

    mapped = 0

    def repl(m):
        nonlocal mapped
        word = m.group(0)
        if not any(c.isascii() and c.isalpha() for c in word):
            return word
        new = "".join(_CONFUSABLES.get(c, c) for c in word)
        mapped += sum(1 for a, b in zip(word, new) if a != b)
        return new

    s = _WORD.sub(repl, s)
    if mapped:
        findings.append(Finding("confusables", mapped))

    return NormalizeResult(s, tuple(findings))
