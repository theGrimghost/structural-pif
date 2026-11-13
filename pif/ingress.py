"""Ingress layer: SCORED text inspection of untrusted (DATA) spans only.

This is the one layer that guesses. It is best-effort, labelled invariant=False,
and reported separately in the eval. It catches the copy-pasted attacks and
nothing more.

Limitations (each one has a test): paraphrased attacks are missed; non-English
attacks are missed; text that merely QUOTES an attack (a news article, a
security blog) is flagged (false positive); user() spans are not scanned, so a
hostile user is out of scope.
"""
import re
from dataclasses import dataclass

from .normalize import normalize

DEFAULT_THRESHOLD = 3
_FLAGS = re.IGNORECASE | re.MULTILINE

_SIGNALS = (
    ("chat_template", 3, re.compile(
        r"<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>"
        r"|\[/?INST\]|<<\s*/?SYS\s*>>", _FLAGS)),
    ("override", 3, re.compile(
        r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}"
        r"\b(?:previous|prior|above|earlier|all|any|your|the)\b[^.\n]{0,30}"
        r"\b(?:instructions?|rules?|prompts?|guidelines?)\b", _FLAGS)),
    ("role_line", 2, re.compile(r"^\s*(?:system|assistant|developer)\s*:", _FLAGS)),
    ("new_role", 2, re.compile(r"\b(?:you are now|from now on you|new instructions)\b", _FLAGS)),
    ("prompt_leak", 2, re.compile(
        r"\b(?:reveal|print|show|repeat|output)\b[^.\n]{0,30}"
        r"\b(?:system prompt|your instructions|hidden prompt)\b", _FLAGS)),
    ("exfil", 2, re.compile(
        r"\b(?:send|email|forward|post|upload)\b[^.\n]{0,60}\b(?:to|at)\b[^.\n]{0,40}(?:@|https?://)",
        _FLAGS)),
)

# nfkc alone is common in honest text, so it is reported by normalize but adds no score here.
_NORM_WEIGHTS = {"tag_chars": 3, "bidi": 2, "zero_width": 1, "confusables": 1}


@dataclass(frozen=True)
class IngressResult:
    score: int
    hits: tuple = ()
    flagged: bool = False
    origin: str = ""
    invariant: bool = False


def scan_text(text, use_normalize=True, threshold=DEFAULT_THRESHOLD):
    score, hits = 0, []
    body = text
    if use_normalize:
        n = normalize(text)
        body = n.text
        for f in n.findings:
            w = _NORM_WEIGHTS.get(f.kind, 0)
            if w:
                score += w
                hits.append(f"norm:{f.kind}")
    for name, weight, rx in _SIGNALS:
        if rx.search(body):
            score += weight
            hits.append(name)
    return IngressResult(score, tuple(hits), score >= threshold)


def scan(ctx, use_normalize=True, threshold=DEFAULT_THRESHOLD):
    best = IngressResult(0)
    for s in ctx.spans:
        if s.role != "data":
            continue
        r = scan_text(s.text, use_normalize, threshold)
        if r.score > best.score:
            best = IngressResult(r.score, r.hits, r.flagged, f"{s.origin.source}:{s.origin.ref}")
    return best
