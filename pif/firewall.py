"""One front door that chains the layers. Each layer can be switched off for the ablation.

Layers: normalize, ingress (scored), provenance, toolauth, egress.
Reasons look like "toolauth:TAINTED_CONTEXT" so every block names the layer that made it.
"""
from dataclasses import dataclass

from .context import InvariantViolation
from .ingress import DEFAULT_THRESHOLD, scan

ALL_LAYERS = frozenset({"normalize", "ingress", "provenance", "toolauth", "egress"})


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reasons: tuple = ()
    score: int = 0
    rendered: str | None = None


def _plain(ctx):
    return "\n\n".join(f"[{s.role.upper()}]\n{s.text}" for s in ctx.spans)


class Firewall:
    def __init__(self, policy, egress, layers=ALL_LAYERS, ingress_threshold=DEFAULT_THRESHOLD):
        layers = frozenset(layers)
        unknown = layers - ALL_LAYERS
        if unknown:
            raise ValueError(f"unknown layers: {sorted(unknown)}")
        self.policy, self.egress, self.layers = policy, egress, layers
        self.threshold = ingress_threshold

    def inspect_input(self, ctx, nonce=None):
        reasons, score, rendered = [], 0, None
        if "ingress" in self.layers:
            res = scan(ctx, use_normalize="normalize" in self.layers, threshold=self.threshold)
            score = res.score
            if res.flagged:
                reasons.append("ingress:SCORE")
        if "provenance" in self.layers:
            try:
                rendered = ctx.render(nonce=nonce).text
            except InvariantViolation:
                reasons.append("provenance:NONCE")
        else:
            rendered = _plain(ctx)
        allowed = not reasons
        return Verdict(allowed, tuple(reasons), score, rendered if allowed else None)

    def authorize_tool(self, ctx, tool, args):
        if "toolauth" not in self.layers:
            return Verdict(True)
        d = self.policy.authorize(ctx, tool, args)
        return Verdict(d.allowed, () if d.allowed else (f"toolauth:{d.code.value}",))

    def check_output(self, text):
        if "egress" not in self.layers:
            return Verdict(True)
        r = self.egress.check(text)
        return Verdict(r.allowed, tuple(f"egress:{k}" for k in sorted(r.kinds)))
