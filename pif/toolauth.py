"""Tool authorization layer: the model requests, the firewall authorizes.

The decision uses structure only: is the tool registered, is its effect banned,
is the context tainted, do the args fit a declared schema, do they pass an
exact-match guard. It never reads args to guess intent.

Check order is fixed: UNKNOWN_TOOL, FORBIDDEN_EFFECT, TAINTED_CONTEXT, schema,
then GUARD.

Limitations: taint is whole-context (one DATA span taints everything after it);
if the app passes untrusted text as user() instead of data(), nothing taints;
a tainted context can still call tools marked safe_when_tainted, and injected
text can steer their arguments.
"""
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class Code(str, Enum):
    ALLOW = "ALLOW"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    FORBIDDEN_EFFECT = "FORBIDDEN_EFFECT"
    TAINTED_CONTEXT = "TAINTED_CONTEXT"
    UNKNOWN_ARG = "UNKNOWN_ARG"
    MISSING_ARG = "MISSING_ARG"
    TYPE = "TYPE"
    TOO_LONG = "TOO_LONG"
    PATTERN = "PATTERN"
    GUARD = "GUARD"


@dataclass(frozen=True)
class ArgSpec:
    kind: type = str
    required: bool = True
    max_len: int | None = None
    pattern: str | None = None  # must fully match
    guard: Callable | None = None  # exact-match allowlist check


@dataclass(frozen=True)
class ToolSpec:
    name: str
    effect: str
    safe_when_tainted: bool = False
    args: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: Code
    detail: str = ""


def _deny(code, detail=""):
    return Decision(False, code, detail)


class Policy:
    def __init__(self, tools, forbidden_effects=("exec",)):
        self._tools = {t.name: t for t in tools}
        self._forbidden = frozenset(forbidden_effects)

    def authorize(self, ctx, tool, args):
        spec = self._tools.get(tool)
        if spec is None:
            return _deny(Code.UNKNOWN_TOOL, str(tool))
        if spec.effect in self._forbidden:
            return _deny(Code.FORBIDDEN_EFFECT, f"{tool} has effect {spec.effect}")
        if ctx.tainted and not spec.safe_when_tainted:
            origins = ", ".join(f"{o.source}:{o.ref}" for o in ctx.tainted_by)
            return _deny(Code.TAINTED_CONTEXT, f"{tool} blocked, tainted by {origins}")
        if not isinstance(args, dict):
            return _deny(Code.TYPE, "args must be a dict")

        for name in args:
            if name not in spec.args:
                return _deny(Code.UNKNOWN_ARG, name)
        for name, a in spec.args.items():
            if a.required and name not in args:
                return _deny(Code.MISSING_ARG, name)
        for name, value in args.items():
            a = spec.args[name]
            if type(value) is not a.kind:
                return _deny(Code.TYPE, name)
            if isinstance(value, str):
                if a.max_len is not None and len(value) > a.max_len:
                    return _deny(Code.TOO_LONG, name)
                if a.pattern is not None and not re.fullmatch(a.pattern, value):
                    return _deny(Code.PATTERN, name)
        for name, value in args.items():
            guard = spec.args[name].guard
            if guard is None:
                continue
            try:
                ok = guard(value)
            except Exception:
                ok = False
            if not ok:
                return _deny(Code.GUARD, name)

        return Decision(True, Code.ALLOW)
