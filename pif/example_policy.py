"""Example policy for a fictional helpdesk bot (used by tests and the eval)."""
from urllib.parse import urlsplit

from .toolauth import ArgSpec, Policy, ToolSpec


def email_guard(allowed_domains):
    allowed = frozenset(d.lower() for d in allowed_domains)

    def guard(value):
        if value.count("@") != 1 or any(c.isspace() for c in value):
            return False
        local, domain = value.split("@")
        return bool(local) and domain.lower() in allowed

    return guard


def host_guard(allowed_hosts):
    allowed = frozenset(h.lower() for h in allowed_hosts)

    def guard(value):
        if any(c.isspace() for c in value):
            return False
        try:
            parts = urlsplit(value)
            host = parts.hostname or ""
        except ValueError:
            return False
        return parts.scheme == "https" and host in allowed

    return guard


# [0-9] on purpose: \d would also accept non-ASCII digits.
_TICKET_ID = ArgSpec(str, pattern=r"[0-9]{1,8}")


def helpdesk_policy():
    return Policy([
        ToolSpec("search_kb", "read", safe_when_tainted=True,
                 args={"query": ArgSpec(str, max_len=200)}),
        ToolSpec("get_ticket", "read", safe_when_tainted=True,
                 args={"ticket_id": _TICKET_ID}),
        ToolSpec("send_email", "network", args={
            "to": ArgSpec(str, max_len=254, guard=email_guard(["acme.example"])),
            "subject": ArgSpec(str, required=False, max_len=100),
            "body": ArgSpec(str, max_len=2000),
        }),
        ToolSpec("http_get", "network", args={
            "url": ArgSpec(str, max_len=2000, guard=host_guard(["kb.acme.example"])),
        }),
        ToolSpec("delete_ticket", "write", args={"ticket_id": _TICKET_ID}),
        ToolSpec("run_shell", "exec", args={"cmd": ArgSpec(str)}),
    ])
