import unittest

from pif.context import Context, Origin
from pif.toolauth import Code
from pif.example_policy import helpdesk_policy

TICKET = Origin("ticket", "8814")


def clean():
    return Context().system("You are a helpdesk bot.").user("help me")


def tainted():
    return clean().data("ticket body", TICKET)


def email(to, **over):
    args = {"to": to, "subject": "hi", "body": "hello"}
    args.update(over)
    return args


class Base(unittest.TestCase):
    def setUp(self):
        self.p = helpdesk_policy()

    def deny(self, ctx, tool, args, code):
        d = self.p.authorize(ctx, tool, args)
        self.assertFalse(d.allowed, d)
        self.assertEqual(d.code, code, d)

    def allow(self, ctx, tool, args):
        d = self.p.authorize(ctx, tool, args)
        self.assertTrue(d.allowed, d)
        self.assertEqual(d.code, Code.ALLOW)


class TestAttacks(Base):
    def test_a01_tainted_email_to_evil(self):
        self.deny(tainted(), "send_email", email("x@evil.example"), Code.TAINTED_CONTEXT)

    def test_a02_tainted_email_to_allowed_domain(self):
        self.deny(tainted(), "send_email", email("a@acme.example"), Code.TAINTED_CONTEXT)

    def test_a03_clean_email_to_evil(self):
        self.deny(clean(), "send_email", email("x@evil.example"), Code.GUARD)

    def test_a04_run_shell_forbidden(self):
        self.deny(clean(), "run_shell", {"cmd": "id"}, Code.FORBIDDEN_EFFECT)

    def test_a05_unknown_tool(self):
        self.deny(clean(), "export_db", {}, Code.UNKNOWN_TOOL)

    def test_a06_ticket_id_injection(self):
        self.deny(clean(), "get_ticket", {"ticket_id": "1; DROP TABLE t"}, Code.PATTERN)

    def test_a07_extra_arg(self):
        self.deny(clean(), "get_ticket", {"ticket_id": "1", "debug": "true"}, Code.UNKNOWN_ARG)

    def test_a08_query_too_long(self):
        self.deny(clean(), "search_kb", {"query": "a" * 5000}, Code.TOO_LONG)

    def test_a09_missing_body(self):
        self.deny(clean(), "send_email", {"to": "a@acme.example", "subject": "hi"}, Code.MISSING_ARG)

    def test_a10_ticket_id_wrong_type(self):
        self.deny(clean(), "get_ticket", {"ticket_id": ["1"]}, Code.TYPE)

    def test_a11_suffix_trick(self):
        self.deny(clean(), "send_email", email("a@notacme.example"), Code.GUARD)

    def test_a12_allowed_name_in_wrong_place(self):
        self.deny(clean(), "send_email", email("acme.example@evil.example"), Code.GUARD)

    def test_a13_tainted_delete(self):
        self.deny(tainted(), "delete_ticket", {"ticket_id": "42"}, Code.TAINTED_CONTEXT)

    def test_a14_tainted_http_get_even_to_allowed_host(self):
        self.deny(tainted(), "http_get", {"url": "https://kb.acme.example/a"}, Code.TAINTED_CONTEXT)

    def test_a15_clean_http_get_bad_host(self):
        self.deny(clean(), "http_get", {"url": "https://evil.example/x"}, Code.GUARD)

    def test_a16_taint_persists_after_later_user_message(self):
        ctx = Context().system("s").data("evil", TICKET).user("ok go")
        self.deny(ctx, "send_email", email("a@acme.example"), Code.TAINTED_CONTEXT)


class TestBenign(Base):
    def test_b01_tainted_search_kb(self):
        self.allow(tainted(), "search_kb", {"query": "refund policy"})

    def test_b02_tainted_get_ticket(self):
        self.allow(tainted(), "get_ticket", {"ticket_id": "8814"})

    def test_b03_clean_email_to_allowed(self):
        self.allow(clean(), "send_email", email("support@acme.example"))

    def test_b04_clean_http_get_allowed_host(self):
        self.allow(clean(), "http_get", {"url": "https://kb.acme.example/article/1"})

    def test_b05_clean_delete(self):
        self.allow(clean(), "delete_ticket", {"ticket_id": "42"})

    def test_b06_domain_case_insensitive(self):
        self.allow(clean(), "send_email", email("SUPPORT@ACME.EXAMPLE"))

    def test_b07_optional_subject_omitted(self):
        self.allow(clean(), "send_email", {"to": "a@acme.example", "body": "hello"})

    def test_b08_tainted_unicode_query(self):
        self.allow(tainted(), "search_kb", {"query": "caf\u00e9 refund"})


class TestExtras(Base):
    def test_x1_url_userinfo_trick(self):
        self.deny(clean(), "http_get", {"url": "https://kb.acme.example@evil.example/x"}, Code.GUARD)

    def test_x2_unknown_tool_beats_taint(self):
        self.deny(tainted(), "export_db", {}, Code.UNKNOWN_TOOL)


if __name__ == "__main__":
    unittest.main()
