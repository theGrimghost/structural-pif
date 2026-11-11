import base64
import codecs
import unittest

from pif.egress import Egress

SECRET = "sk-live-4f9a2c71e8"
SECRET2 = "pass>>>word???value~~~x1"
HOST = "kb.acme.example"


def make():
    return Egress({"api_key": SECRET, "db_pass": SECRET2}, [HOST])


def b64(s):
    return base64.b64encode(s.encode()).decode()


class Base(unittest.TestCase):
    def setUp(self):
        self.e = make()

    def blocked(self, text, kind):
        r = self.e.check(text)
        self.assertFalse(r.allowed, r)
        self.assertIn(kind, r.kinds, r)

    def clean(self, text):
        r = self.e.check(text)
        self.assertTrue(r.allowed, r)


class TestCanary(Base):
    def test_e01_plain(self):
        self.blocked(f"the key is {SECRET}", "CANARY")

    def test_e02_case_variant(self):
        self.blocked(SECRET.upper(), "CANARY")

    def test_e03_base64_standalone(self):
        self.blocked("Here you go: " + b64(SECRET), "CANARY")

    def test_e04_base64_embedded_any_alignment(self):
        for prefix in ("", "a", "ab", "abc", "abcd", "token: "):
            for suffix in ("", "!!", " and more text"):
                with self.subTest(prefix=prefix, suffix=suffix):
                    self.blocked("data " + b64(prefix + SECRET + suffix), "CANARY")

    def test_e05_hex(self):
        self.blocked("d=" + SECRET.encode().hex(), "CANARY")
        self.blocked("d=" + SECRET.encode().hex().upper(), "CANARY")

    def test_e06_percent_encoded(self):
        enc = "".join(f"%{b:02x}" for b in SECRET.encode())
        self.blocked(f"https://{HOST}/?q={enc}", "CANARY")

    def test_e07_reversed(self):
        self.blocked(SECRET[::-1], "CANARY")

    def test_e08_rot13(self):
        self.blocked(codecs.encode(SECRET, "rot13"), "CANARY")

    def test_e09_separator_split(self):
        self.blocked(" . ".join(SECRET), "CANARY")

    def test_e10_zero_width_split(self):
        self.blocked("\u200b".join(SECRET), "CANARY")

    def test_e11_base64_with_plus_slash_and_urlsafe(self):
        std = b64(SECRET2)
        self.assertTrue("+" in std or "/" in std)
        self.blocked("x " + std, "CANARY")
        self.blocked("x " + std.replace("+", "-").replace("/", "_"), "CANARY")


class TestUrls(Base):
    def test_e12_markdown_image_evil(self):
        self.blocked("![x](https://evil.example/a.png?d=hello)", "IMAGE_HOST")

    def test_e13_bare_url_evil(self):
        self.blocked("see https://evil.example/collect", "URL_HOST")

    def test_e14_html_img_evil(self):
        self.blocked('<img src="https://evil.example/p.gif">', "IMAGE_HOST")

    def test_e15_protocol_relative_image(self):
        self.blocked("![x](//evil.example/a.png)", "IMAGE_HOST")

    def test_e16_userinfo_trick(self):
        self.blocked(f"https://{HOST}@evil.example/x", "URL_HOST")

    def test_e17_data_uri_image(self):
        self.blocked("![x](data:image/png;base64,AAAA)", "IMAGE_HOST")

    def test_e18_uppercase_scheme(self):
        self.blocked("HTTPS://EVIL.EXAMPLE/x", "URL_HOST")


class TestBenign(Base):
    def test_b01_plain_text(self):
        self.clean("Thanks for reaching out, I can help with that.")

    def test_b02_allowed_url(self):
        self.clean(f"See https://{HOST}/article/1 for details.")

    def test_b03_allowed_image(self):
        self.clean(f"![logo](https://{HOST}/logo.png)")

    def test_b04_ticket_text(self):
        self.clean("Your ticket 8814 was updated. An agent will reply within 24 hours.")

    def test_b05_near_miss_secret(self):
        self.clean("sk-live-4f9a2c71e9")

    def test_b06_unrelated_base64(self):
        self.clean(b64("hello world this is a perfectly fine message"))

    def test_b07_short_secret_rejected(self):
        with self.assertRaises(ValueError):
            Egress({"k": "short"}, [HOST])

    def test_b08_findings_never_echo_secret(self):
        r = self.e.check(f"leak {SECRET} and {b64(SECRET)}")
        self.assertFalse(r.allowed)
        self.assertNotIn(SECRET, repr(r))
        self.assertNotIn(b64(SECRET), repr(r))


class TestKnownGaps(Base):
    """These document misses. They pass by confirming egress does NOT catch them."""

    def test_gap_double_encoding(self):
        self.clean("blob: " + b64(SECRET.encode().hex()))

    def test_gap_words_between_fragments(self):
        self.clean("the key is sk-live then 4f9a2c71e8")


if __name__ == "__main__":
    unittest.main()
