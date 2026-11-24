import unittest

import detector


class DetectorTests(unittest.TestCase):
    def ids(self, text, kind="message"):
        return {f["id"] for f in detector.analyze(text, kind)["findings"]}

    def test_obvious_phishing_is_high(self):
        r = detector.analyze("URGENT: your account will be suspended. Verify your password at http://paypal-secure.xyz/login now!", "message")
        self.assertEqual(r["level"], "High")
        self.assertTrue({"brand_lookalike", "urgency", "sensitive"} <= self.ids("URGENT: verify your password at http://paypal-secure.xyz/login"))

    def test_ordinary_message_is_low(self):
        r = detector.analyze("Hi, lunch at noon? Notes are at https://zoom.us/j/12345", "message")
        self.assertEqual(r["level"], "Low")

    def test_link_checks(self):
        self.assertIn("ip_host", self.ids("http://192.168.4.20/login", "url"))
        self.assertIn("userinfo", self.ids("https://paypal.com@evil.example/", "url"))
        self.assertIn("punycode", self.ids("https://xn--pypal-4ve.com", "url"))
        self.assertIn("brand_lookalike", self.ids("paypa1-login.com", "url"))

    def test_real_brand_domain_not_flagged(self):
        self.assertNotIn("brand_lookalike", self.ids("https://www.paypal.com/signin", "url"))
        self.assertNotIn("brand_lookalike", self.ids("https://login.microsoftonline.com", "url"))

    def test_url_extraction_ignores_email_addresses(self):
        r = detector.analyze("Write to help@example.com or visit www.example.org/page.", "message")
        self.assertEqual(r["urls"], ["www.example.org/page"])


if __name__ == "__main__":
    unittest.main()
