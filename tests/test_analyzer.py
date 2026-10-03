import unittest

from phishlens.analyzer import analyze_email, analyze_url


class URLTests(unittest.TestCase):
    def test_https_normal_url_low(self):
        result = analyze_url("https://example.com/about")
        self.assertEqual(result["risk_level"], "low")
        self.assertEqual(result["findings"], [])

    def test_ip_host_flagged(self):
        result = analyze_url("http://192.0.2.10/login")
        codes = {item["code"] for item in result["findings"]}
        self.assertIn("IP_ADDRESS_HOST", codes)
        self.assertIn("HTTP_NOT_HTTPS", codes)

    def test_at_symbol_flagged(self):
        result = analyze_url("https://trusted.example@evil.example/path")
        self.assertIn("AT_SYMBOL", {item["code"] for item in result["findings"]})

    def test_shortener_flagged(self):
        result = analyze_url("https://bit.ly/abc")
        self.assertIn("URL_SHORTENER", {item["code"] for item in result["findings"]})

    def test_invalid_url_rejected(self):
        with self.assertRaises(ValueError):
            analyze_url("not a url with spaces")


class EmailTests(unittest.TestCase):
    def test_urgent_password_message(self):
        result = analyze_email("URGENT: verify your account immediately. Click the link and enter your password.")
        self.assertGreater(result["risk_score"], 0)
        codes = {item["code"] for item in result["findings"]}
        self.assertIn("URGENCY_LANGUAGE", codes)
        self.assertIn("SENSITIVE_INFORMATION_REQUEST", codes)

    def test_benign_text_has_no_findings(self):
        result = analyze_email("Hello, the team meeting is at 3 PM.")
        self.assertEqual(result["findings"], [])

    def test_empty_email_rejected(self):
        with self.assertRaises(ValueError):
            analyze_email("  ")


if __name__ == "__main__":
    unittest.main()
