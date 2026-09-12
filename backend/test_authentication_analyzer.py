import unittest

from app.analyzers.authentication_analyzer import analyze_headers_authentication


class TestAuthenticationAnalyzer(unittest.TestCase):

    def test_no_authentication_headers(self):
        headers = {
            "From": "security@example.com",
            "To": "analyst@example.com",
            "Subject": "Normal Email",
        }

        result = analyze_headers_authentication(headers)

        self.assertEqual(result["indicators"], [])
        self.assertEqual(result["risk_score"], 0)

    def test_spf_fail(self):
        headers = {
            "Authentication-Results":
                "mail.example.com; spf=fail smtp.mailfrom=evil.example.net"
        }

        result = analyze_headers_authentication(headers)

        self.assertIn("spf_fail", result["indicators"])
        self.assertEqual(result["risk_score"], 25)

    def test_dkim_fail(self):
        headers = {
            "Authentication-Results":
                "mail.example.com; dkim=fail header.d=evil.example.net"
        }

        result = analyze_headers_authentication(headers)

        self.assertIn("dkim_fail", result["indicators"])
        self.assertEqual(result["risk_score"], 25)

    def test_dmarc_fail(self):
        headers = {
            "Authentication-Results":
                "mail.example.com; dmarc=fail header.from=evil.example.net"
        }

        result = analyze_headers_authentication(headers)

        self.assertIn("dmarc_fail", result["indicators"])
        self.assertEqual(result["risk_score"], 30)

    def test_spf_dkim_dmarc_fail(self):
        headers = {
            "Authentication-Results":
                "mail.example.com; "
                "spf=fail smtp.mailfrom=evil.example.net; "
                "dkim=fail header.d=evil.example.net; "
                "dmarc=fail header.from=evil.example.net"
        }

        result = analyze_headers_authentication(headers)

        self.assertIn("spf_fail", result["indicators"])
        self.assertIn("dkim_fail", result["indicators"])
        self.assertIn("dmarc_fail", result["indicators"])

        self.assertEqual(result["risk_score"], 80)

    def test_spf_pass(self):
        headers = {
            "Authentication-Results":
                "mail.example.com; spf=pass smtp.mailfrom=example.com"
        }

        result = analyze_headers_authentication(headers)

        self.assertNotIn("spf_fail", result["indicators"])
        self.assertEqual(result["risk_score"], 0)

    def test_dkim_pass(self):
        headers = {
            "Authentication-Results":
                "mail.example.com; dkim=pass header.d=example.com"
        }

        result = analyze_headers_authentication(headers)

        self.assertNotIn("dkim_fail", result["indicators"])
        self.assertEqual(result["risk_score"], 0)

    def test_dmarc_pass(self):
        headers = {
            "Authentication-Results":
                "mail.example.com; dmarc=pass header.from=example.com"
        }

        result = analyze_headers_authentication(headers)

        self.assertNotIn("dmarc_fail", result["indicators"])
        self.assertEqual(result["risk_score"], 0)

    def test_mixed_authentication_results(self):
        headers = {
            "Authentication-Results":
                "mail.example.com; "
                "spf=fail smtp.mailfrom=evil.example.net; "
                "dkim=pass header.d=example.com; "
                "dmarc=fail header.from=evil.example.net"
        }

        result = analyze_headers_authentication(headers)

        self.assertIn("spf_fail", result["indicators"])
        self.assertNotIn("dkim_fail", result["indicators"])
        self.assertIn("dmarc_fail", result["indicators"])

        self.assertEqual(result["risk_score"], 55)


if __name__ == "__main__":
    unittest.main()
