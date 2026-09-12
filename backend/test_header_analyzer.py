import unittest

from app.analyzers.header_analyzer import analyze_headers


class TestHeaderAnalyzer(unittest.TestCase):

    def test_normal_headers(self):
        headers = {
            "From": "security@example.com",
            "To": "analyst@example.com",
            "Subject": "Security Notification",
            "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
            "Message-ID": "<12345@example.com>",
        }

        result = analyze_headers(headers)

        self.assertEqual(result["indicators"], [])
        self.assertEqual(result["risk_score"], 0)

    def test_missing_from(self):
        headers = {
            "To": "analyst@example.com",
            "Subject": "Security Notification",
            "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
            "Message-ID": "<12345@example.com>",
        }

        result = analyze_headers(headers)

        self.assertIn("missing_from", result["indicators"])

    def test_missing_to(self):
        headers = {
            "From": "security@example.com",
            "Subject": "Security Notification",
            "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
            "Message-ID": "<12345@example.com>",
        }

        result = analyze_headers(headers)

        self.assertIn("missing_to", result["indicators"])

    def test_missing_subject(self):
        headers = {
            "From": "security@example.com",
            "To": "analyst@example.com",
            "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
            "Message-ID": "<12345@example.com>",
        }

        result = analyze_headers(headers)

        self.assertIn("missing_subject", result["indicators"])

    def test_missing_date(self):
        headers = {
            "From": "security@example.com",
            "To": "analyst@example.com",
            "Subject": "Security Notification",
            "Message-ID": "<12345@example.com>",
        }

        result = analyze_headers(headers)

        self.assertIn("missing_date", result["indicators"])

    def test_missing_message_id(self):
        headers = {
            "From": "security@example.com",
            "To": "analyst@example.com",
            "Subject": "Security Notification",
            "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
        }

        result = analyze_headers(headers)

        self.assertIn(
            "missing_message_id",
            result["indicators"]
        )

    def test_reply_to_mismatch(self):
        headers = {
            "From": "security@example.com",
            "To": "analyst@example.com",
            "Reply-To": "support@evil.example.net",
            "Subject": "Security Notification",
            "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
            "Message-ID": "<12345@example.com>",
        }

        result = analyze_headers(headers)

        self.assertIn(
            "reply_to_mismatch",
            result["indicators"]
        )

    def test_return_path_mismatch(self):
        headers = {
            "From": "security@example.com",
            "To": "analyst@example.com",
            "Return-Path": "<bounce@evil.example.net>",
            "Subject": "Security Notification",
            "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
            "Message-ID": "<12345@example.com>",
        }

        result = analyze_headers(headers)

        self.assertIn(
            "return_path_mismatch",
            result["indicators"]
        )

    def test_message_id_domain_mismatch(self):
        headers = {
            "From": "security@example.com",
            "To": "analyst@example.com",
            "Subject": "Security Notification",
            "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
            "Message-ID": "<12345@evil.example.net>",
        }

        result = analyze_headers(headers)

        self.assertIn(
            "message_id_domain_mismatch",
            result["indicators"]
        )

    def test_display_name_spoofing(self):
        headers = {
            "From": "Microsoft Security <security@evil.example.net>",
            "To": "analyst@example.com",
            "Subject": "Security Notification",
            "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
            "Message-ID": "<12345@evil.example.net>",
        }

        result = analyze_headers(headers)

        self.assertIn(
            "display_name_spoofing",
            result["indicators"]
        )

    def test_multiple_header_findings(self):
        headers = {
            "From": "Microsoft Security <security@evil.example.net>",
            "To": "analyst@example.com",
            "Reply-To": "support@another.example.net",
            "Return-Path": "<bounce@another.example.net>",
            "Subject": "Security Notification",
            "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
            "Message-ID": "<12345@another.example.net>",
        }

        result = analyze_headers(headers)

        self.assertIn(
            "reply_to_mismatch",
            result["indicators"]
        )

        self.assertIn(
            "return_path_mismatch",
            result["indicators"]
        )

        self.assertIn(
            "message_id_domain_mismatch",
            result["indicators"]
        )

        self.assertIn(
            "display_name_spoofing",
            result["indicators"]
        )


if __name__ == "__main__":
    unittest.main()
