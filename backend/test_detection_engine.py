import unittest

from app.analyzers.detection_engine import analyze_email


class TestDetectionEngine(unittest.TestCase):

    def create_email(
        self,
        body_text="",
        body_html="",
        headers=None,
        attachments=None
    ):
        return {
            "headers": headers or {},
            "body": {
                "plain_text": body_text,
                "html": body_html
            },
            "attachments": attachments or []
        }

    def test_clean_email(self):
        email = {
            "headers": {
                "From": "user@example.com",
                "To": "analyst@example.com",
                "Subject": "Normal Business Email",
                "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
                "Message-ID": "<normal@example.com>",
            },
            "body": {
                "plain_text": "Hello, this is a normal business email.",
                "html": ""
            },
            "attachments": []
        }

        result = analyze_email(email)

        self.assertEqual(result["overall_score"], 0)
        self.assertEqual(result["overall_risk"], "LOW")

    def test_http_url_detection(self):
        email = self.create_email(
            body_text="Please visit http://example.com/login"
        )

        result = analyze_email(email)

        self.assertGreater(
            result["overall_score"],
            0
        )

        self.assertIn(
            "uses_http",
            result["url_results"][0].indicators
        )

    def test_ip_address_url_detection(self):
        email = self.create_email(
            body_text="Login here: http://192.0.2.10/login"
        )

        result = analyze_email(email)

        self.assertIn(
            "ip_address_hostname",
            result["url_results"][0].indicators
        )

        self.assertEqual(
            result["url_results"][0].risk_score,
            30
        )

    def test_dangerous_attachment(self):
        email = self.create_email(
            attachments=[
                {
                    "filename": "Security_Update.exe",
                    "mime_type": "application/octet-stream",
                    "content": b"test executable"
                }
            ]
        )

        result = analyze_email(email)

        self.assertEqual(
            len(result["attachment_results"]),
            1
        )

        attachment = result["attachment_results"][0]

        self.assertIn(
            "dangerous_extension",
            attachment["indicators"]
        )

        self.assertIn(
            "suspicious_filename",
            attachment["indicators"]
        )

        self.assertEqual(
            attachment["risk_score"],
            35
        )

    def test_multiple_attachments(self):
        email = self.create_email(
            attachments=[
                {
                    "filename": "Security_Update.exe",
                    "mime_type": "application/octet-stream",
                    "content": b"test executable"
                },
                {
                    "filename": "Invoice.pdf.exe",
                    "mime_type": "application/octet-stream",
                    "content": b"another executable"
                }
            ]
        )

        result = analyze_email(email)

        self.assertEqual(
            len(result["attachment_results"]),
            2
        )

        self.assertGreater(
            result["overall_score"],
            35
        )

    def test_header_findings(self):
        email = self.create_email(
            headers={
                "From": "security@example.com",
                "To": "analyst@example.com",
                "Subject": "Security Alert",
                "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
                "Message-ID": "<test@example.com>",
                "Reply-To": "attacker@evil.example.net"
            }
        )

        result = analyze_email(email)

        self.assertIn(
            "reply_to_mismatch",
            result["header_results"]["indicators"]
        )

    def test_authentication_findings(self):
        email = self.create_email(
            headers={
                "From": "security@example.com",
                "To": "analyst@example.com",
                "Subject": "Authentication Test",
                "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
                "Message-ID": "<auth@example.com>",
                "Authentication-Results":
                    "example.com; spf=fail; dkim=fail; dmarc=fail"
            }
        )

        result = analyze_email(email)

        self.assertIn(
            "spf_fail",
            result["authentication_results"]["indicators"]
        )

        self.assertIn(
            "dkim_fail",
            result["authentication_results"]["indicators"]
        )

        self.assertIn(
            "dmarc_fail",
            result["authentication_results"]["indicators"]
        )

    def test_multi_layer_detection(self):
        email = self.create_email(
            body_text=(
                "Urgent security verification: "
                "http://192.0.2.10/login"
            ),
            headers={
                "From": "security@example.com",
                "To": "analyst@example.com",
                "Subject": "Security Alert",
                "Date": "Thu, 27 Aug 2026 10:00:00 +0530",
                "Message-ID": "<alert@example.com>",
                "Reply-To": "attacker@evil.example.net",
                "Authentication-Results":
                    "example.com; spf=fail; dkim=fail; dmarc=fail"
            },
            attachments=[
                {
                    "filename": "Security_Update.exe",
                    "mime_type": "application/octet-stream",
                    "content": b"test executable"
                }
            ]
        )

        result = analyze_email(email)

        self.assertGreater(
            result["overall_score"],
            0
        )

        self.assertEqual(
            result["overall_risk"],
            "CRITICAL"
        )

        self.assertGreaterEqual(
            len(result["correlation_results"]["categories"]),
            3
        )

        self.assertIn(
            "multiple_detection_categories",
            result["correlation_results"]["indicators"]
        )

        self.assertIn(
            "multi_layer_phishing_evidence",
            result["correlation_results"]["indicators"]
        )


if __name__ == "__main__":
    unittest.main()
