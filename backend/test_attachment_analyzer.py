import unittest

from app.analyzers.attachment_analyzer import analyze_attachment


class TestAttachmentAnalyzer(unittest.TestCase):

    def create_attachment(
        self,
        filename,
        mime_type="application/octet-stream",
        size=100
    ):
        return {
            "filename": filename,
            "mime_type": mime_type,
            "size": size,
            "sha256": "testhash123"
        }

    def test_safe_attachment(self):
        attachment = self.create_attachment(
            "report.pdf",
            "application/pdf"
        )

        result = analyze_attachment(attachment)

        self.assertEqual(result["indicators"], [])
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "LOW")

    def test_dangerous_extension(self):
        attachment = self.create_attachment(
            "malware.exe"
        )

        result = analyze_attachment(attachment)

        self.assertIn(
            "dangerous_extension",
            result["indicators"]
        )

        self.assertEqual(result["risk_score"], 30)
        self.assertEqual(result["risk_level"], "MEDIUM")

    def test_double_extension(self):
        attachment = self.create_attachment(
            "invoice.pdf.exe"
        )

        result = analyze_attachment(attachment)

        self.assertIn(
            "dangerous_extension",
            result["indicators"]
        )

        self.assertIn(
            "double_extension",
            result["indicators"]
        )

        self.assertIn(
            "suspicious_filename",
            result["indicators"]
        )

        self.assertEqual(result["risk_score"], 55)
        self.assertEqual(result["risk_level"], "HIGH")

    def test_suspicious_filename(self):
        attachment = self.create_attachment(
            "urgent_invoice.pdf",
            "application/pdf"
        )

        result = analyze_attachment(attachment)

        self.assertIn(
            "suspicious_filename",
            result["indicators"]
        )

        self.assertEqual(result["risk_score"], 5)
        self.assertEqual(result["risk_level"], "LOW")

    def test_dangerous_mime_type(self):
        attachment = self.create_attachment(
            "report.dat",
            "application/x-msdownload"
        )

        result = analyze_attachment(attachment)

        self.assertIn(
            "dangerous_mime_type",
            result["indicators"]
        )

        self.assertEqual(result["risk_score"], 15)
        self.assertEqual(result["risk_level"], "LOW")

    def test_dangerous_extension_and_mime(self):
        attachment = self.create_attachment(
            "security_update.exe",
            "application/x-msdownload"
        )

        result = analyze_attachment(attachment)

        self.assertIn(
            "dangerous_extension",
            result["indicators"]
        )

        self.assertIn(
            "suspicious_filename",
            result["indicators"]
        )

        self.assertIn(
            "dangerous_mime_type",
            result["indicators"]
        )

        self.assertEqual(result["risk_score"], 50)
        self.assertEqual(result["risk_level"], "HIGH")

    def test_multiple_attachment_indicators(self):
        attachment = self.create_attachment(
            "invoice.pdf.exe",
            "application/x-msdownload"
        )

        result = analyze_attachment(attachment)

        self.assertIn(
            "dangerous_extension",
            result["indicators"]
        )

        self.assertIn(
            "double_extension",
            result["indicators"]
        )

        self.assertIn(
            "suspicious_filename",
            result["indicators"]
        )

        self.assertIn(
            "dangerous_mime_type",
            result["indicators"]
        )

        self.assertEqual(result["risk_score"], 70)
        self.assertEqual(result["risk_level"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()


    def test_mime_extension_mismatch(self):
        attachment = self.create_attachment(
            "invoice.exe",
            "application/pdf"
        )

        result = analyze_attachment(attachment)

        self.assertIn(
            "mime_extension_mismatch",
            result["indicators"]
        )


    def test_safe_pdf_mime_match(self):
        attachment = self.create_attachment(
            "invoice.pdf",
            "application/pdf"
        )

        result = analyze_attachment(attachment)

        self.assertNotIn(
            "mime_extension_mismatch",
            result["indicators"]
        )


    def test_safe_executable_mime_match(self):
        attachment = self.create_attachment(
            "update.exe",
            "application/x-msdownload"
        )

        result = analyze_attachment(attachment)

        self.assertNotIn(
            "mime_extension_mismatch",
            result["indicators"]
        )
