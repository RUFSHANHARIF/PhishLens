import unittest

from app.analyzers.email_correlator import correlate_email_findings


class TestEmailCorrelator(unittest.TestCase):

    def test_no_findings(self):
        result = correlate_email_findings(
            [],
            [],
            {"indicators": [], "risk_score": 0},
            {"indicators": [], "risk_score": 0},
        )

        self.assertEqual(result["indicators"], [])
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["categories"], [])

    def test_url_only(self):
        url_results = [
            {
                "indicators": ["uses_http"],
                "risk_score": 10,
            }
        ]

        result = correlate_email_findings(
            url_results,
            [],
            {"indicators": [], "risk_score": 0},
            {"indicators": [], "risk_score": 0},
        )

        self.assertEqual(result["categories"], ["url"])
        self.assertEqual(result["indicators"], [])
        self.assertEqual(result["risk_score"], 0)

    def test_attachment_only(self):
        attachment_results = [
            {
                "filename": "invoice.exe",
                "indicators": ["dangerous_extension"],
                "risk_score": 30,
            }
        ]

        result = correlate_email_findings(
            [],
            attachment_results,
            {"indicators": [], "risk_score": 0},
            {"indicators": [], "risk_score": 0},
        )

        self.assertEqual(result["categories"], ["attachment"])
        self.assertEqual(result["indicators"], [])
        self.assertEqual(result["risk_score"], 0)

    def test_multiple_detection_categories(self):
        url_results = [
            {
                "indicators": ["uses_http"],
                "risk_score": 10,
            }
        ]

        attachment_results = [
            {
                "filename": "invoice.exe",
                "indicators": ["dangerous_extension"],
                "risk_score": 30,
            }
        ]

        result = correlate_email_findings(
            url_results,
            attachment_results,
            {"indicators": [], "risk_score": 0},
            {"indicators": [], "risk_score": 0},
        )

        self.assertEqual(
            result["categories"],
            ["url", "attachment"]
        )

        self.assertIn(
            "multiple_detection_categories",
            result["indicators"]
        )

        self.assertIn(
            "suspicious_url_and_attachment",
            result["indicators"]
        )

        self.assertEqual(result["risk_score"], 25)

    def test_header_authentication_correlation(self):
        header_results = {
            "indicators": ["reply_to_mismatch"],
            "risk_score": 20,
        }

        authentication_results = {
            "indicators": ["spf_fail"],
            "risk_score": 25,
        }

        result = correlate_email_findings(
            [],
            [],
            header_results,
            authentication_results,
        )

        self.assertEqual(
            result["categories"],
            ["header", "authentication"]
        )

        self.assertIn(
            "multiple_detection_categories",
            result["indicators"]
        )

        self.assertIn(
            "header_authentication_mismatch",
            result["indicators"]
        )

        self.assertEqual(result["risk_score"], 25)

    def test_three_layer_correlation(self):
        url_results = [
            {
                "indicators": ["uses_http"],
                "risk_score": 10,
            }
        ]

        attachment_results = [
            {
                "filename": "invoice.exe",
                "indicators": ["dangerous_extension"],
                "risk_score": 30,
            }
        ]

        header_results = {
            "indicators": ["reply_to_mismatch"],
            "risk_score": 20,
        }

        authentication_results = {
            "indicators": [],
            "risk_score": 0,
        }

        result = correlate_email_findings(
            url_results,
            attachment_results,
            header_results,
            authentication_results,
        )

        self.assertEqual(
            result["categories"],
            ["url", "attachment", "header"]
        )

        self.assertIn(
            "multiple_detection_categories",
            result["indicators"]
        )

        self.assertIn(
            "suspicious_url_and_attachment",
            result["indicators"]
        )

        self.assertIn(
            "multi_layer_phishing_evidence",
            result["indicators"]
        )

        self.assertEqual(result["risk_score"], 45)

    def test_all_four_categories(self):
        url_results = [
            {
                "indicators": ["uses_http"],
                "risk_score": 10,
            }
        ]

        attachment_results = [
            {
                "filename": "invoice.exe",
                "indicators": ["dangerous_extension"],
                "risk_score": 30,
            }
        ]

        header_results = {
            "indicators": ["reply_to_mismatch"],
            "risk_score": 20,
        }

        authentication_results = {
            "indicators": ["spf_fail"],
            "risk_score": 25,
        }

        result = correlate_email_findings(
            url_results,
            attachment_results,
            header_results,
            authentication_results,
        )

        self.assertEqual(
            result["categories"],
            [
                "url",
                "attachment",
                "header",
                "authentication"
            ]
        )

        self.assertIn(
            "multiple_detection_categories",
            result["indicators"]
        )

        self.assertIn(
            "suspicious_url_and_attachment",
            result["indicators"]
        )

        self.assertIn(
            "header_authentication_mismatch",
            result["indicators"]
        )

        self.assertIn(
            "multi_layer_phishing_evidence",
            result["indicators"]
        )

        self.assertEqual(result["risk_score"], 60)


if __name__ == "__main__":
    unittest.main()
