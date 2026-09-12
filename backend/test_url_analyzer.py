import unittest

from app.models.url_model import ExtractedURL
from app.analyzers.url_analyzer import analyze_url


class TestURLAnalyzer(unittest.TestCase):

    def create_url(
        self,
        raw_url,
        scheme,
        hostname,
        port=None,
        path="/"
    ):
        return ExtractedURL(
            raw_url=raw_url,
            source="test",
            scheme=scheme,
            hostname=hostname,
            port=port,
            path=path,
            visible_text=None,
            sources=["test"]
        )

    def test_http_url(self):
        url = self.create_url(
            "http://example.com/login",
            "http",
            "example.com",
            path="/login"
        )

        analyze_url(url)

        self.assertIn("uses_http", url.indicators)
        self.assertEqual(url.risk_score, 10)

    def test_ip_address(self):
        url = self.create_url(
            "http://192.0.2.10/login",
            "http",
            "192.0.2.10",
            path="/login"
        )

        analyze_url(url)

        self.assertIn("uses_http", url.indicators)
        self.assertIn("ip_address_hostname", url.indicators)
        self.assertEqual(url.risk_score, 30)

    def test_unusual_port(self):
        url = self.create_url(
            "http://example.com:8080/admin",
            "http",
            "example.com",
            port=8080,
            path="/admin"
        )

        analyze_url(url)

        self.assertIn("uses_http", url.indicators)
        self.assertIn("unusual_port", url.indicators)
        self.assertEqual(url.risk_score, 25)

    def test_at_symbol(self):
        url = self.create_url(
            "https://example.com@evil.example.net/login",
            "https",
            "evil.example.net",
            path="/login"
        )

        analyze_url(url)

        self.assertIn("contains_at_symbol", url.indicators)
        self.assertEqual(url.risk_score, 20)

    def test_percent_encoding(self):
        url = self.create_url(
            "https://example.com/%6c%6f%67%69%6e",
            "https",
            "example.com",
            path="/%6c%6f%67%69%6e"
        )

        analyze_url(url)

        self.assertIn("percent_encoded_url", url.indicators)
        self.assertEqual(url.risk_score, 10)

    def test_deep_subdomain(self):
        url = self.create_url(
            "https://login.security.account.example.com/",
            "https",
            "login.security.account.example.com",
            path="/"
        )

        analyze_url(url)

        self.assertIn("deep_subdomain", url.indicators)
        self.assertEqual(url.risk_score, 10)

    def test_suspicious_keyword_combination(self):
        url = self.create_url(
            "https://example.com/account/verify",
            "https",
            "example.com",
            path="/account/verify"
        )

        analyze_url(url)

        self.assertIn("suspicious_keyword", url.indicators)
        self.assertEqual(url.risk_score, 5)

    def test_redirect_parameter(self):
        url = self.create_url(
            "https://example.com/login?redirect=https://evil.example.net/login",
            "https",
            "example.com",
            path="/login"
        )

        analyze_url(url)

        self.assertIn("redirect_parameter", url.indicators)
        self.assertEqual(url.risk_score, 10)

    def test_many_query_parameters(self):
        url = self.create_url(
            "https://example.com/login?user=analyst&session=12345"
            "&tracking=abc123&source=email&campaign=test",
            "https",
            "example.com",
            path="/login"
        )

        analyze_url(url)

        self.assertIn("many_query_parameters", url.indicators)
        self.assertEqual(url.risk_score, 5)

    def test_long_url(self):
        long_path = "/" + ("a" * 160)

        url = self.create_url(
            "https://example.com" + long_path,
            "https",
            "example.com",
            path=long_path
        )

        analyze_url(url)

        self.assertIn("long_url", url.indicators)
        self.assertEqual(url.risk_score, 5)

    def test_https_normal_url(self):
        url = self.create_url(
            "https://example.com/",
            "https",
            "example.com",
            path="/"
        )

        analyze_url(url)

        self.assertEqual(url.indicators, [])
        self.assertEqual(url.risk_score, 0)


if __name__ == "__main__":
    unittest.main()
