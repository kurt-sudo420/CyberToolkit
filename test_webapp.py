import socket
import string
import unittest
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient

    from webapp import SYMBOLS, app
except ImportError:  # The CLI is stdlib-only; skip web tests without FastAPI.
    TestClient = None


@unittest.skipIf(TestClient is None, "pip install -r requirements.txt to run web tests")
class WebAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_health_check(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_dashboard_is_served_with_security_headers(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("CyberToolkit", response.text)
        self.assertIn("default-src 'none'", response.headers["content-security-policy"])
        self.assertEqual(response.headers["x-frame-options"], "DENY")

    def test_dashboard_assets_are_served(self):
        for path in ("/app.js", "/style.css", "/fonts/exo2-wght.woff2"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)

    def test_hash_text(self):
        response = self.client.post("/api/hash", json={"text": "abc"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["hash"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        self.assertEqual(response.json()["bytes"], 3)

    def test_hash_empty_string_is_valid(self):
        response = self.client.post("/api/hash", json={"text": ""})
        self.assertEqual(
            response.json()["hash"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_hash_rejects_missing_or_oversized_text(self):
        self.assertEqual(self.client.post("/api/hash", json={}).status_code, 422)
        too_big = {"text": "a" * 1_000_001}
        self.assertEqual(self.client.post("/api/hash", json=too_big).status_code, 422)

    def test_dns_lookup_success(self):
        fake = [
            (None, None, None, None, ("93.184.215.14", 0)),
            (None, None, None, None, ("2606:2800:21f:cb07:6820:80da:af6b:8b2c", 0, 0, 0)),
        ]
        with patch("socket.getaddrinfo", return_value=fake):
            response = self.client.get("/api/dns", params={"domain": "Example.com"})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["domain"], "example.com")
        self.assertEqual(body["ipv4"], ["93.184.215.14"])
        self.assertEqual(body["ipv6"], ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"])

    def test_dns_lookup_not_found_does_not_leak_errors(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("resolver internals")):
            response = self.client.get("/api/dns", params={"domain": "nope.invalid"})
        self.assertEqual(response.status_code, 404)
        self.assertNotIn("resolver internals", response.text)

    def test_dns_rejects_invalid_hostnames_before_resolving(self):
        for domain in ("localhost", "-bad.com", "a..b.com", "10.0.0.1", "ex ample.com", "x" * 64 + ".com"):
            with self.subTest(domain=domain), patch("socket.getaddrinfo") as resolver:
                response = self.client.get("/api/dns", params={"domain": domain})
                self.assertEqual(response.status_code, 422)
                resolver.assert_not_called()

    def test_generate_password(self):
        response = self.client.get("/api/password", params={"length": 12})
        self.assertEqual(response.status_code, 200)
        password = response.json()["password"]
        self.assertEqual(len(password), 12)
        self.assertTrue(any(c in string.ascii_lowercase for c in password))
        self.assertTrue(any(c in string.ascii_uppercase for c in password))
        self.assertTrue(any(c in string.digits for c in password))
        self.assertTrue(any(c in SYMBOLS for c in password))
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_password_length_matches_cli_bounds(self):
        self.assertEqual(len(self.client.get("/api/password").json()["password"]), 20)
        for length in (7, 257, 10**9):
            with self.subTest(length=length):
                self.assertEqual(self.client.get("/api/password", params={"length": length}).status_code, 422)


if __name__ == "__main__":
    unittest.main()
