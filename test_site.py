"""Checks that docs/ works as a static site on GitHub Pages.

Pages serves a project site from a subpath (/CyberToolkit/), so every
asset reference has to be relative. Runs with the standard library only.
"""

import re
import unittest
from pathlib import Path

DOCS = Path(__file__).resolve().parent / "docs"


class StaticSiteTests(unittest.TestCase):
    def setUp(self):
        self.html = (DOCS / "index.html").read_text(encoding="utf-8")

    def test_local_references_are_relative_and_exist(self):
        refs = re.findall(r'(?:src|href)="([^"#]+)"', self.html)
        local = [r for r in refs if not r.startswith(("http://", "https://", "mailto:"))]
        self.assertTrue(local)
        for ref in local:
            with self.subTest(ref=ref):
                self.assertFalse(ref.startswith("/"), "absolute paths break under the Pages subpath")
                self.assertTrue((DOCS / ref).is_file())

    def test_css_font_files_exist(self):
        css = (DOCS / "style.css").read_text(encoding="utf-8")
        refs = re.findall(r'url\("([^"]+)"\)', css)
        self.assertGreaterEqual(len(refs), 4)
        for ref in refs:
            with self.subTest(ref=ref):
                self.assertTrue((DOCS / ref).is_file())

    def test_meta_csp_allows_only_self_and_dns_over_https(self):
        csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', self.html).group(1)
        self.assertIn("default-src 'none'", csp)
        self.assertIn("connect-src 'self' https://cloudflare-dns.com", csp)

    def test_page_never_calls_an_absolute_api_path(self):
        js = (DOCS / "app.js").read_text(encoding="utf-8")
        self.assertNotIn('fetch("/api', js)
        self.assertNotIn("fetch(`/api", js)


if __name__ == "__main__":
    unittest.main()
