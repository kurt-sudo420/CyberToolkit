import unittest
from unittest.mock import patch

import cybertoolkit as kit


class SecurityTests(unittest.TestCase):
    def test_supported_port_syntax(self):
        self.assertEqual(kit.parse_ports("443,80-78,79"), [78, 79, 80, 443])

    def test_invalid_ports_fail_as_a_unit(self):
        for spec in ("0", "80,70000", "80,", "1-10000000000000", "text"):
            with self.subTest(spec=spec):
                self.assertEqual(kit.parse_ports(spec), [])

    def test_password_length_is_bounded(self):
        with patch("builtins.input", return_value="1000000000"), patch("builtins.print") as output:
            kit.password_generator()
        self.assertEqual(len(output.call_args.args[0]), 256)

    def test_remote_banner_cannot_control_terminal(self):
        with patch("builtins.input", side_effect=["localhost", "22"]), patch("socket.socket") as sock:
            sock.return_value.__enter__.return_value.recv.return_value = b"SSH\x1b[2J\rspoof"
            with patch("builtins.print") as output:
                kit.banner_grab()
        self.assertEqual(output.call_args.args[0], "'SSH\\x1b[2J\\rspoof'")


class ParsePortsEdgeCases(unittest.TestCase):
    def test_duplicates_removed(self):
        self.assertEqual(kit.parse_ports("80,80,80"), [80])

    def test_whitespace_tolerated(self):
        self.assertEqual(kit.parse_ports(" 22 , 80 "), [22, 80])

    def test_result_is_sorted(self):
        self.assertEqual(kit.parse_ports("443,22,80"), [22, 80, 443])

    def test_full_range(self):
        self.assertEqual(kit.parse_ports("1-65535"), list(range(1, 65536)))

    def test_invalid_specs_rejected(self):
        for spec in ("", "abc", "80,abc", "1000-abc", "22,80,abc,8080", "65536-70000"):
            with self.subTest(spec=spec):
                self.assertEqual(kit.parse_ports(spec), [])


if __name__ == "__main__":
    unittest.main()
