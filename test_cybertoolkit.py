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


if __name__ == "__main__":
    unittest.main()
