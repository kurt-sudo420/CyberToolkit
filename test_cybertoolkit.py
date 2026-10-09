"""Tests for the pure-logic parts of CyberToolkit.

The network functions (port_scanner, banner_grab, dns_lookup) are exercised
manually against a local listener rather than unit-tested here, since mocking
sockets adds more complexity than it's worth for a project this size.

Run with:  python -m pytest test_cybertoolkit.py -v
"""


from cybertoolkit import parse_ports


class TestParsePorts:
    def test_single_port(self):
        assert parse_ports("80") == [80]

    def test_comma_list(self):
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_range(self):
        assert parse_ports("1-5") == [1, 2, 3, 4, 5]

    def test_mixed(self):
        assert parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]

    def test_reversed_range_is_normalised(self):
        assert parse_ports("5-1") == [1, 2, 3, 4, 5]

    def test_duplicates_removed(self):
        assert parse_ports("80,80,80") == [80]

    def test_whitespace_tolerated(self):
        assert parse_ports(" 22 , 80 ") == [22, 80]

    def test_out_of_range_filtered(self):
        assert parse_ports("70000") == []
        assert parse_ports("0") == []

    def test_garbage_rejected(self):
        assert parse_ports("abc") == []

    def test_partial_garbage_rejected(self):
        assert parse_ports("80,abc") == []

    def test_empty(self):
        assert parse_ports("") == []

    def test_result_is_sorted(self):
        assert parse_ports("443,22,80") == [22, 80, 443]

    def test_invalid_range(self):
        assert parse_ports("1000-abc") == []

    def test_invalid_single_port(self):
        assert parse_ports("abc") == []

    def test_mixed_valid_invalid(self):
        assert parse_ports("22,80,abc,8080") == []

    def test_large_range(self):
        assert parse_ports("1-65535") == list(range(1, 65536))

    def test_large_invalid_range(self):
        assert parse_ports("65536-70000") == []
