import pytest

from netscan.utils import parse_ports, validate_target


class TestValidateTarget:
    def test_single_ip(self):
        assert validate_target("192.168.1.1") is True

    def test_cidr(self):
        assert validate_target("10.0.0.0/24") is True

    def test_invalid(self):
        assert validate_target("not a host !!!") is False


class TestParsePorts:
    def test_single(self):
        assert parse_ports("22") == [22]

    def test_list_and_range(self):
        assert parse_ports("22,80,1-3") == [1, 2, 3, 22, 80]

    def test_dedup_and_sort(self):
        assert parse_ports("80,22,80") == [22, 80]

    def test_out_of_range_rejected(self):
        with pytest.raises(ValueError):
            parse_ports("70000")
