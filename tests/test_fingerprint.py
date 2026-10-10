from netscan.fingerprint import guess_os, guess_service


class TestGuessService:
    def test_banner_beats_port_map(self):
        assert guess_service(22, "OpenSSH_8.9p1 Ubuntu") == "OpenSSH"

    def test_fallback_to_port_map(self):
        assert guess_service(3306, None) == "MySQL"

    def test_unknown(self):
        assert guess_service(49999, None) == "unknown"


class TestGuessOS:
    def test_linux_ttl(self):
        assert "Linux" in guess_os(64)

    def test_windows_ttl(self):
        assert "Windows" in guess_os(128)

    def test_unknown_ttl(self):
        assert guess_os(None) == "unknown"
