from netscan.vulns.local import check_banner


def test_vulnerable_openssh_detected():
    vulns = check_banner("OpenSSH_8.0p1", "OpenSSH")
    assert any("CVE-2023-38408" in v.name for v in vulns)
    assert vulns[0].severity == "High"


def test_patched_openssh_clean():
    assert check_banner("OpenSSH_9.6p1", "OpenSSH") == []


def test_vsftpd_backdoor_critical():
    vulns = check_banner("vsftpd 2.3.4", "vsftpd")
    assert len(vulns) == 1
    assert vulns[0].severity == "Critical"


def test_no_banner_no_findings():
    assert check_banner(None, "OpenSSH") == []
