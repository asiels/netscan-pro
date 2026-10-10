from netscan.core.models import HostResult, PortResult, PortState, Vulnerability


def test_open_port_count():
    host = HostResult(host="10.0.0.1", ports=[PortResult(port=22), PortResult(port=443)])
    assert host.open_port_count == 2


def test_roundtrip_serialisation():
    host = HostResult(
        host="10.0.0.1",
        os_guess="Linux/Unix (TTL<=64)",
        ports=[
            PortResult(
                port=22,
                service="OpenSSH",
                banner="OpenSSH_8.0p1",
                vulns=[Vulnerability(name="CVE-2023-38408", severity="High", description="x")],
            )
        ],
    )
    d = host.to_dict()
    assert d["host"] == "10.0.0.1"
    assert d["ports"][0]["vulns"][0]["name"] == "CVE-2023-38408"
    assert PortState.OPEN == "open"  # str-enum behaves like a string
