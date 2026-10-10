"""Async engine tests use unittest.mock so they run under pytest OR plain python."""
import asyncio
from unittest import mock

from netscan.core.async_engine import scan_async


class _FakeWriter:
    def close(self):
        pass

    async def wait_closed(self):
        pass


def test_async_scan_reports_only_open_ports():
    open_ports = {22, 80}

    async def fake_open_connection(host, port):
        if port in open_ports:
            return None, _FakeWriter()
        raise ConnectionRefusedError

    with mock.patch("asyncio.open_connection", fake_open_connection):
        result = asyncio.run(scan_async("127.0.0.1", [22, 80, 443], timeout=0.1, concurrency=10))
    assert result == [22, 80]
