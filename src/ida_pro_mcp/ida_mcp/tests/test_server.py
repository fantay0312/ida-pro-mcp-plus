"""Tests for the top-level stdio proxy server (server.py) and unsafe tool gating."""

import contextlib
import os
import sys

from ..framework import test
from ..rpc import MCP_SERVER, MCP_UNSAFE

try:
    from ida_pro_mcp import server
except ImportError:
    _parent = os.path.join(os.path.dirname(__file__), "..", "..")
    sys.path.insert(0, _parent)
    try:
        import server  # type: ignore
    finally:
        sys.path.remove(_parent)


class _FakeHttpResponse:
    status = 200
    reason = "OK"

    def __init__(self, body=b'{"jsonrpc":"2.0","result":{}}'):
        self._body = body

    def read(self):
        return self._body


class _RecordingConnection:
    calls = []

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout

    def request(self, method, path, body=None, headers=None):
        self.__class__.calls.append(
            {
                "host": self.host,
                "port": self.port,
                "timeout": self.timeout,
                "method": method,
                "path": path,
                "body": body,
                "headers": headers or {},
            }
        )

    def getresponse(self):
        return _FakeHttpResponse()

    def close(self):
        pass


class _FakeBrokerClient:
    def __init__(self):
        self.requests = []
        self.instances = [
            {
                "instance_id": "ida-1001-11111",
                "name": "first",
                "binary_path": "/tmp/first.bin",
            },
            {
                "instance_id": "ida-1002-22222",
                "name": "second",
                "binary_path": "/tmp/second.bin",
            },
        ]
        self.current = self.instances[0]

    def list_instances(self):
        return [inst.copy() for inst in self.instances]

    def get_current(self):
        return self.current.copy()

    def send_request(self, request, instance_id=None, timeout=60.0):
        self.requests.append(
            {"request": request, "instance_id": instance_id, "timeout": timeout}
        )
        method = request.get("method")
        params = request.get("params", {})
        if method == "tools/call" and params.get("name") == "open_file":
            return {
                "jsonrpc": "2.0",
                "result": {
                    "structuredContent": {
                        "success": True,
                        "host": "127.0.0.1",
                        "port": 22222,
                        "pid": 1002,
                    }
                },
                "id": request.get("id"),
            }
        return {
            "jsonrpc": "2.0",
            "result": {"structuredContent": {"ok": True}},
            "id": request.get("id"),
        }


@contextlib.contextmanager
def _saved_target():
    """Preserve the currently selected IDA target across assertions."""
    old_host = server.IDA_HOST
    old_port = server.IDA_PORT
    old_session = getattr(server.mcp._transport_session_id, "data", None)
    old_exts = getattr(server.mcp._enabled_extensions, "data", set())
    old_session_targets = server._session_targets.copy()
    old_broker_client = server._broker_client
    old_broker_target = server._broker_instance_id
    old_broker_session_targets = server._broker_session_targets.copy()
    try:
        yield
    finally:
        server.IDA_HOST = old_host
        server.IDA_PORT = old_port
        server.mcp._transport_session_id.data = old_session
        server.mcp._enabled_extensions.data = old_exts
        server._session_targets.clear()
        server._session_targets.update(old_session_targets)
        server._broker_client = old_broker_client
        server._broker_instance_id = old_broker_target
        server._broker_session_targets.clear()
        server._broker_session_targets.update(old_broker_session_targets)


@test()
def test_tools_list_keeps_discovery_and_launch_tools_when_ida_unreachable():
    """tools/list should still expose local discovery/recovery tools when IDA is down."""
    with _saved_target():
        server.IDA_HOST = "127.0.0.1"
        server.IDA_PORT = 1  # unreachable
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        result = server.dispatch_proxy(req)
        assert "result" in result, f"Expected successful tools/list response, got: {result}"
        tool_names = {tool["name"] for tool in result["result"].get("tools", [])}
        assert "select_instance" in tool_names
        assert "list_instances" in tool_names
        assert "open_file" in tool_names


@test()
def test_server_proxy_to_instance_forwards_session_and_extensions():
    """Top-level proxy requests should preserve MCP session and enabled extensions."""
    with _saved_target():
        original_conn = server.http.client.HTTPConnection
        _RecordingConnection.calls = []
        server.http.client.HTTPConnection = _RecordingConnection
        server.mcp._transport_session_id.data = "http:session-456"
        server.mcp._enabled_extensions.data = {"dbg"}
        try:
            server._proxy_to_instance("127.0.0.1", 13337, b"{}")
            assert len(_RecordingConnection.calls) == 1
            call = _RecordingConnection.calls[0]
            assert call["path"] == "/mcp?ext=dbg"
            assert call["headers"].get("Mcp-Session-Id") == "session-456"
        finally:
            server.http.client.HTTPConnection = original_conn


@test()
def test_select_instance_is_scoped_to_transport_session():
    """HTTP transport sessions should not overwrite each other's selected direct target."""
    with _saved_target():
        original_probe = server.probe_instance
        server.probe_instance = lambda host, port: True
        try:
            server.mcp._transport_session_id.data = "http:session-a"
            result_a = server.select_instance(11111, "127.0.0.1")
            assert result_a["success"] is True

            server.mcp._transport_session_id.data = "http:session-b"
            result_b = server.select_instance(22222, "127.0.0.1")
            assert result_b["success"] is True

            server.mcp._transport_session_id.data = "http:session-a"
            assert server._get_direct_target() == ("127.0.0.1", 11111)

            server.mcp._transport_session_id.data = "http:session-b"
            assert server._get_direct_target() == ("127.0.0.1", 22222)
        finally:
            server.probe_instance = original_probe


@test()
def test_broker_instance_selection_is_scoped_to_transport_session():
    """Broker-mode proxying should send each HTTP session to its own selected instance."""
    with _saved_target():
        broker = _FakeBrokerClient()
        server._broker_client = broker

        server.mcp._transport_session_id.data = "http:session-a"
        result_a = server.select_instance(11111, "127.0.0.1")
        assert result_a["success"] is True
        server._proxy_to_ida(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}
        )

        server.mcp._transport_session_id.data = "http:session-b"
        result_b = server.select_instance(22222, "127.0.0.1")
        assert result_b["success"] is True
        server._proxy_to_ida(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {}}
        )

        assert broker.requests[0]["instance_id"] == "ida-1001-11111"
        assert broker.requests[1]["instance_id"] == "ida-1002-22222"


@test()
def test_broker_open_file_uses_broker_transport_and_switches_to_new_instance():
    """open_file should route through the broker and retarget to the launched instance."""
    with _saved_target():
        broker = _FakeBrokerClient()
        server._broker_client = broker
        server.mcp._transport_session_id.data = "http:session-a"
        result = server.open_file("/tmp/sample.bin", switch=True, timeout=0)
        assert result["success"] is True
        assert result["switched"] is True
        assert broker.requests[0]["request"]["params"]["name"] == "open_file"
        assert broker.requests[0]["instance_id"] == "ida-1001-11111"
        assert server._get_broker_target() == "ida-1002-22222"


# ---------------------------------------------------------------------------
# Unsafe tool gating (idalib registry-removal approach, mirrors idalib_server)
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _saved_tools():
    """Save and restore the tools registry so removal tests are non-destructive."""
    original = MCP_SERVER.tools.methods.copy()
    try:
        yield
    finally:
        MCP_SERVER.tools.methods = original


@test()
def test_unsafe_tools_registered():
    """@unsafe decorator should populate MCP_UNSAFE with known tool names."""
    assert len(MCP_UNSAFE) > 0, "MCP_UNSAFE is empty — no tools marked @unsafe"
    assert "py_eval" in MCP_UNSAFE, "py_eval should be marked @unsafe"
    assert "py_exec_file" in MCP_UNSAFE, "py_exec_file should be marked @unsafe"


@test()
def test_unsafe_tools_present_by_default():
    """Unsafe tools should be in the registry by default (plugin behavior)."""
    tool_names = set(MCP_SERVER.tools.methods)
    for name in ("py_eval", "py_exec_file"):
        assert name in tool_names, f"{name} should be present by default"


@test()
def test_unsafe_tools_hidden_after_removal():
    """tools/list should exclude tools removed from the registry (idalib --unsafe behavior)."""
    with _saved_tools():
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        result = MCP_SERVER._mcp_tools_list()
        tool_names = {t["name"] for t in result.get("tools", [])}
        leaked = MCP_UNSAFE & tool_names
        assert not leaked, f"Removed unsafe tools still listed: {leaked}"


@test()
def test_unsafe_tool_call_rejected_after_removal():
    """tools/call for a removed tool should return an error."""
    with _saved_tools():
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        result = MCP_SERVER._mcp_tools_call("py_eval", {"code": "pass"})
        assert result.get("isError"), f"Expected error for removed tool, got: {result}"


@test()
def test_safe_tools_unaffected_by_unsafe_removal():
    """Non-unsafe tools should remain callable after unsafe removal."""
    with _saved_tools():
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        assert "decompile" not in MCP_UNSAFE, "decompile should not be unsafe"
        assert "decompile" in MCP_SERVER.tools.methods, "decompile should survive removal"
