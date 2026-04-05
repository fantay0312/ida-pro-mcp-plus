import argparse
import http.client
import json
import os
import sys
import threading
import time
import traceback
from typing import Annotated, Any, TYPE_CHECKING, TypedDict
from urllib.parse import urlparse

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import McpServer
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer
    from zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse

    sys.path.pop(0)

try:
    from .installer import (
        list_available_clients,
        print_mcp_config,
        run_install_command,
        set_ida_rpc,
    )
except ImportError:
    from installer import (
        list_available_clients,
        print_mcp_config,
        run_install_command,
        set_ida_rpc,
    )

try:
    from .ida_mcp.discovery import discover_instances, probe_instance
except ImportError:
    try:
        from ida_mcp.discovery import discover_instances, probe_instance
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
        from discovery import discover_instances, probe_instance

        sys.path.pop(0)

class ProxyInstanceInfo(TypedDict, total=False):
    host: str
    port: int
    pid: int
    binary: str
    idb_path: str
    started_at: str
    reachable: bool
    active: bool


class ProxySelectResult(TypedDict, total=False):
    success: bool
    host: str
    port: int
    message: str
    error: str


class ProxyOpenFileResult(TypedDict, total=False):
    success: bool
    host: str
    port: int
    binary: str
    pid: int
    switched: bool
    message: str
    error: str
    result: Any


DEFAULT_IDA_HOST = "127.0.0.1"
DEFAULT_IDA_PORT = 13337
IDA_HOST = DEFAULT_IDA_HOST
IDA_PORT = DEFAULT_IDA_PORT

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch

LOCAL_TOOLS = {"list_instances", "select_instance", "open_file"}
_target_lock = threading.Lock()
_session_targets: dict[str, tuple[str, int]] = {}
_broker_instance_id: str | None = None
_broker_session_targets: dict[str, str] = {}


def _get_transport_session_key() -> str | None:
    return mcp.get_current_transport_session_id()


def _get_direct_target() -> tuple[str, int]:
    session_key = _get_transport_session_key()
    if session_key is not None:
        with _target_lock:
            target = _session_targets.get(session_key)
        if target is not None:
            return target
    return IDA_HOST, IDA_PORT


def _set_direct_target(host: str, port: int) -> None:
    global IDA_HOST, IDA_PORT

    session_key = _get_transport_session_key()
    if session_key is not None:
        with _target_lock:
            _session_targets[session_key] = (host, port)
        return

    IDA_HOST = host
    IDA_PORT = port
    set_ida_rpc(host, port)


def _clear_direct_target() -> None:
    global IDA_HOST, IDA_PORT

    session_key = _get_transport_session_key()
    if session_key is not None:
        with _target_lock:
            _session_targets.pop(session_key, None)
        return

    IDA_HOST = DEFAULT_IDA_HOST
    IDA_PORT = DEFAULT_IDA_PORT
    set_ida_rpc(IDA_HOST, IDA_PORT)


def _get_broker_target() -> str | None:
    session_key = _get_transport_session_key()
    if session_key is not None:
        with _target_lock:
            target = _broker_session_targets.get(session_key)
        if target is not None:
            return target
    return _broker_instance_id


def _set_broker_target(instance_id: str) -> None:
    global _broker_instance_id

    session_key = _get_transport_session_key()
    if session_key is not None:
        with _target_lock:
            _broker_session_targets[session_key] = instance_id
        return

    _broker_instance_id = instance_id


def _clear_broker_target() -> None:
    global _broker_instance_id

    session_key = _get_transport_session_key()
    if session_key is not None:
        with _target_lock:
            _broker_session_targets.pop(session_key, None)
        return

    _broker_instance_id = None


def _parse_broker_instance_id(instance_id: str) -> tuple[int | None, int | None]:
    parts = instance_id.rsplit("-", 2)
    if len(parts) != 3:
        return None, None
    try:
        return int(parts[1]), int(parts[2])
    except ValueError:
        return None, None


def _normalize_broker_instance(
    instance: dict[str, Any], active_instance_id: str | None
) -> ProxyInstanceInfo:
    instance_id = str(instance.get("instance_id", ""))
    parsed_pid, parsed_port = _parse_broker_instance_id(instance_id)
    host = str(instance.get("host") or DEFAULT_IDA_HOST)
    port = instance.get("port")
    if not isinstance(port, int):
        port = parsed_port
    pid = instance.get("pid")
    if not isinstance(pid, int):
        pid = parsed_pid
    binary = (
        instance.get("binary")
        or instance.get("name")
        or os.path.basename(str(instance.get("binary_path", "")))
        or instance_id
    )
    result: ProxyInstanceInfo = {
        "host": host,
        "reachable": True,
        "active": instance_id == active_instance_id,
    }
    if isinstance(port, int):
        result["port"] = port
    if isinstance(pid, int):
        result["pid"] = pid
    if binary:
        result["binary"] = str(binary)
    idb_path = instance.get("idb_path") or instance.get("binary_path")
    if isinstance(idb_path, str) and idb_path:
        result["idb_path"] = idb_path
    started_at = instance.get("started_at")
    if isinstance(started_at, str) and started_at:
        result["started_at"] = started_at
    return result


def _get_effective_broker_target() -> str | None:
    if _broker_client is None:
        return None
    selected = _get_broker_target()
    if selected is not None:
        return selected
    current = _broker_client.get_current()
    if isinstance(current, dict):
        instance_id = current.get("instance_id")
        if isinstance(instance_id, str) and instance_id:
            return instance_id
    return None


def _list_broker_instances_raw() -> list[dict[str, Any]]:
    if _broker_client is None:
        return []
    instances = _broker_client.list_instances()
    return [inst for inst in instances if isinstance(inst, dict)]


def _list_broker_instances() -> list[ProxyInstanceInfo]:
    active_instance_id = _get_effective_broker_target()
    return [
        _normalize_broker_instance(instance, active_instance_id)
        for instance in _list_broker_instances_raw()
    ]


def _find_broker_instance(host: str, port: int) -> dict[str, Any] | None:
    for instance in _list_broker_instances_raw():
        normalized = _normalize_broker_instance(instance, None)
        if normalized.get("host") == host and normalized.get("port") == port:
            return instance
    return None


def _extract_tool_result(response: dict[str, Any]) -> Any:
    if "error" in response:
        raise RuntimeError(response["error"].get("message", "Unknown error"))

    result = response.get("result", {})
    if result.get("isError"):
        content = result.get("content", [])
        message = (
            content[0].get("text", "Unknown tool error")
            if content
            else "Unknown tool error"
        )
        raise RuntimeError(message)
    return result.get("structuredContent")


def _get_proxy_request_path() -> str:
    """Build the proxied MCP path, preserving enabled extensions."""
    enabled = sorted(getattr(mcp._enabled_extensions, "data", set()))
    if enabled:
        return f"/mcp?ext={','.join(enabled)}"
    return "/mcp"


def _get_proxy_request_headers() -> dict[str, str]:
    """Build proxy request headers, preserving HTTP MCP session identity."""
    headers = {"Content-Type": "application/json"}
    transport_session_id = mcp.get_current_transport_session_id()
    if transport_session_id and transport_session_id.startswith("http:"):
        session_id = transport_session_id.split(":", 1)[1]
        if session_id and session_id != "anonymous":
            headers["Mcp-Session-Id"] = session_id
    return headers


def _proxy_to_instance(host: str, port: int, payload: bytes | str | dict) -> dict:
    """Send a JSON-RPC request to a specific IDA instance and return the response."""
    if isinstance(payload, dict):
        payload = json.dumps(payload)
    elif isinstance(payload, str):
        payload = payload.encode("utf-8")

    conn = http.client.HTTPConnection(host, port, timeout=30)
    try:
        conn.request(
            "POST",
            _get_proxy_request_path(),
            payload,
            _get_proxy_request_headers(),
        )
        response = conn.getresponse()
        raw_data = response.read().decode()
        if response.status >= 400:
            raise RuntimeError(
                f"HTTP {response.status} {response.reason}: {raw_data}"
            )
        return json.loads(raw_data)
    finally:
        conn.close()


_broker_client = None  # Set when running in --broker mode


def _proxy_to_ida(payload: bytes | str | dict) -> dict:
    """Send a JSON-RPC request to the active IDA instance and return the response.

    In broker mode, requests are forwarded through the BrokerClient's /api/request
    endpoint which uses SSE to reach the IDA instance. In standard mode, requests
    go directly to the IDA RPC HTTP server.
    """
    if _broker_client is not None:
        if isinstance(payload, (bytes, bytearray)):
            request = json.loads(payload)
        elif isinstance(payload, str):
            request = json.loads(payload)
        else:
            request = payload
        response = _broker_client.send_request(
            request,
            instance_id=_get_effective_broker_target(),
            timeout=60.0,
        )
        if response is None:
            raise RuntimeError(
                "Broker returned no response. Is an IDA instance connected? "
                "Press Ctrl+Alt+M in IDA to register with the broker."
            )
        return response
    host, port = _get_direct_target()
    return _proxy_to_instance(host, port, payload)


def _call_ida_tool(host: str, port: int, name: str, arguments: dict[str, Any]) -> Any:
    """Call an MCP tool on a specific IDA instance and return structured content."""
    response = _proxy_to_instance(
        host,
        port,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )
    return _extract_tool_result(response)


def _call_broker_tool(instance_id: str, name: str, arguments: dict[str, Any]) -> Any:
    """Call an MCP tool through the broker for a specific connected instance."""
    if _broker_client is None:
        raise RuntimeError("Broker client is not available")

    response = _broker_client.send_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
        instance_id=instance_id,
        timeout=60.0,
    )
    if response is None:
        raise RuntimeError("Broker returned no response")
    return _extract_tool_result(response)


def _resolve_broker_instance_id_from_result(
    result: dict[str, Any], wait_timeout_sec: int
) -> str | None:
    host = result.get("host")
    port = result.get("port")
    pid = result.get("pid")
    if not isinstance(host, str):
        host = DEFAULT_IDA_HOST

    deadline = time.monotonic() + max(0.0, min(float(wait_timeout_sec), 5.0))
    while True:
        for instance in _list_broker_instances_raw():
            normalized = _normalize_broker_instance(instance, None)
            if isinstance(port, int) and normalized.get("port") == port:
                return str(instance.get("instance_id", ""))
            if isinstance(pid, int) and normalized.get("pid") == pid:
                return str(instance.get("instance_id", ""))
            if (
                isinstance(port, int)
                and normalized.get("host") == host
                and normalized.get("port") == port
            ):
                return str(instance.get("instance_id", ""))
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.25)


def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests to the MCP server registry."""
    if not isinstance(request, dict):
        request_obj: JsonRpcRequest = json.loads(request)
    else:
        request_obj: JsonRpcRequest = request  # type: ignore

    if request_obj["method"] == "initialize":
        return dispatch_original(request)
    if request_obj["method"].startswith("notifications/"):
        return dispatch_original(request)

    # Handle local tools (instance discovery) without proxying to IDA
    if request_obj["method"] == "tools/call":
        params = request_obj.get("params", {})
        tool_name = params.get("name", "")
        if tool_name in LOCAL_TOOLS:
            return dispatch_original(request)

    # Handle tools/list locally: always include local tools, merge IDA tools when available
    if request_obj["method"] == "tools/list":
        # Get local tools (always available)
        local_result = dispatch_original(request)
        local_tool_names = (
            {t["name"] for t in local_result.get("result", {}).get("tools", [])}
            if local_result
            else set()
        )
        # Try to get IDA tools and merge them in
        try:
            ida_result = _proxy_to_ida(request)
            if ida_result and "result" in ida_result:
                # Filter out IDA tools that duplicate local tools (e.g. select_instance)
                ida_tools = [
                    t
                    for t in ida_result["result"].get("tools", [])
                    if t.get("name") not in local_tool_names
                ]
                if local_result and "result" in local_result:
                    local_result["result"]["tools"] = (
                        ida_tools + local_result["result"].get("tools", [])
                    )
        except Exception:
            pass  # IDA unreachable — local tools still work
        return local_result

    try:
        return _proxy_to_ida(request)
    except Exception as e:
        full_info = traceback.format_exc()
        request_id = request_obj.get("id")
        if request_id is None:
            return None  # Notification, no response needed

        shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"
        return JsonRpcResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": (
                        "Failed to complete request to IDA Pro. "
                        f"Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?\n"
                        "The request was not retried automatically. "
                        "If this was a mutating operation, verify IDA state before retrying.\n"
                        f"{full_info}"
                    ),
                    "data": str(e),
                },
                "id": request_id,
            }
        )


mcp.registry.dispatch = dispatch_proxy


# ============================================================================
# Local tools (handled by the proxy, not forwarded to IDA)
# ============================================================================


@mcp.tool
def list_instances() -> list[ProxyInstanceInfo]:
    """List discovered IDA Pro instances and indicate which one is active."""
    if _broker_client is not None:
        return _list_broker_instances()

    result = []
    active_host, active_port = _get_direct_target()
    for inst in discover_instances():
        reachable = probe_instance(inst["host"], inst["port"])
        result.append(
            {
                **inst,
                "reachable": reachable,
                "active": inst["host"] == active_host and inst["port"] == active_port,
            }
        )
    return result


@mcp.tool
def select_instance(
    port: Annotated[int, "Port number of the IDA instance to connect to"],
    host: Annotated[str, "Host address of the IDA instance"] = "127.0.0.1",
) -> ProxySelectResult:
    """Switch this MCP server to proxy requests to a different IDA Pro instance.

    Use list_instances first to see available instances, then select one by port.
    All subsequent tool calls will be routed to the selected instance.
    """
    if _broker_client is not None:
        if port == 0:
            _clear_broker_target()
            return {
                "success": True,
                "message": "Reset to broker default target",
            }

        instance = _find_broker_instance(host, port)
        if instance is None:
            return {
                "success": False,
                "error": f"Broker instance at {host}:{port} is not available",
            }

        instance_id = instance.get("instance_id")
        if not isinstance(instance_id, str) or not instance_id:
            return {
                "success": False,
                "error": f"Broker instance at {host}:{port} has no instance_id",
            }

        _set_broker_target(instance_id)
        return {
            "success": True,
            "host": host,
            "port": port,
            "message": f"Selected broker instance {instance_id}",
        }

    if port == 0:
        _clear_direct_target()
        return {
            "success": True,
            "host": DEFAULT_IDA_HOST,
            "port": DEFAULT_IDA_PORT,
            "message": "Reset to default IDA target",
        }
    if not probe_instance(host, port):
        return {"success": False, "error": f"Instance at {host}:{port} is not reachable"}
    _set_direct_target(host, port)
    return {"success": True, "host": host, "port": port}


@mcp.tool
def open_file(
    file_path: Annotated[
        str, "Absolute path to the binary file to open in a new IDA instance"
    ],
    switch: Annotated[
        bool, "Automatically switch to the new instance once it starts"
    ] = True,
    autonomous: Annotated[
        bool, "Run in autonomous mode (-A flag), suppressing all dialogs"
    ] = False,
    new_database: Annotated[
        bool, "Force creating a new database even if one exists"
    ] = False,
    timeout: Annotated[
        int, "Seconds to wait for the new instance to register (0 = don't wait)"
    ] = 30,
) -> ProxyOpenFileResult:
    """Open a file in a new IDA Pro instance.

    This proxy-side tool delegates to any reachable IDA instance's local open_file
    implementation so discovery/launch remains available even when the currently
    selected instance is down.
    """
    if _broker_client is not None:
        broker_instances = _list_broker_instances_raw()
        if not broker_instances:
            return {
                "success": False,
                "error": (
                    "No running IDA instance is available to launch a new file. "
                    "Start one instance first or connect one to the broker."
                ),
            }

        instance_id = _get_effective_broker_target()
        if instance_id is None:
            instance_id = str(broker_instances[0].get("instance_id", ""))

        if not instance_id:
            return {
                "success": False,
                "error": "Broker did not provide a usable instance_id",
            }

        try:
            result = _call_broker_tool(
                instance_id,
                "open_file",
                {
                    "file_path": file_path,
                    "switch": switch,
                    "autonomous": autonomous,
                    "new_database": new_database,
                    "timeout": timeout,
                },
            )
        except Exception as e:
            return {"success": False, "error": str(e)}

        if not isinstance(result, dict):
            return {"success": True, "result": result}

        if switch:
            launched_instance_id = _resolve_broker_instance_id_from_result(result, timeout)
            if launched_instance_id:
                _set_broker_target(launched_instance_id)
                result["switched"] = True
            else:
                result["switched"] = False
        return result

    target_host, target_port = _get_direct_target()
    if not probe_instance(target_host, target_port):
        target_host = ""
        target_port = 0
        for inst in discover_instances():
            if probe_instance(inst["host"], inst["port"]):
                target_host = inst["host"]
                target_port = inst["port"]
                break

    if not target_host or target_port == 0:
        return {
            "success": False,
            "error": (
                "No running IDA instance is available to launch a new file. "
                "Start one instance first or specify --ida-rpc explicitly."
            ),
        }

    try:
        result = _call_ida_tool(
            target_host,
            target_port,
            "open_file",
            {
                "file_path": file_path,
                "switch": switch,
                "autonomous": autonomous,
                "new_database": new_database,
                "timeout": timeout,
            },
        )
    except Exception as e:
        return {"success": False, "error": str(e)}

    return result if isinstance(result, dict) else {"success": True, "result": result}


# ============================================================================

DEFAULT_IDA_RPC = f"http://{IDA_HOST}:{IDA_PORT}"


def _resolve_ida_rpc(args) -> None:
    """Resolve the IDA RPC target: explicit --ida-rpc, or auto-discovery."""
    global IDA_HOST, IDA_PORT

    if args.ida_rpc is not None:
        # Explicit --ida-rpc: use directly (backwards compatible)
        ida_rpc = urlparse(args.ida_rpc)
        if ida_rpc.hostname is None or ida_rpc.port is None:
            raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
        IDA_HOST = ida_rpc.hostname
        IDA_PORT = ida_rpc.port
        set_ida_rpc(IDA_HOST, IDA_PORT)
        return

    # Auto-discover running IDA instances
    instances = discover_instances()
    if len(instances) == 0:
        print(
            f"[MCP] No IDA instances discovered, using default {IDA_HOST}:{IDA_PORT}",
            file=sys.stderr,
        )
    elif len(instances) == 1:
        inst = instances[0]
        IDA_HOST = inst["host"]
        IDA_PORT = inst["port"]
        print(
            f"[MCP] Auto-connected to: {inst['binary']} at {IDA_HOST}:{IDA_PORT}",
            file=sys.stderr,
        )
    else:
        print(f"[MCP] Found {len(instances)} IDA instances:", file=sys.stderr)
        for i, inst in enumerate(instances):
            print(f"  [{i}] {inst['binary']} at {inst['host']}:{inst['port']}", file=sys.stderr)
        inst = instances[0]
        IDA_HOST = inst["host"]
        IDA_PORT = inst["port"]
        print(
            f"[MCP] Auto-selected: {inst['binary']}. "
            "Use select_instance tool to switch.",
            file=sys.stderr,
        )

    set_ida_rpc(IDA_HOST, IDA_PORT)


def main():
    global IDA_HOST, IDA_PORT

    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument(
        "--install",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Install the MCP Server and IDA plugin. "
        "The IDA plugin is installed immediately. "
        "Optionally specify comma-separated client targets (e.g., 'claude,cursor'). "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--uninstall",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Uninstall the MCP Server and IDA plugin. "
        "The IDA plugin is uninstalled immediately. "
        "Optionally specify comma-separated client targets. "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="Allow installation despite IDA Free being installed",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default=None,
        help="MCP transport for install: 'streamable-http' (default), 'stdio', or 'sse'. "
        "For running: use stdio (default) or pass a URL (e.g., http://127.0.0.1:8744[/mcp|/sse])",
    )
    parser.add_argument(
        "--scope",
        type=str,
        choices=["global", "project"],
        default=None,
        help="Installation scope: 'project' (current directory, default) or 'global' (user-level)",
    )
    parser.add_argument(
        "--ida-rpc",
        type=str,
        default=None,
        help=f"IDA RPC server (default: auto-discover, fallback: {DEFAULT_IDA_RPC})",
    )
    parser.add_argument(
        "--config", action="store_true", help="Generate MCP config JSON"
    )
    parser.add_argument(
        "--list-clients",
        action="store_true",
        help="List all available MCP client targets",
    )
    parser.add_argument(
        "--broker",
        action="store_true",
        help="Start in Broker mode (HTTP+SSE server for multi-instance management). "
        "IDA instances connect to the broker via HTTP; MCP requests are forwarded via SSE.",
    )
    parser.add_argument(
        "--broker-port",
        type=int,
        default=13337,
        help="Broker server port (default: 13337)",
    )
    args = parser.parse_args()

    # Handle --list-clients independently
    if args.list_clients:
        list_available_clients()
        return

    # Resolve IDA RPC target (explicit or auto-discovery)
    # Skip in broker mode — the broker manages IDA instances via its own registry
    if not args.broker:
        _resolve_ida_rpc(args)

    is_install = args.install is not None
    is_uninstall = args.uninstall is not None

    # Validate flag combinations
    if args.scope and not (is_install or is_uninstall):
        print("--scope requires --install or --uninstall")
        return

    if is_install and is_uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if is_install or is_uninstall:
        run_install_command(
            uninstall=is_uninstall,
            targets_str=args.install if is_install else args.uninstall,
            args=args,
        )
        return

    if args.config:
        print_mcp_config()
        return

    # ------------------------------------------------------------------
    # Broker mode: start the HTTP+SSE broker server that IDA instances
    # connect to. MCP requests are forwarded to the active IDA instance
    # via SSE channels managed by the broker.
    # ------------------------------------------------------------------
    if args.broker:
        global _broker_client

        try:
            from .http_server import IDAHttpServer
            from .broker_client import BrokerClient
        except ImportError:
            from http_server import IDAHttpServer
            from broker_client import BrokerClient

        broker = IDAHttpServer(port=args.broker_port)
        print(
            f"[MCP] Starting Broker mode on port {args.broker_port}...",
            file=sys.stderr,
        )
        broker.start()

        # Wire up the broker client so _proxy_to_ida forwards through the
        # broker's /api/request endpoint instead of direct IDA HTTP RPC.
        _broker_client = BrokerClient(base_url=f"http://127.0.0.1:{args.broker_port}")
        try:
            transport = args.transport or "stdio"
            if transport == "stdio":
                mcp.stdio()
            else:
                url = urlparse(transport)
                if url.hostname is None or url.port is None:
                    raise Exception(f"Invalid transport URL: {args.transport}")
                mcp.serve(url.hostname, url.port)
                input("Broker + MCP server running. Press Enter or Ctrl+C to stop.")
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            broker.stop()
        return

    try:
        transport = args.transport or "stdio"
        if transport == "stdio":
            mcp.stdio()
        else:
            url = urlparse(transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            # NOTE: npx -y @modelcontextprotocol/inspector for debugging
            mcp.serve(url.hostname, url.port)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == "__main__":
    main()
