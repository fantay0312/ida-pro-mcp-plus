"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import sys
import idaapi
import ida_kernwin
import ida_netnode
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


NETNODE_AUTOSTART = "$ ida_mcp.autostart"


def _get_autostart() -> bool:
    """Read the autostart preference from the IDB. Defaults to True."""
    node = ida_netnode.netnode(NETNODE_AUTOSTART)
    val = node.altval(0)  # 0 = not set, 1 = off, 2 = on
    return val != 1


def _set_autostart(enabled: bool):
    """Persist the autostart preference into the IDB."""
    node = ida_netnode.netnode(NETNODE_AUTOSTART, 0, True)
    node.altset(0, 1 if not enabled else 2)


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


CONFIG_ACTION_ID = "mcp:configure"
CONFIG_ACTION_LABEL = "MCP Configuration"


class MCPConfigForm(idaapi.Form):
    """Form to configure MCP server host and port."""

    def __init__(self, host: str, port: int, autostart: bool):
        form_str = r"""STARTITEM 0
MCP Server Configuration

<Host:{host}>
<Port:{port}>
<Autostart server when IDA opens:{autostart}>{checks}>
"""
        super().__init__(
            form_str,
            {
                "host": idaapi.Form.StringInput(value=host),
                "port": idaapi.Form.NumericInput(value=port, tp=idaapi.Form.FT_DEC),
                "checks": idaapi.Form.ChkGroupControl(("autostart",), value=1 if autostart else 0),
            },
        )


class MCPConfigHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "MCP"):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        old_host = self.plugin.host
        old_port = self.plugin.port
        old_autostart = self.plugin.autostart

        form = MCPConfigForm(self.plugin.host, self.plugin.port, self.plugin.autostart)
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            form.Free()
            return 0

        host = form.host.value
        port = form.port.value
        autostart = bool(form.checks.value & 1)
        form.Free()

        if port < 1 or port > 65535:
            print(f"[MCP] Invalid port: {port}")
            return 0

        if autostart != old_autostart:
            self.plugin.autostart = autostart
            _set_autostart(autostart)
            print(f"[MCP] Autostart {'enabled' if autostart else 'disabled'}")

        if host == old_host and port == old_port:
            if autostart == old_autostart:
                print(f"[MCP] Configuration unchanged: {host}:{port}")
            return 1

        self.plugin.host = host
        self.plugin.port = port
        print(f"[MCP] Configuration updated: {host}:{port}")

        # Apply new endpoint immediately if the server is running.
        if self.plugin.mcp is not None:
            print("[MCP] Applying configuration change without manual restart...")
            self.plugin.run(0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MCPUIHooks(ida_kernwin.UI_Hooks):
    """Defers menu attachment and autostart until the UI is fully ready."""

    def __init__(self, plugin: "MCP"):
        super().__init__()
        self.plugin = plugin

    def ready_to_run(self):
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/", CONFIG_ACTION_ID, idaapi.SETMENU_APP
        )
        if self.plugin.autostart:
            print("[MCP] Autostarting server...")
            self.plugin.run(0)
        self.unhook()


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 13337

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self.host = self.DEFAULT_HOST
        self.port = self.DEFAULT_PORT
        self.autostart = _get_autostart()

        if self.autostart:
            print("[MCP] Plugin loaded, server will start automatically")
        else:
            print(
                f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
            )

        # Register a separate menu item for host/port configuration
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                CONFIG_ACTION_ID,
                CONFIG_ACTION_LABEL,
                MCPConfigHandler(self),
            )
        )
        # Defer menu attachment and autostart until the UI is fully initialized
        self._ui_hooks = MCPUIHooks(self)
        self._ui_hooks.hook()

        return idaapi.PLUGIN_KEEP

    def _unregister_instance(self):
        port = getattr(self, "_registered_port", None)
        if port is not None:
            try:
                if TYPE_CHECKING:
                    from .ida_mcp.discovery import unregister_instance
                else:
                    from ida_mcp.discovery import unregister_instance
                unregister_instance(port)
            except Exception as e:
                print(f"[MCP] Instance unregistration failed: {e}")
            self._registered_port = None

    def run(self, arg):
        if self.mcp:
            self._unregister_instance()
            self.mcp.stop()
            self.mcp = None

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches, set_local_instance
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches, set_local_instance

        try:
            init_caches()
        except Exception as e:
            print(f"[MCP] Cache init failed: {e}")

        port = self.port
        max_port = port + 100
        while port < max_port:
            try:
                MCP_SERVER.serve(
                    self.host, port, request_handler=IdaMcpHttpRequestHandler
                )
                print(f"  Config: http://{self.host}:{port}/config.html")
                self.mcp = MCP_SERVER
                set_local_instance(self.host, port)
                self._register_instance(port)
                return
            except OSError as e:
                if e.errno in (48, 98, 10048):  # Address already in use
                    port += 1
                else:
                    raise
        print(f"[MCP] Error: No available port in range {self.port}-{max_port - 1}")

    def _register_instance(self, port: int):
        try:
            if TYPE_CHECKING:
                from .ida_mcp.discovery import register_instance
            else:
                from ida_mcp.discovery import register_instance
            import os
            import idc
            import ida_nalt
            binary = ida_nalt.get_root_filename() or ""
            idb_path = idc.get_idb_path() or ""
            file_path = register_instance(
                host=self.host,
                port=port,
                pid=os.getpid(),
                binary=binary,
                idb_path=idb_path,
            )
            self._registered_port = port
            print(f"[MCP] Registered instance: {binary} (pid={os.getpid()}, port={port})")
            print(f"  Discovery file: {file_path}")
        except Exception as e:
            import traceback
            print(f"[MCP] Instance registration failed: {e}")
            traceback.print_exc()

        # Also try to register with the Broker (if one is running)
        self._try_broker_connect(port)

    def _try_broker_connect(self, local_port: int):
        """Attempt to register this IDA instance with a running Broker server.

        This is best-effort: if no Broker is listening, it silently skips.
        When connected, the Broker can forward MCP requests to this instance
        via SSE, enabling multi-instance management.
        """
        try:
            if TYPE_CHECKING:
                from .ida_mcp.api_instances import (
                    connect_to_server,
                    get_registered_server_url,
                    is_connected,
                )
            else:
                from ida_mcp.api_instances import (
                    connect_to_server,
                    get_registered_server_url,
                    is_connected,
                )

            if is_connected():
                return

            import os
            import ida_nalt
            import ida_idp

            binary = ida_nalt.get_root_filename() or ""
            instance_id = f"ida-{os.getpid()}-{local_port}"

            arch_info = {}
            try:
                info = ida_idp.get_idp_desc()
                arch_info["processor"] = info if isinstance(info, str) else ""
            except Exception:
                pass

            def _handle_broker_request(request: dict) -> dict:
                """Forward a Broker request to the local MCP server."""
                import json
                import urllib.request
                body = json.dumps(request).encode("utf-8")
                req = urllib.request.Request(
                    f"http://127.0.0.1:{local_port}/mcp",
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=60) as resp:
                        return json.loads(resp.read().decode("utf-8"))
                except Exception as e:
                    return {
                        "jsonrpc": "2.0",
                        "error": {"code": -32000, "message": str(e)},
                        "id": request.get("id"),
                    }

            success = connect_to_server(
                instance_id=instance_id,
                instance_type="gui",
                name=binary,
                binary_path=ida_nalt.get_input_file_path() or "",
                arch_info=arch_info,
                on_mcp_request=_handle_broker_request,
                server_url=get_registered_server_url(),
            )
            if success:
                print(f"[MCP] Also registered with Broker for multi-instance management")
        except Exception:
            pass  # Broker not available, silently skip

    def term(self):
        if hasattr(self, "_ui_hooks"):
            self._ui_hooks.unhook()
        ida_kernwin.unregister_action(CONFIG_ACTION_ID)
        self._unregister_instance()
        if self.mcp:
            self.mcp.stop()


def PLUGIN_ENTRY():
    return MCP()

