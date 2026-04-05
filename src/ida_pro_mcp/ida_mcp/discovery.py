"""Instance discovery for IDA Pro MCP.

IDA plugin instances register themselves by writing JSON files to
{ida_user_dir}/mcp/instances/. The MCP server discovers running
instances by reading these files and validating PID liveness.
"""

import datetime
import glob
import json
import os
import socket
import sys
import tempfile
from typing import TypedDict


class InstanceInfo(TypedDict):
    host: str
    port: int
    pid: int
    binary: str
    idb_path: str
    started_at: str


def _get_ida_user_dir() -> str:
    if sys.platform == "win32":
        return os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro")
    return os.path.join(os.path.expanduser("~"), ".idapro")


def get_instances_dir() -> str:
    return os.path.join(_get_ida_user_dir(), "mcp", "instances")


def _instance_file_path(port: int) -> str:
    return os.path.join(get_instances_dir(), f"instance_{port}.json")


def _broker_file_path() -> str:
    return os.path.join(_get_ida_user_dir(), "mcp", "broker.json")


def register_instance(
    host: str, port: int, pid: int, binary: str, idb_path: str
) -> str:
    """Write an instance registration file. Returns the file path."""
    info: InstanceInfo = {
        "host": host,
        "port": port,
        "pid": pid,
        "binary": binary,
        "idb_path": idb_path,
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    instances_dir = get_instances_dir()
    os.makedirs(instances_dir, exist_ok=True)
    file_path = _instance_file_path(port)
    # Atomic write
    fd, tmp_path = tempfile.mkstemp(dir=instances_dir, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2)
        os.replace(tmp_path, file_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return file_path


def write_broker_endpoint(host: str, port: int) -> str:
    """Write the active broker endpoint so IDA plugins can discover it."""
    info = {
        "host": host,
        "port": port,
        "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    file_path = _broker_file_path()
    broker_dir = os.path.dirname(file_path)
    os.makedirs(broker_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=broker_dir, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2)
        os.replace(tmp_path, file_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return file_path


def read_broker_endpoint() -> tuple[str, int] | None:
    """Read the advertised broker endpoint if one is available."""
    file_path = _broker_file_path()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            info = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    host = info.get("host")
    port = info.get("port")
    if not isinstance(host, str) or not isinstance(port, int):
        return None
    return host, port


def clear_broker_endpoint(host: str | None = None, port: int | None = None) -> bool:
    """Remove the advertised broker endpoint if it matches the expected values."""
    file_path = _broker_file_path()
    current = read_broker_endpoint()
    if current is None:
        return False
    if host is not None and current[0] != host:
        return False
    if port is not None and current[1] != port:
        return False
    try:
        os.unlink(file_path)
        return True
    except OSError:
        return False


def unregister_instance(port: int) -> bool:
    """Remove an instance registration file. Returns True if removed."""
    file_path = _instance_file_path(port)
    try:
        os.unlink(file_path)
        return True
    except OSError:
        return False


def is_pid_alive(pid: int) -> bool:
    """Check if a process is still running."""
    if sys.platform == "win32":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            return True  # Process exists, we lack permission
        except ProcessLookupError:
            return False
        except OSError:
            return False


def probe_instance(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if an instance is reachable via TCP."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def discover_instances() -> list[InstanceInfo]:
    """Scan for registered instances, cleaning up stale entries."""
    instances_dir = get_instances_dir()
    if not os.path.isdir(instances_dir):
        return []

    result: list[InstanceInfo] = []
    pattern = os.path.join(instances_dir, "instance_*.json")
    for file_path in glob.glob(pattern):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                info: InstanceInfo = json.load(f)
        except (json.JSONDecodeError, OSError):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue

        if not all(k in info for k in ("host", "port", "pid")):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue

        if not is_pid_alive(info["pid"]):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue

        # Secondary check: verify the instance is actually listening.
        # Catches PID reuse (Windows can recycle PIDs quickly) and
        # cases where the process is alive but the server crashed.
        if not probe_instance(info["host"], info["port"], timeout=1.0):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue

        result.append(info)

    result.sort(key=lambda x: x.get("started_at", ""))
    return result
