"""Bulk Export API - Export decompiled functions, strings, imports, and segments.

Inspired by IDA-NO-MCP (P4nda0s). These tools run inside IDA via the standard
@tool/@idasync pattern and write results to disk for offline AI analysis.
"""

import gc
import os
import time
from typing import Annotated, NotRequired, TypedDict

import ida_bytes
import ida_entry
import ida_funcs
import ida_hexrays
import ida_lines
import ida_nalt
import ida_segment
import ida_xref
import idautils
import idc

from .rpc import tool
from .sync import idasync
from .utils import parse_address


# ============================================================================
# TypedDict definitions
# ============================================================================


class BulkExportResult(TypedDict):
    output_dir: str
    total_functions: int
    exported: int
    fallback_disasm: int
    failed: int
    skipped: int
    elapsed_sec: float
    index_file: str


class ExportStringsResult(TypedDict):
    output_file: str
    total_strings: int
    elapsed_sec: float


class ExportImportsResult(TypedDict):
    imports_file: str
    exports_file: str
    total_imports: int
    total_exports: int
    elapsed_sec: float


class ExportSegmentsResult(TypedDict):
    output_file: str
    total_segments: int
    hexdump_segments: int
    elapsed_sec: float
    error: NotRequired[str]


# ============================================================================
# Internal helpers (ported from IDA-NO-MCP, adapted for the upstream style)
# ============================================================================


def _ensure_dir(path: str) -> None:
    """Create directory if it does not exist."""
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)


def _sanitize_filename(name: str) -> str:
    """Sanitize a function name so it can be used as a filename."""
    for ch in '<>:"/\\|?*':
        name = name.replace(ch, "_")
    name = name.replace(".", "_")
    if len(name) > 200:
        name = name[:200]
    return name


def _get_callers(func_ea: int) -> list[int]:
    """Return sorted unique list of caller function start addresses."""
    callers: list[int] = []
    for ref in idautils.XrefsTo(func_ea, 0):
        if idc.is_code(idc.get_full_flags(ref.frm)):
            caller_func = ida_funcs.get_func(ref.frm)
            if caller_func:
                callers.append(caller_func.start_ea)
    return sorted(set(callers))


def _get_callees(func_ea: int) -> list[int]:
    """Return sorted unique list of callee function start addresses."""
    callees: list[int] = []
    func = ida_funcs.get_func(func_ea)
    if not func:
        return callees
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.is_code(idc.get_full_flags(head)):
            for ref in idautils.XrefsFrom(head, 0):
                if ref.type in (ida_xref.fl_CF, ida_xref.fl_CN):
                    callee_func = ida_funcs.get_func(ref.to)
                    if callee_func:
                        callees.append(callee_func.start_ea)
    return sorted(set(callees))


def _format_addr_list(addrs: list[int]) -> str:
    """Format an address list as a comma-separated hex string."""
    if not addrs:
        return "none"
    return ", ".join(hex(a) for a in addrs)


def _generate_disassembly(func_ea: int) -> tuple[str | None, str | None]:
    """Generate disassembly text for a function. Returns (text, error)."""
    func = ida_funcs.get_func(func_ea)
    if not func:
        return None, "not a valid function"
    lines: list[str] = []
    for item_ea in idautils.FuncItems(func_ea):
        raw = ida_lines.generate_disasm_line(
            item_ea,
            ida_lines.GENDSM_FORCE_CODE | ida_lines.GENDSM_REMOVE_TAGS,
        )
        if raw is None:
            text = ""
        else:
            text = ida_lines.tag_remove(raw).rstrip()
        if not text:
            text = "<unable to render disassembly>"
        lines.append(f"{item_ea:X}: {text}")
    if not lines:
        return None, "function has no items"
    return "\n".join(lines), None


def _build_function_header(
    func_ea: int,
    func_name: str,
    source_type: str,
    callers: list[int],
    callees: list[int],
    fallback_reason: str | None = None,
) -> str:
    """Build the metadata comment header for a function export file."""
    parts = [
        "/*",
        f" * func-name: {func_name}",
        f" * func-address: {hex(func_ea)}",
        f" * export-type: {source_type}",
        f" * callers: {_format_addr_list(callers)}",
        f" * callees: {_format_addr_list(callees)}",
    ]
    if fallback_reason:
        parts.append(f" * fallback-reason: {fallback_reason}")
    parts.append(" */")
    parts.append("")
    return "\n".join(parts)


def _get_default_export_dir() -> str:
    """Derive an export directory next to the current IDB."""
    input_path = ida_nalt.get_input_file_path()
    if not input_path:
        try:
            import ida_loader
            input_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        except Exception:
            pass
    base_dir = os.path.dirname(input_path) if input_path else os.getcwd()
    module_name = ida_nalt.get_root_filename() or "unknown"
    return os.path.join(base_dir, f"{module_name}_export")


def _try_clear_hexrays_cache() -> None:
    """Try to clear the Hex-Rays cached cfuncs to save memory."""
    try:
        ida_hexrays.clear_cached_cfuncs()
    except Exception:
        pass


# ============================================================================
# MCP Tools
# ============================================================================


@tool
@idasync
def bulk_export(
    output_dir: Annotated[
        str,
        "Directory to write exported files. Defaults to <binary>_export/ next to IDB.",
    ] = "",
    skip_existing: Annotated[
        bool,
        "Skip functions whose output file already exists (for resumable export).",
    ] = True,
    skip_library: Annotated[
        bool,
        "Skip library functions (FUNC_LIB flag).",
    ] = True,
    memory_clean_interval: Annotated[
        int,
        "Run GC every N functions to reduce memory pressure. 0 disables.",
    ] = 50,
) -> BulkExportResult:
    """Export ALL decompiled functions to individual files on disk.

    Each function is written as a .c file (decompiled) or .asm file (disassembly
    fallback). A function_index.txt summary is also generated. This is useful for
    feeding an entire binary to an AI for analysis.

    The tool attempts Hex-Rays decompilation first. If that fails, it falls back
    to generating disassembly text. Library functions are skipped by default.
    """
    t0 = time.time()

    if not output_dir:
        output_dir = _get_default_export_dir()

    decompile_dir = os.path.join(output_dir, "decompile")
    disasm_dir = os.path.join(output_dir, "disassembly")
    _ensure_dir(decompile_dir)
    _ensure_dir(disasm_dir)

    all_funcs = list(idautils.Functions())
    total = len(all_funcs)
    exported = 0
    fallback_count = 0
    failed_count = 0
    skipped_count = 0
    index_lines: list[str] = []

    for idx, func_ea in enumerate(all_funcs):
        func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
        func = ida_funcs.get_func(func_ea)

        # Skip invalid or library functions
        if func is None:
            skipped_count += 1
            continue
        if skip_library and (func.flags & ida_funcs.FUNC_LIB):
            skipped_count += 1
            continue

        # Determine output paths
        c_path = os.path.join(decompile_dir, f"{func_ea:X}.c")
        asm_path = os.path.join(disasm_dir, f"{func_ea:X}.asm")

        if skip_existing and (os.path.exists(c_path) or os.path.exists(asm_path)):
            exported += 1
            rel = f"decompile/{func_ea:X}.c" if os.path.exists(c_path) else f"disassembly/{func_ea:X}.asm"
            index_lines.append(f"{hex(func_ea)}\t{func_name}\t{rel}\t(cached)")
            continue

        # Attempt decompilation
        dec_text: str | None = None
        fallback_reason: str | None = None

        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc is not None:
                dec_text = str(cfunc)
                cfunc = None  # release immediately
                if not dec_text or not dec_text.strip():
                    dec_text = None
                    fallback_reason = "empty decompilation result"
            else:
                fallback_reason = "decompile returned None"
        except ida_hexrays.DecompilationFailure as exc:
            fallback_reason = f"decompilation failure: {exc}"
        except Exception as exc:
            fallback_reason = f"unexpected error: {exc}"

        callers = _get_callers(func_ea)
        callees = _get_callees(func_ea)

        if dec_text is not None:
            # Write decompiled output
            header = _build_function_header(func_ea, func_name, "decompile", callers, callees)
            try:
                with open(c_path, "w", encoding="utf-8") as fh:
                    fh.write(header)
                    fh.write(dec_text)
                exported += 1
                index_lines.append(f"{hex(func_ea)}\t{func_name}\tdecompile/{func_ea:X}.c")
            except IOError:
                failed_count += 1
        else:
            # Fallback to disassembly
            disasm_text, disasm_err = _generate_disassembly(func_ea)
            if disasm_text is not None:
                header = _build_function_header(
                    func_ea, func_name, "disassembly-fallback", callers, callees, fallback_reason
                )
                try:
                    with open(asm_path, "w", encoding="utf-8") as fh:
                        fh.write(header)
                        fh.write(disasm_text)
                    fallback_count += 1
                    index_lines.append(f"{hex(func_ea)}\t{func_name}\tdisassembly/{func_ea:X}.asm\t{fallback_reason}")
                except IOError:
                    failed_count += 1
            else:
                failed_count += 1

        # Periodic memory cleanup
        if memory_clean_interval > 0 and (idx + 1) % memory_clean_interval == 0:
            _try_clear_hexrays_cache()
            gc.collect()

    # Write function index
    index_path = os.path.join(output_dir, "function_index.txt")
    with open(index_path, "w", encoding="utf-8") as fh:
        fh.write(f"# Function Index - {ida_nalt.get_root_filename()}\n")
        fh.write(f"# Total: {total}, Exported: {exported}, Fallback: {fallback_count}, "
                 f"Failed: {failed_count}, Skipped: {skipped_count}\n")
        fh.write("# address\tname\tfile\tnotes\n")
        for line in index_lines:
            fh.write(line + "\n")

    elapsed = round(time.time() - t0, 2)
    return {
        "output_dir": output_dir,
        "total_functions": total,
        "exported": exported,
        "fallback_disasm": fallback_count,
        "failed": failed_count,
        "skipped": skipped_count,
        "elapsed_sec": elapsed,
        "index_file": index_path,
    }


@tool
@idasync
def export_strings(
    output_file: Annotated[
        str,
        "Path to write strings output. Defaults to <binary>_export/strings.txt.",
    ] = "",
    min_length: Annotated[
        int,
        "Minimum string length to include (default: 4).",
    ] = 4,
) -> ExportStringsResult:
    """Export all strings from the binary to a text file.

    Each line contains: address<TAB>length<TAB>string_text
    """
    t0 = time.time()

    if not output_file:
        export_dir = _get_default_export_dir()
        _ensure_dir(export_dir)
        output_file = os.path.join(export_dir, "strings.txt")
    else:
        parent = os.path.dirname(output_file)
        if parent:
            _ensure_dir(parent)

    count = 0
    with open(output_file, "w", encoding="utf-8") as fh:
        fh.write(f"# Strings - {ida_nalt.get_root_filename()}\n")
        fh.write("# address\tlength\tstring\n")
        for s in idautils.Strings():
            if s is None:
                continue
            text = str(s)
            if len(text) < min_length:
                continue
            fh.write(f"{hex(s.ea)}\t{len(text)}\t{text}\n")
            count += 1

    elapsed = round(time.time() - t0, 2)
    return {
        "output_file": output_file,
        "total_strings": count,
        "elapsed_sec": elapsed,
    }


@tool
@idasync
def export_imports(
    output_dir: Annotated[
        str,
        "Directory for imports.txt and exports.txt. Defaults to <binary>_export/.",
    ] = "",
) -> ExportImportsResult:
    """Export the imports and exports tables to text files.

    imports.txt: address<TAB>module<TAB>name
    exports.txt: address<TAB>ordinal<TAB>name
    """
    t0 = time.time()

    if not output_dir:
        output_dir = _get_default_export_dir()
    _ensure_dir(output_dir)

    imports_path = os.path.join(output_dir, "imports.txt")
    exports_path = os.path.join(output_dir, "exports.txt")

    # Collect imports
    import_count = 0
    with open(imports_path, "w", encoding="utf-8") as fh:
        fh.write(f"# Imports - {ida_nalt.get_root_filename()}\n")
        fh.write("# address\tmodule\tname\n")
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i) or "<unnamed>"

            def _imp_cb(ea: int, name: str | None, ordinal: int) -> bool:
                nonlocal import_count
                symbol = name if name else f"#{ordinal}"
                fh.write(f"{hex(ea)}\t{module_name}\t{symbol}\n")
                import_count += 1
                return True

            ida_nalt.enum_import_names(i, _imp_cb)

    # Collect exports
    export_count = 0
    with open(exports_path, "w", encoding="utf-8") as fh:
        fh.write(f"# Exports - {ida_nalt.get_root_filename()}\n")
        fh.write("# address\tordinal\tname\n")
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal) or ""
            fh.write(f"{hex(ea)}\t{ordinal}\t{name}\n")
            export_count += 1

    elapsed = round(time.time() - t0, 2)
    return {
        "imports_file": imports_path,
        "exports_file": exports_path,
        "total_imports": import_count,
        "total_exports": export_count,
        "elapsed_sec": elapsed,
    }


@tool
@idasync
def export_segments(
    output_file: Annotated[
        str,
        "Path to write segment info. Defaults to <binary>_export/segments.txt.",
    ] = "",
    include_hexdump: Annotated[
        bool,
        "Include hex dump of each segment (can be very large).",
    ] = False,
    max_hexdump_size: Annotated[
        int,
        "Max bytes to hexdump per segment (default: 0x10000 = 64KB). 0 for unlimited.",
    ] = 0x10000,
) -> ExportSegmentsResult:
    """Export segment information from the binary.

    Writes segment name, start, end, size, permissions, and class for every
    segment. Optionally includes a hex dump of each segment's contents.
    """
    t0 = time.time()

    if not output_file:
        export_dir = _get_default_export_dir()
        _ensure_dir(export_dir)
        output_file = os.path.join(export_dir, "segments.txt")
    else:
        parent = os.path.dirname(output_file)
        if parent:
            _ensure_dir(parent)

    seg_count = 0
    hexdump_count = 0

    with open(output_file, "w", encoding="utf-8") as fh:
        fh.write(f"# Segments - {ida_nalt.get_root_filename()}\n\n")

        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue

            seg_name = ida_segment.get_segm_name(seg) or "<unnamed>"
            seg_class = ida_segment.get_segm_class(seg) or ""
            start = seg.start_ea
            end = seg.end_ea
            size = end - start

            # Permission flags
            perms = ""
            if seg.perm & ida_segment.SFL_LOADER:
                perms += "L"
            if seg.perm & 4:  # Read
                perms += "R"
            if seg.perm & 2:  # Write
                perms += "W"
            if seg.perm & 1:  # Execute
                perms += "X"
            if not perms:
                perms = "---"

            fh.write(f"[{seg_name}]\n")
            fh.write(f"  class:       {seg_class}\n")
            fh.write(f"  start:       {hex(start)}\n")
            fh.write(f"  end:         {hex(end)}\n")
            fh.write(f"  size:        {hex(size)} ({size} bytes)\n")
            fh.write(f"  permissions: {perms}\n")
            fh.write(f"  bitness:     {seg.abits()}-bit\n")

            if include_hexdump:
                dump_size = size
                if max_hexdump_size > 0 and dump_size > max_hexdump_size:
                    dump_size = max_hexdump_size
                    fh.write(f"  hexdump:     (first {hex(dump_size)} of {hex(size)} bytes)\n")
                else:
                    fh.write(f"  hexdump:\n")

                # Read bytes and format as hexdump
                for offset in range(0, dump_size, 16):
                    addr = start + offset
                    chunk_size = min(16, dump_size - offset)
                    raw = ida_bytes.get_bytes(addr, chunk_size)
                    if raw is None:
                        raw = b"\x00" * chunk_size

                    hex_part = " ".join(f"{b:02x}" for b in raw)
                    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
                    fh.write(f"    {addr:08X}: {hex_part:<48s}  {ascii_part}\n")

                hexdump_count += 1

            fh.write("\n")
            seg_count += 1

    elapsed = round(time.time() - t0, 2)
    return {
        "output_file": output_file,
        "total_segments": seg_count,
        "hexdump_segments": hexdump_count,
        "elapsed_sec": elapsed,
    }
