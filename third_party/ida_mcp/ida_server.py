#!/usr/bin/env python3
"""
IDA Pro MCP Server - Binary Analysis Tools for AI Agents

This MCP server wraps IDA Pro's analysis capabilities, exposing them as tools
that can be used by AI agents for automated binary analysis and vulnerability
discovery.

Supports Windows IDA from WSL with automatic path conversion.

Environment Variables:
    IDA_PATH: Path to IDA Pro executable (idat64.exe)
    IDA_MCP_DEBUG: Set to "1" to enable debug output

Tools:
    load_binary: Load a binary into IDA for analysis
    get_functions: List all functions with metadata
    disassemble_function: Get assembly for a specific function
    get_strings: Extract strings from the binary
    find_xrefs: Find cross-references to/from an address
"""

import sys
import os
import argparse
import json
import tempfile
import subprocess
import shutil
import re
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import time

# Try to import FastMCP for MCP protocol support
try:
    from mcp.server.fastmcp import FastMCP
    HAS_FASTMCP = True
except ImportError:
    HAS_FASTMCP = False

# Configuration
DEFAULT_PORT = 6666
DEFAULT_HOST = "127.0.0.1"
IDA_TIMEOUT = 300  # 5 minutes for IDA analysis

# Debug mode controlled by environment variable
DEBUG = os.environ.get("IDA_MCP_DEBUG", "").lower() in ("1", "true", "yes")


def _dbg(msg: str):
    """Debug print helper - only prints if IDA_MCP_DEBUG=1."""
    if DEBUG:
        print(f"[IDA_MCP_DEBUG] {msg}", flush=True)


def _info(msg: str):
    """Info print - always prints."""
    print(f"[IDA MCP] {msg}", flush=True)


@dataclass
class IDAConfig:
    """IDA Pro configuration."""
    ida_path: Optional[str] = None
    temp_dir: Optional[str] = None

    def __post_init__(self):
        if not self.ida_path:
            self.ida_path = self._detect_ida()
        # Always use Windows-accessible temp dir for Windows IDA
        if self.ida_path and self._is_windows_ida():
            self.temp_dir = "/mnt/c/temp/ida_mcp"
            os.makedirs(self.temp_dir, exist_ok=True)
        elif not self.temp_dir:
            self.temp_dir = tempfile.mkdtemp(prefix="ida_mcp_")

    def _is_windows_ida(self) -> bool:
        """Check if using Windows IDA from WSL."""
        return bool(self.ida_path and self.ida_path.startswith("/mnt/") and self.ida_path.endswith(".exe"))

    def _detect_ida(self) -> Optional[str]:
        """Try to find IDA Pro installation."""
        candidates = [
            # Environment variable (highest priority)
            os.environ.get("IDA_PATH", ""),
            os.environ.get("IDADIR", "") + "/idat64" if os.environ.get("IDADIR") else "",
            # Windows via WSL - User's specific installation
            "/mnt/c/Users/ChemistryKing/Desktop/IDA Professional 9.0/idat64.exe",
            "/mnt/c/Users/ChemistryKing/Desktop/IDA Professional 9.0/ida64.exe",
            # Windows via WSL - Common locations
            "/mnt/c/Program Files/IDA Pro 9.0/idat64.exe",
            "/mnt/c/Program Files/IDA Pro 8.4/idat64.exe",
            "/mnt/c/Program Files/IDA Pro/idat64.exe",
            # Linux native
            "/opt/ida/idat64",
            "/opt/ida-pro/idat64",
            os.path.expanduser("~/ida/idat64"),
        ]

        for path in candidates:
            if path and os.path.isfile(path):
                _info(f"Found IDA at: {path}")
                return path

        # Try PATH
        ida_in_path = shutil.which("idat64") or shutil.which("idat")
        if ida_in_path:
            _info(f"Found IDA in PATH: {ida_in_path}")
            return ida_in_path

        return None


class IDABridge:
    """Bridge to execute IDAPython scripts via IDA batch mode."""

    def __init__(self, config: IDAConfig):
        self.config = config
        self._current_binary: Optional[str] = None
        self._is_windows_ida = self._detect_windows_ida()

        _dbg(f"IDABridge initialized:")
        _dbg(f"  IDA Path: {self.config.ida_path}")
        _dbg(f"  Windows IDA: {self._is_windows_ida}")
        _dbg(f"  Temp Dir: {self.config.temp_dir}")

    def _detect_windows_ida(self) -> bool:
        """Check if we're using a Windows IDA from WSL."""
        if self.config.ida_path:
            return self.config.ida_path.startswith("/mnt/") and self.config.ida_path.endswith(".exe")
        return False

    def _wsl_to_windows_path(self, wsl_path: str) -> str:
        """Convert WSL path to Windows path for Windows IDA."""
        if not self._is_windows_ida:
            return wsl_path

        if wsl_path.startswith("/mnt/"):
            # /mnt/c/path -> C:\path
            parts = wsl_path[5:].split("/", 1)
            drive = parts[0].upper()
            rest = parts[1].replace("/", "\\") if len(parts) > 1 else ""
            return f"{drive}:\\{rest}"
        else:
            # Linux path -> WSL network path (\\wsl$\Ubuntu\...)
            distro = "Ubuntu"
            try:
                result = subprocess.run(["wsl.exe", "-l", "-q"], capture_output=True, text=True, timeout=5)
                lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
                if lines:
                    distro = lines[0]
            except Exception:
                pass
            path_converted = wsl_path.replace("/", "\\")
            return f"\\\\wsl$\\{distro}{path_converted}"

    def _run_ida_script(self, script_content: str, binary_path: Optional[str] = None,
                        keep_files: bool = False) -> Dict[str, Any]:
        """Run an IDAPython script via IDA batch mode."""
        if not self.config.ida_path:
            return {"error": "IDA Pro not found. Set IDA_PATH environment variable.", "success": False}

        if binary_path is None:
            binary_path = self._current_binary

        if not binary_path:
            return {"error": "No binary loaded. Use load_binary first.", "success": False}

        if not os.path.isfile(binary_path):
            return {"error": f"Binary not found: {binary_path}", "success": False}

        # Use Windows-accessible temp directory
        temp_dir = self.config.temp_dir
        os.makedirs(temp_dir, exist_ok=True)

        # Create unique filenames
        timestamp = int(time.time() * 1000)
        script_path = os.path.join(temp_dir, f"script_{timestamp}.py")
        output_path = os.path.join(temp_dir, f"output_{timestamp}.json")
        log_path = os.path.join(temp_dir, f"ida_{timestamp}.log")

        # Convert paths for Windows IDA
        if self._is_windows_ida:
            script_path_ida = self._wsl_to_windows_path(script_path)
            output_path_ida = self._wsl_to_windows_path(output_path)
            log_path_ida = self._wsl_to_windows_path(log_path)
            binary_path_ida = self._wsl_to_windows_path(binary_path)
        else:
            script_path_ida = script_path
            output_path_ida = output_path
            log_path_ida = log_path
            binary_path_ida = binary_path

        # Debug output
        _dbg("=" * 60)
        _dbg("IDA Script Execution")
        _dbg("=" * 60)
        _dbg(f"Windows IDA Mode: {self._is_windows_ida}")
        _dbg(f"Paths (WSL -> Windows):")
        _dbg(f"  Binary:  {binary_path}")
        _dbg(f"       ->  {binary_path_ida}")
        _dbg(f"  Script:  {script_path}")
        _dbg(f"       ->  {script_path_ida}")
        _dbg(f"  Output:  {output_path}")
        _dbg(f"       ->  {output_path_ida}")
        _dbg(f"  Log:     {log_path}")
        _dbg(f"       ->  {log_path_ida}")

        # Wrap script with output handling - IDA 9.0 compatible
        wrapped_script = f'''# IDA MCP Auto-generated Script
import json
import idc
import idaapi
import idautils
import ida_funcs
import ida_bytes
import ida_name
import ida_xref
import ida_ida

# Wait for auto-analysis to complete
idaapi.auto_wait()

try:
    # User script
{self._indent_script(script_content)}

    # Write result to output file
    with open(r"{output_path_ida}", "w") as f:
        json.dump({{"success": True, "data": result}}, f, indent=2, default=str)
except Exception as e:
    import traceback
    with open(r"{output_path_ida}", "w") as f:
        json.dump({{"success": False, "error": str(e), "traceback": traceback.format_exc()}}, f)

# Exit IDA
idc.qexit(0)
'''

        # Write script file
        with open(script_path, 'w') as f:
            f.write(wrapped_script)

        _dbg(f"Script written to: {script_path}")

        try:
            # Build command string with proper quoting for paths with spaces
            cmd_str = f'"{self.config.ida_path}" -A -S"{script_path_ida}" -L"{log_path_ida}" "{binary_path_ida}"'

            _dbg(f"Command line:")
            _dbg(f"  {cmd_str}")
            _dbg("")
            _info(f"Running IDA on: {os.path.basename(binary_path)}")

            # Run IDA with shell=True to handle quoting properly
            result = subprocess.run(
                cmd_str,
                shell=True,
                capture_output=True,
                text=True,
                timeout=IDA_TIMEOUT,
                cwd=temp_dir
            )

            _dbg(f"IDA Exit Code: {result.returncode}")
            if result.stdout:
                _dbg(f"IDA stdout: {result.stdout[:200]}")
            if result.stderr:
                _dbg(f"IDA stderr: {result.stderr[:200]}")

            # Read output
            if os.path.isfile(output_path):
                with open(output_path, 'r') as f:
                    output_data = json.load(f)
                _dbg(f"Output file exists: {output_path}")
                return output_data
            else:
                _dbg(f"Output file NOT found: {output_path}")
                # Try to read log for error info
                log_content = ""
                if os.path.isfile(log_path):
                    with open(log_path, 'r', errors='ignore') as f:
                        log_content = f.read()[-500:]
                return {
                    "error": "IDA script did not produce output",
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "log_tail": log_content,
                    "success": False
                }

        except subprocess.TimeoutExpired:
            return {"error": f"IDA analysis timed out after {IDA_TIMEOUT}s", "success": False}
        except Exception as e:
            return {"error": str(e), "success": False}
        finally:
            # Only cleanup if not keeping files
            if not keep_files:
                for f in [script_path, output_path]:
                    try:
                        if os.path.exists(f):
                            os.unlink(f)
                    except Exception:
                        pass
            else:
                _dbg(f"Keeping files for audit:")
                _dbg(f"  Script: {script_path}")
                _dbg(f"  Output: {output_path}")
                _dbg(f"  Log:    {log_path}")

    def _indent_script(self, script: str, indent: str = "    ") -> str:
        """Indent script content for embedding."""
        return "\n".join(indent + line for line in script.split("\n"))

    def load_binary(self, file_path: str) -> Dict[str, Any]:
        """Load a binary into IDA for analysis."""
        if not os.path.isfile(file_path):
            return {"error": f"File not found: {file_path}", "success": False}

        self._current_binary = os.path.abspath(file_path)

        # IDA 9.0 compatible script
        script = '''
result = {
    "file_path": idc.get_input_file_path(),
    "file_type": idaapi.get_file_type_name(),
    "processor": idaapi.get_idp_name(),
    "bits": 64 if ida_ida.inf_is_64bit() else 32,
    "entry_point": hex(ida_ida.inf_get_start_ea()),
    "num_functions": len(list(idautils.Functions())),
    "num_segments": idaapi.get_segm_qty(),
}
'''
        result = self._run_ida_script(script, file_path, keep_files=DEBUG)
        if result.get("success"):
            _info(f"Loaded binary: {file_path}")
        return result

    def get_functions(self, filter_pattern: Optional[str] = None) -> Dict[str, Any]:
        """Get list of all functions in the binary."""
        filter_code = ""
        if filter_pattern:
            filter_code = f'''
import re
pattern = re.compile(r"{filter_pattern}")
'''

        script = f'''
{filter_code}
functions = []
for func_ea in idautils.Functions():
    func = ida_funcs.get_func(func_ea)
    if func:
        name = ida_name.get_name(func_ea)
        {"if not pattern.search(name): continue" if filter_pattern else ""}
        functions.append({{
            "address": hex(func_ea),
            "name": name,
            "size": func.size(),
            "flags": hex(func.flags),
            "is_library": bool(func.flags & ida_funcs.FUNC_LIB),
        }})

result = {{
    "count": len(functions),
    "functions": functions
}}
'''
        return self._run_ida_script(script, keep_files=DEBUG)

    def disassemble_function(self, address: str) -> Dict[str, Any]:
        """Disassemble a function at the given address or by name."""
        script = f'''
# Parse address - can be hex string or function name
addr_str = "{address}"
if addr_str.startswith("0x") or addr_str.startswith("0X"):
    func_ea = int(addr_str, 16)
else:
    # Try to find by name
    func_ea = ida_name.get_name_ea(idc.BADADDR, addr_str)
    if func_ea == idc.BADADDR:
        try:
            func_ea = int(addr_str)
        except:
            raise ValueError(f"Function not found: {{addr_str}}")

func = ida_funcs.get_func(func_ea)
if not func:
    raise ValueError(f"No function at address: {{hex(func_ea)}}")

# Get disassembly
disasm_lines = []
ea = func.start_ea
while ea < func.end_ea:
    disasm = idc.generate_disasm_line(ea, 0)
    mnem = idc.print_insn_mnem(ea)
    ops = idc.print_operand(ea, 0)
    if idc.print_operand(ea, 1):
        ops += ", " + idc.print_operand(ea, 1)

    disasm_lines.append({{
        "address": hex(ea),
        "bytes": ida_bytes.get_bytes(ea, idc.get_item_size(ea)).hex(),
        "mnemonic": mnem,
        "operands": ops,
        "disasm": disasm,
    }})
    ea = idc.next_head(ea)

# Identify dangerous patterns
dangerous_calls = []
dangerous_functions = ["strcpy", "strcat", "sprintf", "gets", "scanf", "printf", "system", "exec"]
for line in disasm_lines:
    if line["mnemonic"] == "call":
        for dangerous in dangerous_functions:
            if dangerous in line["operands"].lower():
                dangerous_calls.append({{
                    "address": line["address"],
                    "function": dangerous,
                    "context": line["disasm"]
                }})

result = {{
    "function_name": ida_name.get_name(func_ea),
    "start_address": hex(func.start_ea),
    "end_address": hex(func.end_ea),
    "size": func.size(),
    "disassembly": disasm_lines,
    "instruction_count": len(disasm_lines),
    "dangerous_calls": dangerous_calls,
}}
'''
        return self._run_ida_script(script, keep_files=DEBUG)

    def get_strings(self, min_length: int = 4) -> Dict[str, Any]:
        """Extract strings from the binary."""
        script = f'''
strings = []
for s in idautils.Strings():
    if s.length >= {min_length}:
        content = str(s)
        strings.append({{
            "address": hex(s.ea),
            "length": s.length,
            "type": "unicode" if s.strtype == idc.STRTYPE_C_16 else "ascii",
            "content": content,
        }})

strings.sort(key=lambda x: int(x["address"], 16))

format_strings = [s for s in strings if "%" in s["content"]]
paths = [s for s in strings if "/" in s["content"] or "\\\\" in s["content"]]

result = {{
    "count": len(strings),
    "strings": strings[:500],
    "format_strings": format_strings[:50],
    "paths": paths[:50],
}}
'''
        return self._run_ida_script(script, keep_files=DEBUG)

    def find_xrefs(self, address: str, direction: str = "both") -> Dict[str, Any]:
        """Find cross-references to/from an address."""
        script = f'''
addr_str = "{address}"
if addr_str.startswith("0x") or addr_str.startswith("0X"):
    target_ea = int(addr_str, 16)
else:
    target_ea = ida_name.get_name_ea(idc.BADADDR, addr_str)
    if target_ea == idc.BADADDR:
        try:
            target_ea = int(addr_str)
        except:
            raise ValueError(f"Address/name not found: {{addr_str}}")

direction = "{direction}"
xrefs_to = []
xrefs_from = []

if direction in ["to", "both"]:
    for xref in idautils.XrefsTo(target_ea):
        func = ida_funcs.get_func(xref.frm)
        func_name = ida_name.get_name(func.start_ea) if func else "unknown"
        xrefs_to.append({{
            "from_address": hex(xref.frm),
            "from_function": func_name,
            "type": ida_xref.get_xref_type_name(xref.type),
        }})

if direction in ["from", "both"]:
    for xref in idautils.XrefsFrom(target_ea):
        target_name = ida_name.get_name(xref.to) or hex(xref.to)
        xrefs_from.append({{
            "to_address": hex(xref.to),
            "to_name": target_name,
            "type": ida_xref.get_xref_type_name(xref.type),
        }})

result = {{
    "target": hex(target_ea),
    "target_name": ida_name.get_name(target_ea) or "unknown",
    "xrefs_to": xrefs_to,
    "xrefs_from": xrefs_from,
    "xrefs_to_count": len(xrefs_to),
    "xrefs_from_count": len(xrefs_from),
}}
'''
        return self._run_ida_script(script, keep_files=DEBUG)


# Global IDA bridge instance
ida_bridge: Optional[IDABridge] = None


def create_mcp_server() -> 'FastMCP':
    """Create the MCP server with IDA tools."""
    global ida_bridge

    if not HAS_FASTMCP:
        raise ImportError("FastMCP is required. Install with: pip install mcp")

    mcp = FastMCP("ida-mcp")
    config = IDAConfig()
    ida_bridge = IDABridge(config)

    @mcp.tool()
    def load_binary(file_path: str) -> Dict[str, Any]:
        """
        Load a binary file into IDA Pro for analysis.
        This must be called first before using other analysis tools.

        Args:
            file_path: Absolute path to the binary file to analyze

        Returns:
            Binary metadata including file type, architecture, entry point, etc.
        """
        _info(f"Tool: load_binary({file_path})")
        return ida_bridge.load_binary(file_path)

    @mcp.tool()
    def get_functions(filter: str = "") -> Dict[str, Any]:
        """
        List all functions in the loaded binary.

        Args:
            filter: Optional regex pattern to filter function names

        Returns:
            List of functions with addresses, names, sizes, and flags
        """
        _info(f"Tool: get_functions(filter={filter or 'none'})")
        return ida_bridge.get_functions(filter if filter else None)

    @mcp.tool()
    def disassemble_function(address: str) -> Dict[str, Any]:
        """
        Disassemble a function and identify dangerous patterns.
        Automatically detects calls to dangerous functions like strcpy, sprintf, printf, etc.

        Args:
            address: Function address (hex like 0x401000) or function name

        Returns:
            Assembly listing with instruction details and dangerous call detection
        """
        _info(f"Tool: disassemble_function({address})")
        result = ida_bridge.disassemble_function(address)

        # Print evidence to terminal for observability
        if result.get("success") and result.get("data"):
            data = result["data"]
            func_name = data.get("function_name", "unknown")
            dangerous = data.get("dangerous_calls", [])

            if dangerous:
                _info(f"  DANGEROUS CALLS in {func_name}:")
                for call in dangerous:
                    _info(f"    {call['address']}: {call['context']}")

            # Print disassembly snippet
            disasm = data.get("disassembly", [])
            if disasm:
                _info(f"  Disassembly of {func_name} ({len(disasm)} instructions):")
                for line in disasm[:20]:  # First 20 lines
                    _info(f"    {line['address']}: {line['disasm']}")
                if len(disasm) > 20:
                    _info(f"    ... ({len(disasm) - 20} more instructions)")

        return result

    @mcp.tool()
    def get_strings(min_length: int = 4) -> Dict[str, Any]:
        """
        Extract strings from the binary.

        Args:
            min_length: Minimum string length to include (default: 4)

        Returns:
            List of strings with addresses and categorization
        """
        _info(f"Tool: get_strings(min_length={min_length})")
        return ida_bridge.get_strings(min_length)

    @mcp.tool()
    def find_xrefs(address: str, direction: str = "both") -> Dict[str, Any]:
        """
        Find cross-references to and from an address.

        Args:
            address: Target address (hex) or symbol name
            direction: "to" (references to), "from" (references from), or "both"

        Returns:
            Lists of cross-references with source/target information
        """
        _info(f"Tool: find_xrefs({address}, direction={direction})")
        return ida_bridge.find_xrefs(address, direction)

    return mcp


def run_self_test(binary_path: str, ida_path: Optional[str] = None) -> bool:
    """Run comprehensive self-test with vulnerability detection."""

    print("=" * 70)
    print("IDA MCP Server Self-Test (with Vulnerability Detection)")
    print("=" * 70)

    # Enable debug for self-test
    global DEBUG
    DEBUG = True

    if ida_path:
        os.environ["IDA_PATH"] = ida_path

    config = IDAConfig()

    print(f"\n[CONFIG]")
    print(f"  IDA Path:     {config.ida_path}")
    print(f"  Temp Dir:     {config.temp_dir}")
    print(f"  Binary:       {binary_path}")

    if not config.ida_path:
        print("\n[ERROR] IDA Pro not found!")
        return False

    if not os.path.isfile(config.ida_path):
        print(f"\n[ERROR] IDA executable not found: {config.ida_path}")
        return False

    if not os.path.isfile(binary_path):
        print(f"\n[ERROR] Binary not found: {binary_path}")
        return False

    bridge = IDABridge(config)
    print(f"  Windows IDA:  {bridge._is_windows_ida}")

    # Setup test directory
    test_dir = "/mnt/c/temp/ida_mcp_test"
    os.makedirs(test_dir, exist_ok=True)

    script_path = os.path.join(test_dir, "test_script.py")
    output_path = os.path.join(test_dir, "test_output.json")
    log_path = os.path.join(test_dir, "test_ida.log")

    # Convert paths
    if bridge._is_windows_ida:
        script_path_ida = bridge._wsl_to_windows_path(script_path)
        output_path_ida = bridge._wsl_to_windows_path(output_path)
        log_path_ida = bridge._wsl_to_windows_path(log_path)
        binary_path_ida = bridge._wsl_to_windows_path(binary_path)
    else:
        script_path_ida = script_path
        output_path_ida = output_path
        log_path_ida = log_path
        binary_path_ida = binary_path

    print(f"\n[PATH CONVERSION]")
    print(f"  Binary (WSL):   {binary_path}")
    print(f"  Binary (Win):   {binary_path_ida}")
    print(f"  Script (WSL):   {script_path}")
    print(f"  Script (Win):   {script_path_ida}")
    print(f"  Output (WSL):   {output_path}")
    print(f"  Output (Win):   {output_path_ida}")
    print(f"  Log (WSL):      {log_path}")
    print(f"  Log (Win):      {log_path_ida}")

    # Write comprehensive test script
    test_script = f'''# IDA MCP Self-Test Script with Vulnerability Detection
import json
import idc
import idaapi
import idautils
import ida_funcs
import ida_bytes
import ida_name
import ida_xref
import ida_ida

idaapi.auto_wait()

# Basic info
info = {{
    "input_file": idc.get_input_file_path(),
    "file_type": idaapi.get_file_type_name(),
    "processor": idaapi.get_idp_name(),
    "bits": 64 if ida_ida.inf_is_64bit() else 32,
    "function_count": len(list(idautils.Functions())),
}}

# Find vulnerable function
vulns = []
evidence = {{}}

for func_ea in idautils.Functions():
    func_name = ida_name.get_name(func_ea)
    if func_name and "vulnerable" in func_name.lower():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        evidence["vulnerable_function"] = {{
            "name": func_name,
            "address": hex(func_ea),
            "size": func.size(),
        }}

        # Get disassembly and find calls
        calls = []
        disasm_lines = []
        ea = func.start_ea
        while ea < func.end_ea:
            disasm = idc.generate_disasm_line(ea, 0)
            mnem = idc.print_insn_mnem(ea)
            disasm_lines.append({{
                "address": hex(ea),
                "disasm": disasm,
            }})

            if mnem == "call":
                op = idc.print_operand(ea, 0)
                calls.append({{
                    "address": hex(ea),
                    "target": op,
                    "disasm": disasm,
                }})

                # Check for vulnerabilities
                op_lower = op.lower()
                if "strcpy" in op_lower:
                    vulns.append({{
                        "type": "BufferOverflow",
                        "cwe": ["CWE-120", "CWE-121"],
                        "function": func_name,
                        "address": hex(ea),
                        "call_target": "strcpy",
                        "evidence": disasm,
                    }})
                if "printf" in op_lower and "sprintf" not in op_lower and "fprintf" not in op_lower:
                    vulns.append({{
                        "type": "FormatString",
                        "cwe": ["CWE-134"],
                        "function": func_name,
                        "address": hex(ea),
                        "call_target": "printf",
                        "evidence": disasm,
                    }})
            ea = idc.next_head(ea)

        evidence["calls"] = calls
        evidence["disassembly"] = disasm_lines
        break

result = {{
    "success": True,
    "info": info,
    "vulnerabilities": vulns,
    "evidence": evidence,
}}

with open(r"{output_path_ida}", "w") as f:
    json.dump(result, f, indent=2)

print("Self-test complete!")
idc.qexit(0)
'''

    with open(script_path, 'w') as f:
        f.write(test_script)

    print(f"\n[SCRIPT WRITTEN]")
    print(f"  {script_path}")

    # Build command
    cmd_str = f'"{config.ida_path}" -A -S"{script_path_ida}" -L"{log_path_ida}" "{binary_path_ida}"'

    print(f"\n[COMMAND LINE]")
    print(f"  {cmd_str}")
    print(f"\n[COPY-PASTE RUNNABLE]")
    print(f"  {cmd_str}")

    print(f"\n[RUNNING IDA...]")
    print(f"  (This may take 30-60 seconds)")

    try:
        # Clean old files
        for f in [output_path, log_path]:
            if os.path.exists(f):
                os.unlink(f)

        result = subprocess.run(
            cmd_str,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=test_dir
        )

        print(f"\n[IDA EXIT CODE] {result.returncode}")

        if result.stdout:
            print(f"\n[STDOUT]\n{result.stdout[:300]}")

        # Check log
        if os.path.isfile(log_path):
            print(f"\n[LOG FILE] {log_path} - EXISTS")
            with open(log_path, 'r', errors='ignore') as f:
                log_content = f.read()
            print(f"[LOG TAIL (500 chars)]\n{log_content[-500:]}")
        else:
            print(f"\n[LOG FILE] {log_path} - NOT FOUND")

        # Check output
        if os.path.isfile(output_path):
            print(f"\n[OUTPUT FILE] {output_path} - EXISTS")
            with open(output_path, 'r') as f:
                output_data = json.load(f)

            print(f"\n[BASIC INFO]")
            info = output_data.get("info", {})
            print(f"  Input File:     {info.get('input_file')}")
            print(f"  File Type:      {info.get('file_type')}")
            print(f"  Processor:      {info.get('processor')}")
            print(f"  Bits:           {info.get('bits')}")
            print(f"  Function Count: {info.get('function_count')}")

            # Print evidence
            evidence = output_data.get("evidence", {})
            if evidence.get("vulnerable_function"):
                vf = evidence["vulnerable_function"]
                print(f"\n[VULNERABLE FUNCTION FOUND]")
                print(f"  Name:    {vf.get('name')}")
                print(f"  Address: {vf.get('address')}")
                print(f"  Size:    {vf.get('size')} bytes")

            if evidence.get("disassembly"):
                print(f"\n[DISASSEMBLY OF vulnerable()]")
                for line in evidence["disassembly"]:
                    print(f"  {line['address']}: {line['disasm']}")

            if evidence.get("calls"):
                print(f"\n[CALLS IN vulnerable()]")
                for call in evidence["calls"]:
                    print(f"  {call['address']}: {call['disasm']}")

            # Print vulnerabilities
            vulns = output_data.get("vulnerabilities", [])
            print(f"\n[VULNERABILITIES DETECTED: {len(vulns)}]")

            found_bof = False
            found_fmt = False

            for vuln in vulns:
                vtype = vuln.get("type")
                cwe = ", ".join(vuln.get("cwe", []))
                func = vuln.get("function")
                addr = vuln.get("address")
                target = vuln.get("call_target")
                evidence_line = vuln.get("evidence")

                print(f"\n  [SELFTEST] FOUND: {vtype}")
                print(f"    CWE:      {cwe}")
                print(f"    Function: {func}")
                print(f"    Address:  {addr}")
                print(f"    Call:     {target}")
                print(f"    Evidence: {evidence_line}")

                if vtype == "BufferOverflow":
                    found_bof = True
                if vtype == "FormatString":
                    found_fmt = True

            # Final verdict
            print(f"\n{'=' * 70}")
            if found_bof and found_fmt:
                print("SELF-TEST PASSED!")
                print(f"  [x] BufferOverflow (CWE-120/121) - FOUND")
                print(f"  [x] FormatString (CWE-134) - FOUND")
                print(f"{'=' * 70}")

                print(f"\n[FILES KEPT FOR AUDIT]")
                print(f"  Script: {script_path}")
                print(f"  Output: {output_path}")
                print(f"  Log:    {log_path}")
                return True
            else:
                print("SELF-TEST FAILED!")
                print(f"  [{'x' if found_bof else ' '}] BufferOverflow")
                print(f"  [{'x' if found_fmt else ' '}] FormatString")
                print(f"{'=' * 70}")
                return False
        else:
            print(f"\n[OUTPUT FILE] {output_path} - NOT FOUND")
            print(f"\n[ERROR] IDA did not produce output")
            return False

    except subprocess.TimeoutExpired:
        print(f"\n[ERROR] IDA timed out after 120 seconds")
        return False
    except Exception as e:
        print(f"\n[ERROR] {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


class SimpleHTTPHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler for health check."""

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = {"status": "ok", "service": "ida-mcp", "version": "1.0.0"}
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        if DEBUG:
            _dbg(f"HTTP: {format % args}")


def main():
    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind to")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind to")
    parser.add_argument("--ida-path", help="Path to IDA Pro executable")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio",
                        help="Transport mode (stdio for MCP, http for standalone)")
    parser.add_argument("--self-test", metavar="BINARY",
                        help="Run self-test with vulnerability detection on specified binary")
    args = parser.parse_args()

    if args.ida_path:
        os.environ["IDA_PATH"] = args.ida_path

    # Handle self-test mode
    if args.self_test:
        success = run_self_test(args.self_test, args.ida_path)
        sys.exit(0 if success else 1)

    _info(f"Starting IDA MCP Server v1.0.0")
    _info(f"Debug mode: {DEBUG}")
    _info(f"Transport: {args.transport}")

    if HAS_FASTMCP and args.transport == "stdio":
        mcp = create_mcp_server()
        _info("Running in MCP mode (stdio transport)")
        mcp.run()
    else:
        _info(f"Running in standalone HTTP mode on {args.host}:{args.port}")

        global ida_bridge
        config = IDAConfig()
        ida_bridge = IDABridge(config)

        server = HTTPServer((args.host, args.port), SimpleHTTPHandler)
        server.serve_forever()


if __name__ == "__main__":
    main()
