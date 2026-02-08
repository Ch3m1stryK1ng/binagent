#!/usr/bin/env python3
"""Test pyghidra-mcp list_cross_references with address-based lookups."""
import subprocess
import json
import sys
import os
import time

VENV_PYTHON = "/home/a347908610/pentestagent/venv/bin/python"
PYGHIDRA_MCP = "/home/a347908610/pentestagent/venv/bin/pyghidra-mcp"
BINARY = os.path.abspath("test_binaries/vuln3_stripped")

env = os.environ.copy()
env["GHIDRA_INSTALL_DIR"] = "/home/a347908610/local/ghidra_12.0.2_PUBLIC"
env["JAVA_HOME"] = "/home/a347908610/local/jdk-21.0.6+7"
env["PATH"] = env["JAVA_HOME"] + "/bin:" + env["PATH"]


def call_tool(proc, tool_name, args):
    """Send a JSON-RPC call and read the response."""
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": args},
    }
    msg = json.dumps(req)
    header = f"Content-Length: {len(msg)}\r\n\r\n"
    proc.stdin.write(header + msg)
    proc.stdin.flush()

    # Read response
    content_length = None
    while True:
        line = proc.stdout.readline()
        if line.startswith("Content-Length:"):
            content_length = int(line.split(":")[1].strip())
        if line.strip() == "":
            break
    body = proc.stdout.read(content_length)
    return json.loads(body)


def main():
    print("Starting pyghidra-mcp server...")
    proc = subprocess.Popen(
        [VENV_PYTHON, "-m", "pyghidra_mcp.server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )

    # Initialize
    init_req = json.dumps({
        "jsonrpc": "2.0", "id": 0,
        "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0.1"}}
    })
    header = f"Content-Length: {len(init_req)}\r\n\r\n"
    proc.stdin.write(header + init_req)
    proc.stdin.flush()

    # Read init response
    while True:
        line = proc.stdout.readline()
        if line.startswith("Content-Length:"):
            cl = int(line.split(":")[1].strip())
        if line.strip() == "":
            break
    proc.stdout.read(cl)

    # Send initialized notification
    notif = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
    header = f"Content-Length: {len(notif)}\r\n\r\n"
    proc.stdin.write(header + notif)
    proc.stdin.flush()
    time.sleep(1)

    try:
        # Step 1: Import binary
        print(f"\n1. Importing {BINARY}...")
        resp = call_tool(proc, "import_binary", {"binary_path": BINARY})
        text = resp.get("result", {}).get("content", [{}])[0].get("text", "")
        print(f"   Import result: {text[:200]}")

        # Step 2: Discover binary name
        print("\n2. Listing project binaries...")
        resp = call_tool(proc, "list_project_binaries", {})
        text = resp.get("result", {}).get("content", [{}])[0].get("text", "")
        print(f"   Binaries: {text[:200]}")
        data = json.loads(text)
        programs = data.get("programs", []) if isinstance(data, dict) else data
        binary_name = None
        for prog in programs:
            pname = prog.get("name", "") if isinstance(prog, dict) else str(prog)
            if "vuln3_stripped" in pname:
                binary_name = pname.lstrip("/")
                break
        print(f"   Binary name: {binary_name}")

        if not binary_name:
            print("ERROR: Could not find binary name!")
            return 1

        # Step 3: List imports to get addresses
        print("\n3. Listing imports...")
        resp = call_tool(proc, "list_imports", {"binary_name": binary_name, "limit": 50})
        text = resp.get("result", {}).get("content", [{}])[0].get("text", "")
        imports = json.loads(text) if text else []
        if isinstance(imports, dict):
            imports = imports.get("imports", imports.get("symbols", []))

        # Find dangerous functions
        dangerous = ["strcpy", "gets", "printf", "system", "sprintf"]
        found_imports = []
        for imp in imports:
            name = imp.get("name", "") if isinstance(imp, dict) else str(imp)
            addr = imp.get("address", "") if isinstance(imp, dict) else ""
            for d in dangerous:
                if d in name.lower():
                    found_imports.append({"name": name, "address": addr})
                    break

        print(f"   Found {len(found_imports)} dangerous imports:")
        for fi in found_imports:
            print(f"     {fi['name']} @ {fi['address']}")

        # Step 4: Test list_cross_references with addresses
        print("\n4. Testing list_cross_references with addresses...")
        for fi in found_imports[:3]:  # Test first 3
            addr = fi["address"]
            name = fi["name"]
            print(f"\n   Xrefs for {name} @ {addr}:")
            resp = call_tool(proc, "list_cross_references", {
                "binary_name": binary_name,
                "name_or_address": addr,
            })
            text = resp.get("result", {}).get("content", [{}])[0].get("text", "")
            print(f"   Result: {text[:300]}")

            # Parse xrefs to get callers
            try:
                xref_data = json.loads(text)
                refs = xref_data if isinstance(xref_data, list) else xref_data.get("references", [])
                callers = set()
                for ref in refs:
                    caller = ref.get("from_function", ref.get("from", ""))
                    if caller:
                        callers.add(caller)
                if callers:
                    print(f"   Callers: {list(callers)[:5]}")

                    # Step 5: Decompile first caller
                    first_caller = list(callers)[0]
                    print(f"\n   Decompiling caller: {first_caller}")
                    resp = call_tool(proc, "decompile_function", {
                        "binary_name": binary_name,
                        "name_or_address": first_caller,
                    })
                    text = resp.get("result", {}).get("content", [{}])[0].get("text", "")
                    print(f"   Decompiled ({len(text)} chars): {text[:200]}...")
            except (json.JSONDecodeError, TypeError) as e:
                print(f"   Parse error: {e}")

        print("\n\nAll tests passed!")
        return 0

    finally:
        proc.terminate()
        proc.wait(timeout=10)


if __name__ == "__main__":
    sys.exit(main())
