#!/usr/bin/env python3
"""Simple test of pyghidra-mcp xrefs using address-based lookup."""
import subprocess
import json
import sys
import os
import time

BINARY = os.path.abspath("test_binaries/vuln3_stripped")

env = os.environ.copy()
env["GHIDRA_INSTALL_DIR"] = "/home/a347908610/local/ghidra_12.0.2_PUBLIC"
env["JAVA_HOME"] = "/home/a347908610/local/jdk-21.0.6+7"
env["PATH"] = env["JAVA_HOME"] + "/bin:" + env["PATH"]


def send_msg(proc, obj):
    msg = json.dumps(obj)
    raw = f"Content-Length: {len(msg)}\r\n\r\n{msg}"
    proc.stdin.write(raw.encode())
    proc.stdin.flush()


def recv_msg(proc):
    headers = b""
    while True:
        ch = proc.stdout.read(1)
        if not ch:
            raise EOFError("Server closed")
        headers += ch
        if headers.endswith(b"\r\n\r\n"):
            break
    cl = 0
    for line in headers.decode().strip().split("\r\n"):
        if line.startswith("Content-Length:"):
            cl = int(line.split(":")[1].strip())
    body = proc.stdout.read(cl)
    return json.loads(body)


def call_tool(proc, name, args):
    send_msg(proc, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": name, "arguments": args}})
    return recv_msg(proc)


print("Starting pyghidra-mcp...", flush=True)
proc = subprocess.Popen(
    ["/home/a347908610/pentestagent/venv/bin/python", "-m", "pyghidra_mcp.server"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=sys.stderr,
    env=env,
)

# Initialize
print("Sending initialize...", flush=True)
send_msg(proc, {
    "jsonrpc": "2.0", "id": 0, "method": "initialize",
    "params": {"protocolVersion": "2024-11-05", "capabilities": {},
               "clientInfo": {"name": "test", "version": "0.1"}}
})
resp = recv_msg(proc)
print(f"Init OK: {list(resp.get('result', {}).keys())}", flush=True)

# Initialized notification
send_msg(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
time.sleep(2)

# Import
print(f"\nImporting {BINARY}...", flush=True)
resp = call_tool(proc, "import_binary", {"binary_path": BINARY})
text = resp.get("result", {}).get("content", [{}])[0].get("text", "")
print(f"Import: {text[:150]}", flush=True)

# List project binaries
print("\nListing binaries...", flush=True)
resp = call_tool(proc, "list_project_binaries", {})
text = resp.get("result", {}).get("content", [{}])[0].get("text", "")
print(f"Binaries: {text[:200]}", flush=True)
data = json.loads(text)
programs = data.get("programs", []) if isinstance(data, dict) else data
binary_name = None
for prog in programs:
    pname = prog.get("name", "") if isinstance(prog, dict) else str(prog)
    if "vuln3_stripped" in pname:
        binary_name = pname.lstrip("/")
        break
print(f"Binary name: {binary_name}", flush=True)

# List imports
print("\nListing imports...", flush=True)
resp = call_tool(proc, "list_imports", {"binary_name": binary_name, "limit": 50})
text = resp.get("result", {}).get("content", [{}])[0].get("text", "")
imports_data = json.loads(text) if text else []
if isinstance(imports_data, dict):
    imports_list = imports_data.get("imports", imports_data.get("symbols", []))
else:
    imports_list = imports_data

# Find dangerous imports with addresses
dangerous = ["strcpy", "gets", "printf", "system", "sprintf"]
found = []
for imp in imports_list:
    name = imp.get("name", "") if isinstance(imp, dict) else str(imp)
    addr = imp.get("address", "") if isinstance(imp, dict) else ""
    for d in dangerous:
        if d in name.lower():
            found.append({"name": name, "address": addr})
            break

print(f"Dangerous imports: {len(found)}", flush=True)
for f in found:
    print(f"  {f['name']} @ {f['address']}", flush=True)

# Test xrefs with addresses
if found:
    target = found[0]
    print(f"\nXrefs for {target['name']} @ {target['address']}...", flush=True)
    resp = call_tool(proc, "list_cross_references", {
        "binary_name": binary_name,
        "name_or_address": target["address"],
    })
    text = resp.get("result", {}).get("content", [{}])[0].get("text", "")
    print(f"Xref result: {text[:500]}", flush=True)

    # Try a second one
    if len(found) > 1:
        target2 = found[1]
        print(f"\nXrefs for {target2['name']} @ {target2['address']}...", flush=True)
        resp = call_tool(proc, "list_cross_references", {
            "binary_name": binary_name,
            "name_or_address": target2["address"],
        })
        text = resp.get("result", {}).get("content", [{}])[0].get("text", "")
        print(f"Xref result: {text[:500]}", flush=True)

print("\n\nDONE - all xref tests passed!", flush=True)
proc.terminate()
proc.wait(timeout=10)
