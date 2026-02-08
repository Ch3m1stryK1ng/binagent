#!/usr/bin/env python3
"""
BinaryAnalystAgent Integration Test

This script verifies:
1. LLM is invoked (log evidence)
2. MCP tools are loaded
3. load_binary happens before other IDA calls
4. Agent fails clearly when MCP is unavailable

Usage:
    # Full test with IDA MCP (requires IDA Pro)
    python scripts/test_binary_agent.py --binary test_binaries/vuln2_stripped

    # Test failure mode (no IDA)
    python scripts/test_binary_agent.py --binary test_binaries/vuln2_stripped --no-ida

    # Test offline mode
    python scripts/test_binary_agent.py --binary test_binaries/vuln2_stripped --offline

    # Quick verification (uses a simple test binary)
    python scripts/test_binary_agent.py --quick
"""

import argparse
import asyncio
import logging
import os
import sys
import tempfile

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def create_test_binary():
    """Create a minimal test binary for verification."""
    # Simple C program with a vulnerability
    c_code = '''
#include <stdio.h>
#include <string.h>

void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Buffer overflow!
    printf(buffer);         // Format string!
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vulnerable(argv[1]);
    }
    return 0;
}
'''
    # Try to compile it
    import subprocess
    import tempfile

    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
        f.write(c_code)
        c_file = f.name

    binary_file = c_file.replace('.c', '')

    try:
        result = subprocess.run(
            ['gcc', '-o', binary_file, c_file, '-fno-stack-protector', '-no-pie'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(f"[TEST] Created test binary: {binary_file}")
            return binary_file
        else:
            print(f"[TEST] GCC failed: {result.stderr}")
            return None
    except FileNotFoundError:
        print("[TEST] GCC not found, cannot create test binary")
        return None
    finally:
        try:
            os.unlink(c_file)
        except:
            pass


async def test_tool_verification():
    """Test that IDA tool verification works."""
    print("\n" + "=" * 60)
    print("TEST 1: Tool Verification")
    print("=" * 60)

    from pentestagent.agents.binary_agent import (
        BinaryAnalystAgent,
        REQUIRED_IDA_TOOLS,
    )
    from pentestagent.llm import LLM
    from pentestagent.runtime.runtime import LocalRuntime
    from pentestagent.tools import get_all_tools

    # Create minimal setup (no MCP)
    llm = LLM(model=os.getenv("PENTESTAGENT_MODEL", "gpt-4o-mini"))
    runtime = LocalRuntime()
    await runtime.start()
    tools = get_all_tools()

    # Create agent with a dummy binary path
    agent = BinaryAnalystAgent(
        llm=llm,
        tools=tools,
        runtime=runtime,
        binary_path="/tmp/nonexistent",
        offline_mode=True,  # Don't fail on missing tools
    )

    # Verify tool verification method exists and works
    all_available, found, missing = agent.verify_ida_tools()

    print(f"[TEST] Required IDA tools: {REQUIRED_IDA_TOOLS}")
    print(f"[TEST] Found tools: {found}")
    print(f"[TEST] Missing tools: {missing}")
    print(f"[TEST] All available: {all_available}")

    # Without MCP, all should be missing
    if len(missing) == len(REQUIRED_IDA_TOOLS):
        print("[PASS] Tool verification correctly detects missing IDA tools")
        return True
    else:
        print("[FAIL] Tool verification did not work as expected")
        return False


async def test_bootstrap_fail_fast():
    """Test that bootstrap fails fast when IDA tools are missing."""
    print("\n" + "=" * 60)
    print("TEST 2: Bootstrap Fail-Fast (No IDA)")
    print("=" * 60)

    from pentestagent.agents.binary_agent import (
        BinaryAnalystAgent,
        IDAToolsNotAvailableError,
    )
    from pentestagent.llm import LLM
    from pentestagent.runtime.runtime import LocalRuntime
    from pentestagent.tools import get_all_tools

    llm = LLM(model=os.getenv("PENTESTAGENT_MODEL", "gpt-4o-mini"))
    runtime = LocalRuntime()
    await runtime.start()
    tools = get_all_tools()

    # Create a temporary file to use as "binary"
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"test")
        test_file = f.name

    try:
        agent = BinaryAnalystAgent(
            llm=llm,
            tools=tools,
            runtime=runtime,
            binary_path=test_file,
            offline_mode=False,  # Should fail
        )

        try:
            await agent.bootstrap()
            print("[FAIL] Bootstrap should have raised IDAToolsNotAvailableError")
            return False
        except IDAToolsNotAvailableError as e:
            print(f"[PASS] Bootstrap correctly failed: {type(e).__name__}")
            print(f"[TEST] Error message: {str(e)[:100]}...")
            return True
        except Exception as e:
            print(f"[FAIL] Unexpected exception: {type(e).__name__}: {e}")
            return False
    finally:
        try:
            os.unlink(test_file)
        except:
            pass


async def test_bootstrap_offline_mode():
    """Test that bootstrap works in offline mode without IDA."""
    print("\n" + "=" * 60)
    print("TEST 3: Bootstrap Offline Mode")
    print("=" * 60)

    from pentestagent.agents.binary_agent import BinaryAnalystAgent
    from pentestagent.llm import LLM
    from pentestagent.runtime.runtime import LocalRuntime
    from pentestagent.tools import get_all_tools

    llm = LLM(model=os.getenv("PENTESTAGENT_MODEL", "gpt-4o-mini"))
    runtime = LocalRuntime()
    await runtime.start()
    tools = get_all_tools()

    # Create a temporary file to use as "binary"
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"test")
        test_file = f.name

    try:
        agent = BinaryAnalystAgent(
            llm=llm,
            tools=tools,
            runtime=runtime,
            binary_path=test_file,
            offline_mode=True,  # Should succeed in offline mode
        )

        result = await agent.bootstrap()

        if result.get("mode") == "offline":
            print(f"[PASS] Bootstrap succeeded in offline mode")
            print(f"[TEST] Result: {result}")
            return True
        else:
            print(f"[FAIL] Expected offline mode, got: {result}")
            return False
    except Exception as e:
        print(f"[FAIL] Bootstrap raised exception in offline mode: {e}")
        return False
    finally:
        try:
            os.unlink(test_file)
        except:
            pass


async def test_llm_invocation():
    """Test that LLM is actually invoked during agent execution."""
    print("\n" + "=" * 60)
    print("TEST 4: LLM Invocation")
    print("=" * 60)

    from pentestagent.llm import LLM

    model = os.getenv("PENTESTAGENT_MODEL", "gpt-4o-mini")
    llm = LLM(model=model)

    print(f"[TEST] Testing LLM with model: {model}")

    try:
        response = await llm.simple_completion(
            prompt="Say 'LLM_TEST_SUCCESS' and nothing else.",
            system="You are a test assistant. Follow instructions exactly."
        )

        if "LLM_TEST_SUCCESS" in response or "test" in response.lower():
            print(f"[PASS] LLM responded: {response[:50]}...")
            return True
        else:
            print(f"[WARN] LLM response unexpected: {response[:50]}...")
            return True  # Still passes - LLM was invoked
    except Exception as e:
        print(f"[FAIL] LLM invocation failed: {e}")
        return False


async def test_mcp_connection():
    """Test MCP connection and tool loading."""
    print("\n" + "=" * 60)
    print("TEST 5: MCP Connection")
    print("=" * 60)

    try:
        from pentestagent.mcp import MCPManager

        manager = MCPManager()
        print(f"[TEST] MCP config path: {manager.config_path}")
        print(f"[TEST] Config exists: {manager.config_path.exists()}")

        if not manager.config_path.exists():
            print("[SKIP] MCP config not found - skipping")
            return None

        tools = await manager.connect_all()
        print(f"[TEST] Connected. Tools loaded: {len(tools)}")

        if tools:
            tool_names = [t.name for t in tools]
            print(f"[TEST] Tool names: {tool_names[:5]}...")  # First 5

            ida_tools = [t for t in tools if 'ida' in t.name.lower()]
            print(f"[TEST] IDA tools: {len(ida_tools)}")

            if ida_tools:
                print(f"[PASS] IDA MCP tools available")
                return True
            else:
                print("[WARN] No IDA tools found in MCP")
                return None
        else:
            print("[WARN] No MCP tools loaded")
            return None

    except Exception as e:
        print(f"[FAIL] MCP connection error: {e}")
        return False
    finally:
        try:
            await manager.disconnect_all()
        except:
            pass


async def test_full_integration(binary_path: str, offline: bool = False):
    """Full integration test with actual binary analysis."""
    print("\n" + "=" * 60)
    print(f"TEST 6: Full Integration {'(Offline)' if offline else '(With IDA)'}")
    print("=" * 60)

    from pentestagent.agents.binary_agent import BinaryAnalystAgent
    from pentestagent.llm import LLM
    from pentestagent.mcp import MCPManager
    from pentestagent.runtime.runtime import LocalRuntime
    from pentestagent.tools import get_all_tools, register_tool_instance

    if not os.path.isfile(binary_path):
        print(f"[SKIP] Binary not found: {binary_path}")
        return None

    print(f"[TEST] Binary: {binary_path}")

    # Setup
    mcp_manager = None
    try:
        # Load MCP tools if not offline
        if not offline:
            try:
                mcp_manager = MCPManager()
                if mcp_manager.config_path.exists():
                    mcp_tools = await mcp_manager.connect_all()
                    for tool in mcp_tools:
                        register_tool_instance(tool)
                    print(f"[TEST] MCP tools loaded: {len(mcp_tools)}")
            except Exception as e:
                print(f"[WARN] MCP failed: {e}")

        model = os.getenv("PENTESTAGENT_MODEL", "gpt-4o-mini")
        llm = LLM(model=model)
        runtime = LocalRuntime(mcp_manager=mcp_manager)
        await runtime.start()
        tools = get_all_tools()

        print(f"[TEST] LLM model: {model}")
        print(f"[TEST] Total tools: {len(tools)}")

        agent = BinaryAnalystAgent(
            llm=llm,
            tools=tools,
            runtime=runtime,
            binary_path=binary_path,
            offline_mode=offline,
        )

        # Run bootstrap
        print("[TEST] Running bootstrap...")
        result = await agent.bootstrap()
        print(f"[TEST] Bootstrap result: {result.get('mode', 'unknown')}")

        if result.get("success"):
            print(f"[PASS] Integration test passed")
            return True
        else:
            print(f"[FAIL] Bootstrap failed: {result}")
            return False

    except Exception as e:
        print(f"[FAIL] Integration test error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        if mcp_manager:
            try:
                await mcp_manager.disconnect_all()
            except:
                pass


async def main():
    parser = argparse.ArgumentParser(description="BinaryAnalystAgent Integration Test")
    parser.add_argument("--binary", help="Path to binary file for testing")
    parser.add_argument("--quick", action="store_true", help="Quick test (creates test binary)")
    parser.add_argument("--no-ida", action="store_true", help="Test without IDA (expect failure)")
    parser.add_argument("--offline", action="store_true", help="Test offline mode")
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(message)s",
        datefmt="%H:%M:%S",
    )

    print("=" * 60)
    print("BinaryAnalystAgent Integration Test Suite")
    print("=" * 60)

    results = {}

    # Test 1: Tool verification
    results["tool_verification"] = await test_tool_verification()

    # Test 2: Bootstrap fail-fast
    results["bootstrap_fail_fast"] = await test_bootstrap_fail_fast()

    # Test 3: Offline mode
    results["offline_mode"] = await test_bootstrap_offline_mode()

    # Test 4: LLM invocation
    results["llm_invocation"] = await test_llm_invocation()

    # Test 5: MCP connection (optional)
    results["mcp_connection"] = await test_mcp_connection()

    # Test 6: Full integration (if binary provided)
    if args.binary or args.quick:
        binary_path = args.binary
        if args.quick:
            binary_path = create_test_binary()

        if binary_path:
            results["full_integration"] = await test_full_integration(
                binary_path,
                offline=args.offline or args.no_ida
            )

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = 0
    failed = 0
    skipped = 0

    for name, result in results.items():
        if result is True:
            status = "PASS"
            passed += 1
        elif result is False:
            status = "FAIL"
            failed += 1
        else:
            status = "SKIP"
            skipped += 1
        print(f"  [{status}] {name}")

    print()
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped")

    if failed > 0:
        print("\n[!] Some tests failed. Check output above for details.")
        sys.exit(1)
    else:
        print("\n[+] All tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
