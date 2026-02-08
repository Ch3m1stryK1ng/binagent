#!/usr/bin/env python3
"""
Self-tests for CTF runner: flag extraction, transcript formatting, and parser.
"""

import json
import sys
import tempfile
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from pentestagent.ctf.runner import CTFRunner, TranscriptBuilder
from pentestagent.ctf.parser import parse_nc_target, parse_connect_string, parse_all_nc_targets
from pentestagent.ctf.solver import DEFAULT_STRATEGIES


def test_flag_extraction():
    """Test that flag regex extraction works correctly."""
    print("Testing flag extraction...")

    # Create a mock runner
    runner = CTFRunner(
        host="test.local",
        port=9999,
        payload="test\n",
        repeat=1,
        timeout=5,
        save_artifacts=False,
    )

    # Simulate output containing a flag
    test_outputs = [
        ("picoCTF{test_flag_123}", True),
        ("The flag is picoCTF{70637h3r_f0r3v3r_c373964d} hidden here", True),
        ("No flag here", False),
        ("Multiple picoCTF{first} and picoCTF{second} flags", True),
        ("Partial pico{not_a_flag}", False),
    ]

    for output, should_find in test_outputs:
        runner.all_output = output
        runner.flags_found = []
        runner._extract_flags()

        found = len(runner.flags_found) > 0
        status = "PASS" if found == should_find else "FAIL"
        print(f"  [{status}] '{output[:50]}...' -> found={found}, expected={should_find}")

        if found != should_find:
            return False

    return True


def test_transcript_builder():
    """Test transcript formatting."""
    print("Testing transcript builder...")

    builder = TranscriptBuilder()
    builder.add_event("Connected to test:1234")
    builder.add_received("Hello\nWorld")
    builder.add_sent("test;RETURN 0\n")
    builder.add_received("Flag: picoCTF{test}")
    builder.add_event("Connection closed")

    text = builder.to_text()

    # Verify structure
    checks = [
        ("CTF RUNNER TRANSCRIPT" in text, "Header present"),
        ("[RECV]" in text, "RECV marker present"),
        ("[SEND]" in text, "SEND marker present"),
        ("Connected to test:1234" in text, "Event recorded"),
        ("END TRANSCRIPT" in text, "Footer present"),
    ]

    for check, name in checks:
        status = "PASS" if check else "FAIL"
        print(f"  [{status}] {name}")
        if not check:
            return False

    # Test JSON output
    json_output = builder.to_json()
    if len(json_output) != 5:
        print(f"  [FAIL] JSON entries: expected 5, got {len(json_output)}")
        return False
    print(f"  [PASS] JSON entries: {len(json_output)}")

    return True


def test_run_metadata():
    """Test that run metadata is correctly formatted."""
    print("Testing run metadata generation...")

    with tempfile.TemporaryDirectory() as tmpdir:
        runner = CTFRunner(
            host="test.example.com",
            port=12345,
            payload="payload\n",
            repeat=5,
            timeout=10,
            mode="blind",
            out_dir=tmpdir,
            save_artifacts=True,
        )

        # Set mock values
        runner.all_output = "Output with picoCTF{metadata_test}"
        runner.start_time = 1000.0
        runner.end_time = 1005.5
        runner.bytes_sent = 100
        runner.bytes_received = 500

        runner._extract_flags()
        runner.save_artifacts()

        # Load and verify run.json
        run_path = Path(tmpdir) / "run.json"
        with open(run_path) as f:
            run_data = json.load(f)

        checks = [
            (run_data["host"] == "test.example.com", "Host correct"),
            (run_data["port"] == 12345, "Port correct"),
            (run_data["repeat"] == 5, "Repeat correct"),
            (run_data["mode"] == "blind", "Mode correct"),
            ("git_commit" in run_data, "Git commit present"),
        ]

        for check, name in checks:
            status = "PASS" if check else "FAIL"
            print(f"  [{status}] {name}")
            if not check:
                return False

        # Load and verify summary.json
        summary_path = Path(tmpdir) / "summary.json"
        with open(summary_path) as f:
            summary_data = json.load(f)

        checks = [
            (summary_data["success"] == True, "Success is True"),
            (len(summary_data["flags"]) == 1, "One flag found"),
            (summary_data["flags"][0]["flag"] == "picoCTF{metadata_test}", "Flag correct"),
            (summary_data["bytes_sent"] == 100, "Bytes sent correct"),
            (summary_data["bytes_received"] == 500, "Bytes received correct"),
        ]

        for check, name in checks:
            status = "PASS" if check else "FAIL"
            print(f"  [{status}] {name}")
            if not check:
                return False

    return True


def test_nc_parser():
    """Test parsing nc host port from descriptions."""
    print("Testing nc target parser...")

    test_cases = [
        # (input, expected_host, expected_port)
        ("nc verbal-sleep.picoctf.net 56332", "verbal-sleep.picoctf.net", 56332),
        ("Connect: nc example.com 12345", "example.com", 12345),
        ("$ nc test.host.io 8080", "test.host.io", 8080),
        ("ncat server.local 9999", "server.local", 9999),
        ("Try connecting to nc my-server.net:443", "my-server.net", 443),
        ("The server is at example.org:8000 for this challenge", "example.org", 8000),
        ("No connection info here", None, None),
        ("Connect to port 12345", None, None),  # No host
    ]

    for text, expected_host, expected_port in test_cases:
        result = parse_nc_target(text)

        if expected_host is None:
            success = result is None
            status = "PASS" if success else "FAIL"
            print(f"  [{status}] '{text[:40]}...' -> None expected, got {result}")
        else:
            if result is None:
                print(f"  [FAIL] '{text[:40]}...' -> expected {expected_host}:{expected_port}, got None")
                return False
            success = result.host == expected_host and result.port == expected_port
            status = "PASS" if success else "FAIL"
            print(f"  [{status}] '{text[:40]}...' -> {result.host}:{result.port}")
            if not success:
                return False

    return True


def test_connect_string_parser():
    """Test parsing host:port connect strings."""
    print("Testing connect string parser...")

    test_cases = [
        ("example.com:8080", "example.com", 8080),
        ("localhost:3000", "localhost", 3000),
        ("test.io 9999", "test.io", 9999),
        ("invalid", None, None),
        ("no-port:", None, None),
        (":8080", None, None),
    ]

    for text, expected_host, expected_port in test_cases:
        result = parse_connect_string(text)

        if expected_host is None:
            success = result is None
            status = "PASS" if success else "FAIL"
            print(f"  [{status}] '{text}' -> None expected")
        else:
            if result is None:
                print(f"  [FAIL] '{text}' -> expected {expected_host}:{expected_port}, got None")
                return False
            success = result.host == expected_host and result.port == expected_port
            status = "PASS" if success else "FAIL"
            print(f"  [{status}] '{text}' -> {result.host}:{result.port}")
            if not success:
                return False

    return True


def test_strategy_ordering():
    """Test that payload strategies are in deterministic order."""
    print("Testing strategy ordering...")

    expected_order = [
        "baseline",
        "semicolon_return_0",
        "semicolon_return_1",
        "semicolon_return_2",
        "semicolon_return_3",
    ]

    actual_order = [s.name for s in DEFAULT_STRATEGIES]

    # Verify first 5 are in expected order
    for i, expected in enumerate(expected_order):
        if i >= len(actual_order):
            print(f"  [FAIL] Missing strategy at index {i}: expected {expected}")
            return False
        if actual_order[i] != expected:
            print(f"  [FAIL] Strategy {i}: expected {expected}, got {actual_order[i]}")
            return False
        print(f"  [PASS] Strategy {i}: {expected}")

    print(f"  [PASS] Total strategies: {len(DEFAULT_STRATEGIES)}")
    return True


def main():
    """Run all tests."""
    print("=" * 60)
    print("CTF Runner Self-Test")
    print("=" * 60)
    print()

    tests = [
        ("Flag Extraction", test_flag_extraction),
        ("Transcript Builder", test_transcript_builder),
        ("Run Metadata", test_run_metadata),
        ("NC Target Parser", test_nc_parser),
        ("Connect String Parser", test_connect_string_parser),
        ("Strategy Ordering", test_strategy_ordering),
    ]

    results = []
    for name, test_func in tests:
        try:
            passed = test_func()
        except Exception as e:
            print(f"  [ERROR] {e}")
            import traceback
            traceback.print_exc()
            passed = False
        results.append((name, passed))
        print()

    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)

    all_passed = True
    for name, passed in results:
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {name}")
        if not passed:
            all_passed = False

    print()
    if all_passed:
        print("All tests passed!")
        return 0
    else:
        print("Some tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
