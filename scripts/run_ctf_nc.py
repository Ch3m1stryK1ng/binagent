#!/usr/bin/env python3
"""
CTF Runner CLI - thin wrapper around pentestagent.ctf.runner

Captures full transcripts, structured metadata, and flag evidence for
audit-grade logging and regression testing.

Usage:
    python scripts/run_ctf_nc.py \
        --host verbal-sleep.picoctf.net \
        --port 56332 \
        --payload "test;RETURN 0\n" \
        --repeat 8 \
        --timeout 15 \
        --mode blind
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from pentestagent.ctf.runner import CTFRunner


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="CTF Runner for nc-based interactive challenges",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Blind mode (send payload 8 times regardless of prompts)
  python scripts/run_ctf_nc.py \\
      --host verbal-sleep.picoctf.net \\
      --port 56332 \\
      --payload "test;RETURN 0\\n" \\
      --repeat 8 \\
      --timeout 15 \\
      --mode blind

  # Prompted mode (wait for "Crowd:" before each send)
  python scripts/run_ctf_nc.py \\
      --host verbal-sleep.picoctf.net \\
      --port 56332 \\
      --payload "test;RETURN 0\\n" \\
      --repeat 8 \\
      --timeout 20 \\
      --mode prompted \\
      --prompt-regex "Crowd:"
"""
    )

    parser.add_argument("--host", required=True, help="Target hostname")
    parser.add_argument("--port", type=int, required=True, help="Target port")
    parser.add_argument(
        "--payload", required=True,
        help="Payload string (use \\n for newlines)"
    )
    parser.add_argument(
        "--repeat", type=int, default=1,
        help="Number of times to repeat the payload (default: 1)"
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0,
        help="Connection timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--prompt-regex", default=r"[Cc]rowd:",
        help="Regex to detect prompts (default: '[Cc]rowd:')"
    )
    parser.add_argument(
        "--flag-regex", default=r"picoCTF\{[^}]+\}",
        help="Regex to extract flags (default: 'picoCTF\\{[^}]+\\}')"
    )
    parser.add_argument(
        "--run-id",
        help="Custom run ID (default: timestamp-based)"
    )
    parser.add_argument(
        "--out-dir",
        help="Output directory (default: runs/<run-id>/)"
    )
    parser.add_argument(
        "--mode", choices=["blind", "prompted"], default="blind",
        help="Interaction mode: 'blind' or 'prompted' (default: blind)"
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Process payload escape sequences
    payload = args.payload.encode().decode('unicode_escape')

    print("=" * 60)
    print("CTF RUNNER")
    print("=" * 60)
    print(f"Host:    {args.host}:{args.port}")
    print(f"Payload: {repr(payload)}")
    print(f"Repeat:  {args.repeat}")
    print(f"Timeout: {args.timeout}s")
    print(f"Mode:    {args.mode}")
    print("=" * 60)

    runner = CTFRunner(
        host=args.host,
        port=args.port,
        payload=payload,
        repeat=args.repeat,
        timeout=args.timeout,
        prompt_regex=args.prompt_regex,
        flag_regex=args.flag_regex,
        mode=args.mode,
        run_id=args.run_id,
        out_dir=args.out_dir,
    )

    success = runner.run()

    print()
    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Run ID:     {runner.run_id}")
    print(f"Output Dir: {runner.out_dir}")
    print(f"Success:    {success}")

    if runner.flags_found:
        print(f"Flags:      {len(runner.flags_found)} found")
        for flag_info in runner.flags_found:
            print(f"  - {flag_info['flag']}")
    else:
        print("Flags:      None found")

    if runner.error:
        print(f"Error:      {runner.error}")

    print("=" * 60)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
