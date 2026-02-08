"""Solve picoCTF Chronohack - time-seeded token prediction.

The server generates a token via: random.seed(int(time.time()*1000)); random token.
Strategy: pipeline all guesses (send without waiting for per-guess responses),
then read all replies at once. Respects rate limits with generous delays.
"""
import socket
import time
import random
import sys
import re

HOST = "verbal-sleep.picoctf.net"
PORT = 65325
TOKEN_LEN = 20
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
FLAG_RE = re.compile(r'picoCTF\{[^}]+\}')


def gen_token(seed):
    random.seed(seed)
    return ''.join(random.choice(ALPHABET) for _ in range(TOKEN_LEN))


def try_connection(round_num, offset_start, offset_end):
    """Connect, estimate server time, pipeline guesses."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    try:
        T0 = int(time.time() * 1000)
        sock.connect((HOST, PORT))
        banner = sock.recv(4096).decode()
        T1 = int(time.time() * 1000)
        latency = T1 - T0
        T_est = T0 + (latency // 2)
        n_guesses = offset_end - offset_start + 1

        print(f"[Round {round_num}] latency={latency}ms T_est={T_est} offsets=[{offset_start},{offset_end}] ({n_guesses} guesses)")

        # Pre-compute all guesses
        guesses = []
        for off in range(offset_start, offset_end + 1):
            seed = T_est + off
            guesses.append((off, seed, gen_token(seed)))

        # Pipeline: send ALL guesses at once
        payload = "".join(g[2] + "\n" for g in guesses)
        sock.sendall(payload.encode())

        # Read all responses
        time.sleep(1)
        all_data = b""
        while True:
            try:
                sock.settimeout(3)
                chunk = sock.recv(65536)
                if not chunk:
                    break
                all_data += chunk
            except socket.timeout:
                break
            except Exception:
                break

        reply = all_data.decode(errors="replace")

        # Check for flag
        m = FLAG_RE.search(reply)
        if m:
            flag = m.group(0)
            print(f"\n{'='*70}")
            print(f"FLAG FOUND: {flag}")
            print(f"Offset range: [{offset_start}, {offset_end}]")
            print(f"{'='*70}")
            sock.close()
            return flag

        n_sorry = reply.count("Sorry")
        print(f"  {n_sorry} rejections, no flag")

        sock.close()
        return None

    except Exception as e:
        print(f"  Error: {e}")
        try:
            sock.close()
        except:
            pass
        return None


def main():
    print(f"[*] Chronohack solver: {HOST}:{PORT}")
    print(f"[*] Pipelining approach - conservative rate limiting\n")

    # Strategy: on each connection, try a window of 50 seeds.
    # Expand outward from 0 in both directions.
    # The token is generated when the server handles our connection,
    # so the offset should be relatively small if clocks are synced.
    # But clock skew could be hundreds of ms or more.
    windows = []
    step = 50
    for start in range(-500, 3001, step):
        windows.append((start, start + step - 1))

    for round_num, (lo, hi) in enumerate(windows, 1):
        flag = try_connection(round_num, lo, hi)
        if flag:
            print(f"\nFinal flag: {flag}")
            return

        # Conservative delay to avoid rate limiting
        time.sleep(5)

    print("[!] Exhausted all windows [-500, 3000]. Clock skew may be too large.")


if __name__ == "__main__":
    main()
