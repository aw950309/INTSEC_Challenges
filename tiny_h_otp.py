#!/usr/bin/env python3
"""
TinyH-OTP: intentionally weak OTP generator for educational use.

TinyH(a)  = SHA1(a) >> 144  (16 most significant bits -> 4 hex chars)
mp        = master password (16-bit value, given as hex, 4 chars)
TinyH-OTP(mp, n) = TinyH^n(mp) XOR mp
"""

import argparse
import hashlib
import sys


def normalize_hex16(x: str) -> str:
    """
    Normalize a string as a 16-bit hex value:
    - strip optional '0x'
    - lowercase
    - zero-pad to 4 hex digits
    """
    x = x.strip().lower()
    if x.startswith("0x"):
        x = x[2:]
    # This will allow shorter hex values, but they’ll be padded to 4 digits
    if len(x) > 4:
        raise ValueError(f"Value '{x}' does not fit in 16 bits (more than 4 hex digits).")
    return x.zfill(4)


def TinyH(a: str) -> str:
    """
    TinyH(a) = SHA1(a) >> 144 (take the 16 most significant bits -> 4 hex chars)
    Here `a` is treated as a UTF-8 string (typically a 4-hex-char string).
    Returns a 4-hex-char lowercase string.
    """
    # Normalize the input as 16-bit hex string, then hash its ASCII representation
    a_norm = normalize_hex16(a)

    # Compute SHA-1 digest of the ASCII representation of the hex string
    digest = hashlib.sha1(a_norm.encode("ascii")).digest()  # 20 bytes = 160 bits

    # Take the 16 most significant bits => first 2 bytes of the big-endian digest
    msb16 = int.from_bytes(digest[:2], byteorder="big")

    # Return as 4 hex characters
    return f"{msb16:04x}"


def TinyH_OTP(mp: str, n: int) -> str:
    """
    TinyH-OTP(mp, n) = TinyH^n(mp) XOR mp

    mp: master password as a hex string (up to 16 bits).
    n : non-negative integer step.

    Returns a 4-hex-char lowercase string (16-bit OTP).
    """
    if n < 0:
        raise ValueError("n must be a non-negative integer.")

    mp_hex = normalize_hex16(mp)

    # Iterated TinyH: TinyH^n(mp)
    state = mp_hex
    for _ in range(n):
        state = TinyH(state)

    # XOR with master password (both 16-bit)
    mp_int = int(mp_hex, 16)
    state_int = int(state, 16)
    otp_int = state_int ^ mp_int

    return f"{otp_int:04x}"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="TinyH-OTP: intentionally weak OTP generator (for teaching)."
    )

    parser.add_argument(
        "mp",
        help="Master password as 16-bit hex (e.g. '1a2b' or '0x1a2b')."
    )
    parser.add_argument(
        "n",
        type=int,
        help="Step index n (non-negative integer)."
    )
    parser.add_argument(
        "--show-chain",
        action="store_true",
        help="Also print TinyH^k(mp) for k = 0..n (useful for demos)."
    )

    args = parser.parse_args(argv)

    try:
        mp_hex = normalize_hex16(args.mp)
    except ValueError as e:
        print(f"Error with master password: {e}", file=sys.stderr)
        sys.exit(1)

    if args.n < 0:
        print("Error: n must be non-negative.", file=sys.stderr)
        sys.exit(1)

    # Optionally print the hash chain
    if args.show_chain:
        state = mp_hex
        print(f"k=0: {state}")
        for k in range(1, args.n + 1):
            state = TinyH(state)
            print(f"k={k}: {state}")

    # Compute OTP
    otp = TinyH_OTP(mp_hex, args.n)
    print(otp)


if __name__ == "__main__":
    main()

