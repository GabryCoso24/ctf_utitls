"""Quick CLI for the ctf_toolkit package."""

from __future__ import annotations

import argparse

from .encoding import b64d, b64e, hex_to_bytes, rot_n, xor_with_key
from .io_helpers import extract_flags


def _cmd_xor(args: argparse.Namespace) -> None:
    data = args.data.encode()
    key = args.key.encode()
    out = xor_with_key(data, key)
    if args.hex:
        print(out.hex())
    else:
        print(out.decode(errors="replace"))


def _cmd_b64(args: argparse.Namespace) -> None:
    if args.decode:
        print(b64d(args.data).decode(errors="replace"))
    else:
        print(b64e(args.data.encode()))


def _cmd_hex(args: argparse.Namespace) -> None:
    print(hex_to_bytes(args.data).decode(errors="replace"))


def _cmd_rot(args: argparse.Namespace) -> None:
    print(rot_n(args.data, args.n))


def _cmd_flag(args: argparse.Namespace) -> None:
    flags = extract_flags(args.data)
    for f in flags:
        print(f)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ctf_toolkit", description="CTF fast helpers")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_xor = sub.add_parser("xor", help="XOR text with repeating key")
    p_xor.add_argument("data")
    p_xor.add_argument("key")
    p_xor.add_argument("--hex", action="store_true", help="print hex output")
    p_xor.set_defaults(func=_cmd_xor)

    p_b64 = sub.add_parser("b64", help="base64 encode/decode")
    p_b64.add_argument("data")
    p_b64.add_argument("--decode", action="store_true")
    p_b64.set_defaults(func=_cmd_b64)

    p_hex = sub.add_parser("hex", help="decode hex string to text")
    p_hex.add_argument("data")
    p_hex.set_defaults(func=_cmd_hex)

    p_rot = sub.add_parser("rot", help="ROT-N for alphabetic chars")
    p_rot.add_argument("data")
    p_rot.add_argument("-n", type=int, default=13)
    p_rot.set_defaults(func=_cmd_rot)

    p_flag = sub.add_parser("flag", help="extract flag{...} from text")
    p_flag.add_argument("data")
    p_flag.set_defaults(func=_cmd_flag)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
