#!/usr/bin/env python3
"""
Step 5: Inspect the single reference to is_story_lt_10 (0x80063B70)
inside STAG3000.PRO (file_403) at file offset 0xFCE0.

Show raw bytes and full disassembly around it so we can see whether
that's a `jalr`-table entry or an in-function pointer constant, and
identify the exact byte payload to change for the "open gate at story
stage 9" patch.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import patch_dw2 as dw2

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

OUT = HERE / "out"
OUT.mkdir(exist_ok=True)
BIN = HERE / "dw2.bin"

STAG_LOAD_BASE = 0x80060000
TARGET_FILE_IDX = 403  # STAG3000.PRO
HIT_OFFSET = 0xFCE0   # file offset where the literal 0x80063B70 lives


def hex_dump(data: bytes, base: int = 0):
    lines = []
    for off in range(0, len(data), 16):
        row = data[off : off + 16]
        hexp = " ".join(f"{b:02x}" for b in row)
        ascp = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"  0x{base + off:08X}: {hexp:<48s}  {ascp}")
    return "\n".join(lines)


def main() -> int:
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        data = bytes(disc.read_file(TARGET_FILE_IDX))

    print(f"STAG3000.PRO: {len(data)} bytes total")
    print(f"\nReference site: file 0x{HIT_OFFSET:08X}, RAM 0x{STAG_LOAD_BASE + HIT_OFFSET:08X}\n")

    # 256 bytes around the hit, raw.
    win_lo = max(0, HIT_OFFSET - 64)
    win_hi = min(len(data), HIT_OFFSET + 192)
    print("Raw bytes (file offsets):")
    print(hex_dump(data[win_lo:win_hi], base=win_lo))
    print()

    # Disassemble the same region as MIPS, at runtime base.
    print("MIPS disassembly (runtime addresses):")
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    md.skipdata = True
    md.skipdata_setup = ("data", None, None)
    base = STAG_LOAD_BASE + win_lo
    chunk = data[win_lo:win_hi]
    for ins in md.disasm(chunk, base):
        marker = ">>> " if ins.address == STAG_LOAD_BASE + HIT_OFFSET else "    "
        print(f"  {marker}0x{ins.address:08X}: {ins.bytes.hex():<8} {ins.mnemonic:<8} {ins.op_str}")

    # Also: is the 4-byte word at HIT_OFFSET aligned, and what are the
    # 4 bytes immediately before / after?
    word_at_hit = struct.unpack_from("<I", data, HIT_OFFSET)[0]
    word_before = struct.unpack_from("<I", data, HIT_OFFSET - 4)[0]
    word_after  = struct.unpack_from("<I", data, HIT_OFFSET + 4)[0]
    print()
    print(f"Word @ HIT-4 = 0x{word_before:08X}")
    print(f"Word @ HIT   = 0x{word_at_hit:08X}   <-- is_story_lt_10")
    print(f"Word @ HIT+4 = 0x{word_after:08X}")

    # If it's a function-pointer table, expect more 0x800XXXXX values
    # around it.
    print("\nLooking for nearby words that look like RAM ptrs (0x800?????):")
    for off in range(max(0, HIT_OFFSET - 64), min(len(data) - 4, HIT_OFFSET + 64), 4):
        w = struct.unpack_from("<I", data, off)[0]
        marker = " <-- HIT" if off == HIT_OFFSET else ""
        if 0x80000000 <= w < 0x80200000:
            print(f"  file 0x{off:08X}: 0x{w:08X}{marker}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
