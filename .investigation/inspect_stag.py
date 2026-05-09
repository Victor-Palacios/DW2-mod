#!/usr/bin/env python3
"""
Inspect STAG2000.PRO (file_402) header & layout.

We want to know the runtime load address F so we can:
  1. Translate file offsets <-> RAM addresses,
  2. Locate `jal F + 0x3B70` (the "is story_progress < 10?" stub) call
     sites, which would be the candidate Tera Domain gate(s).
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import patch_dw2 as dw2

BIN = HERE / "dw2.bin"


def main() -> int:
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        for idx, label in [
            (398, "file_398"),
            (400, "file_400"),
            (401, "file_401"),
            (402, "STAG2000.PRO"),
            (dw2.IDX_STAG3000_PRO, "STAG3000.PRO"),
            (407, "file_407"),
            (dw2.IDX_STAG4000_PRO, "STAG4000.PRO"),
            (411, "file_411"),
            (412, "file_412"),
            (413, "file_413"),
        ]:
            try:
                data = bytes(disc.read_file(idx))
            except Exception as e:
                print(f"[{label} idx={idx}] read failed: {e}")
                continue
            head = data[:64]
            print(f"\n{label} (idx={idx}, {len(data)} bytes, LBA {disc.lba[idx]}):")
            # Show first 64 bytes
            for off in range(0, 64, 16):
                hex_part = " ".join(f"{b:02x}" for b in head[off:off+16])
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in head[off:off+16])
                print(f"  {off:04X}: {hex_part:<48s}  {ascii_part}")
            if head.startswith(b"PS-X EXE"):
                load = struct.unpack_from("<I", head, 0x18)[0]
                tsz  = struct.unpack_from("<I", head, 0x1C)[0]
                print(f"  -> PSX-EXE header: load=0x{load:08X}, text_size=0x{tsz:08X}")
            else:
                # Many STAG files start with a small header pointing to
                # subroutines. Print the first few uint32s.
                u32s = struct.unpack_from("<8I", head, 0)
                print("  first 8 uint32 LE: " + ", ".join(f"0x{x:08X}" for x in u32s))

    return 0


if __name__ == "__main__":
    sys.exit(main())
