#!/usr/bin/env python3
"""
Determine the actual load address of STAG4000.PRO by examining its header.
Most stage files have a header with the load address encoded.
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
        
        for file_idx in [400, 402, 403, 407, 410, 411]:
            try:
                data = bytes(disc.read_file(file_idx))
            except:
                continue
            
            if len(data) < 128:
                continue
            
            print(f"\nfile_{file_idx}:")
            print(f"  Size: {len(data)} bytes")
            print(f"  LBA: {disc.lba[file_idx]}")
            
            # Show first 64 bytes
            print("  First 64 bytes (hex):")
            for off in range(0, 64, 16):
                hex_str = " ".join(f"{b:02x}" for b in data[off:off+16])
                print(f"    {off:04X}: {hex_str}")
            
            # Look for 0x800-range pointers (load addresses)
            print("  Possible load addresses (0x800xxxxx words):")
            for off in range(0, min(256, len(data)), 4):
                word = struct.unpack("<I", data[off:off+4])[0]
                if 0x80000000 <= word < 0x80200000:
                    print(f"    +0x{off:04X}: 0x{word:08X}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
