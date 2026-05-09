#!/usr/bin/env python3
"""
Alternative hypothesis: the Transfer menu item is disabled via a global "can_use_transfer" flag
that's set by each domain's init code, rather than a per-locationId check.

Search for stores of 0x0 or 0x1 to a consistent memory location,
conditioned on being in a dungeon.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "digimon2/lib/python3.14/site-packages"))

import patch_dw2 as dw2
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

OUT = HERE / "out"
BIN = HERE / "dw2.bin"


def search_file_for_disable_pattern(file_idx: int, file_name: str):
    """
    Look for code that:
    1. Stores 0x0 or 0x1 to some location (the "disable" action)
    2. Inside conditional branches
    3. Particularly in STAG files
    """
    try:
        with open(BIN, "rb") as fh:
            disc = dw2.DiscImage(fh)
            data = bytes(disc.read_file(file_idx))
    except Exception:
        return None
    
    # Look for the pattern: li $rX, 0; sb $rX, offset($rY)
    # This is typically encoded as: addiu $rX, $zero, 0; sb $rX, offset($rY)
    # Or: xor $rX, $rX, $rX; sb $rX, ...
    
    # In little-endian bytes:
    # li 0: 00 00 00 24 (addiu $rX, $zero, 0) -- but this is harder to match generically
    # Better: search for sb $zero, offset($rX) which disables by writing 0
    
    results = []
    for offset in range(len(data) - 4):
        word = struct.unpack("<I", data[offset : offset + 4])[0]
        
        # Check for sb $zero, offset(reg)
        # sb opcode: 0x28, rs=0, immediate=offset
        opcode = (word >> 26) & 0x3F
        rs = (word >> 21) & 0x1F
        rt = (word >> 16) & 0x1F
        
        # sb: opcode 40 (101000), but let me double-check
        # Actually in MIPS: sb is opcode 0x28 (40 in decimal) with format I-type
        # But the bit field is: opcode rs rt offset (little-endian in MIPS)
        # In the 32-bit word (little-endian): [offset(16)][rt(5)][rs(5)][opcode(6)]
        
        # Let me just look for sb (opcode 0x28) writing to a consistent offset
        if opcode == 0x28:  # sb
            immediate = word & 0xFFFF
            # Track this
            results.append({
                'offset': offset,
                'word': word,
                'rt': rt,
                'rs': rs,
                'imm': immediate,
            })
    
    return {
        'file_name': file_name,
        'sb_count': len(results),
        'sample_stores': results[:10],
    }


def main() -> int:
    stag_files = [
        (400, "file_400"),
        (402, "STAG2000.PRO"),
        (403, "STAG3000.PRO"),
        (410, "STAG4000.PRO"),
    ]
    
    with open(OUT / "transfer_sb_zero_searches.txt", "w") as f:
        for file_idx, file_name in stag_files:
            result = search_file_for_disable_pattern(file_idx, file_name)
            if result:
                f.write(f"\n{file_name} (file {file_idx}):\n")
                f.write(f"  Total sb instructions: {result['sb_count']}\n")
                f.write(f"  Sample sb patterns:\n")
                for i, store in enumerate(result['sample_stores']):
                    f.write(f"    +0x{store['offset']:06X}: sb $r{store['rt']}, 0x{store['imm']:04X}($r{store['rs']})\n")
    
    print(f"Wrote sb pattern search to {OUT / 'transfer_sb_zero_searches.txt'}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
