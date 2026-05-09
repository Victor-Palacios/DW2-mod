#!/usr/bin/env python3
"""
Final attempt: search STAG4000 more carefully by looking for domain/location
type checks and how they affect menu state.

Key insight: in DW2, dungeons are "Domain" maps with specific IDs.
The Transfer menu is disabled per-dungeon, suggesting each domain init
sets a "can_transfer" flag to 0.

Look for patterns:
- Load a domain/location type variable
- Check if it's a "Domain" type
- Store 0 to a "menu_transfer_enabled" flag
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

BIN = HERE / "dw2.bin"
OUT = HERE / "out"


def search_stag4000_for_menu_disables():
    """
    Search STAG4000.PRO (file 410, 65536 bytes) for any code that
    stores 0 or 1 to a memory location in loops or conditional branches.
    These might be menu enable/disable flags.
    """
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        stag4000 = bytes(disc.read_file(410))
    
    # Look for code patterns:
    # 1. addiu $rX, $zero, 0 (or xor $rX, $rX, $rX)  — load 0
    # 2. sb $rX, offset($rY)                         — store to memory
    
    zero_loads = []
    stores = []
    
    for offset in range(len(stag4000) - 4):
        word = struct.unpack("<I", stag4000[offset:offset+4])[0]
        opcode = (word >> 26) & 0x3F
        
        # addiu $rX, $zero, 0: opcode 0x08, rs=0 (zero), immediate=0
        if opcode == 0x08:
            rs = (word >> 21) & 0x1F
            imm = word & 0xFFFF
            if rs == 0 and imm == 0:
                zero_loads.append(offset)
        
        # sb: opcode 0x28
        if opcode == 0x28:
            stores.append(offset)
    
    print(f"STAG4000.PRO analysis:")
    print(f"  Found {len(zero_loads)} addiu $rX, $zero, 0 instructions")
    print(f"  Found {len(stores)} sb instructions")
    print(f"  Potential zero-store pairs: {len([z for z in zero_loads if any(s > z and s < z + 20 for s in stores)])}")
    
    with open(OUT / "transfer_stag4000_analysis.txt", "w") as f:
        f.write(f"STAG4000.PRO (65536 bytes):\n\n")
        f.write(f"Zero loads (addiu $rX, $zero, 0):\n")
        for off in zero_loads[:50]:
            f.write(f"  +0x{off:06X}\n")
        
        f.write(f"\nStore byte (sb) instructions:\n")
        for off in stores[:50]:
            f.write(f"  +0x{off:06X}\n")
        
        f.write(f"\nPotential disable sequences (zero load followed by sb):\n")
        for z_off in zero_loads:
            for s_off in stores:
                if z_off < s_off < z_off + 80:  # ~20 instructions
                    f.write(f"  +0x{z_off:06X} (addiu $0, 0) -> +0x{s_off:06X} (sb) [distance: {s_off - z_off} bytes]\n")


def search_all_stag_for_consistent_store_pattern():
    """
    Find stores to a consistent offset across all STAG files.
    If Transfer disable uses a dedicated flag at a fixed offset,
    it would appear in the same location in multiple domain handlers.
    """
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        
        stag_offsets = {}
        for file_idx in range(380, 450):
            try:
                data = bytes(disc.read_file(file_idx))
            except:
                continue
            
            if len(data) < 100:
                continue
            
            # Look for sb to offset 0xA0 (common menu struct offset)
            for off in range(len(data) - 4):
                word = struct.unpack("<I", data[off:off+4])[0]
                opcode = (word >> 26) & 0x3F
                
                if opcode == 0x28:  # sb
                    imm = word & 0xFFFF
                    imm_signed = imm if imm < 0x8000 else imm - 0x10000
                    
                    # Look for stores to offset 0xA0, 0xA1, 0xA2, 0xA3
                    if 0xA0 <= imm <= 0xA3 or -96 <= imm_signed <= -93:
                        if 'idx_' not in stag_offsets:
                            stag_offsets[imm] = []
                        stag_offsets[imm].append((file_idx, off))
    
    with open(OUT / "transfer_consistent_store_pattern.txt", "w") as f:
        f.write("Stores to consistent offsets across STAG files:\n\n")
        for imm, locations in sorted(stag_offsets.items()):
            f.write(f"Offset 0x{imm:04X}: {len(locations)} occurrences\n")
            for file_idx, off in locations[:10]:
                f.write(f"  file_{file_idx} + 0x{off:06X}\n")


def main():
    print("Final Transfer menu disable analysis...\n")
    search_stag4000_for_menu_disables()
    print()
    search_all_stag_for_consistent_store_pattern()
    print(f"\nWrote detailed analysis to {OUT / 'transfer_stag4000_analysis.txt'}")
    print(f"Wrote consistent patterns to {OUT / 'transfer_consistent_store_pattern.txt'}")


if __name__ == "__main__":
    main()
