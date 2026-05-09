#!/usr/bin/env python3
"""
Search for the code that disables the Transfer menu option in dungeons.

Hypothesis: the code either:
1. Reads locationId1 (save+0x0) or locationId2 (save+0xD)
2. Compares it against a "transfer-allowed" location ID
3. Sets a "disabled" flag on the menu item if not in an allowed location

The save mirror base is at RAM 0x80060000.
locationId1 would be at RAM 0x80060000 + 0x0
locationId2 would be at RAM 0x80060000 + 0xD

We'll search in STAG4000.PRO (field handler) and SLUS for patterns:
- lui $r?, 0x8006; lbu/lb $r?, 0x0/0xD($r?)  (load locationId)
- sb $r?, <offset>($r?)  (store "disabled" flag)
- Comparisons/branches conditioned on location
"""

from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import patch_dw2 as dw2

BIN = HERE / "dw2.bin"
OUT = HERE / "out"
OUT.mkdir(exist_ok=True)


def disasm_mips(data: bytes, base_addr: int) -> list[str]:
    """Quick MIPS disassembler (using the built-in from patch_dw2)."""
    lines = []
    for i in range(0, len(data), 4):
        if i + 4 > len(data):
            break
        word = struct.unpack("<I", data[i : i + 4])[0]
        addr = base_addr + i
        # Try to decode a few common patterns
        lines.append(f"0x{addr:08X}: {word:08X}")
    return lines


def search_stag4000():
    """Search STAG4000.PRO (file 410) for menu-disable patterns."""
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        stag4000_data = bytes(disc.read_file(410))

    print(f"STAG4000.PRO: {len(stag4000_data)} bytes")
    
    # Known patch sites from DW2-TT:
    # DigimonGiftPatcher: 0x7060, 0x706C
    # DigiBeetlePatcher: 0x940
    
    # Let's examine windows around these
    patch_sites = [0x940, 0x7060, 0x706C]
    
    with open(OUT / "transfer_stag4000_patches.txt", "w") as f:
        for site in patch_sites:
            f.write(f"\n=== Around STAG4000.PRO + 0x{site:04X} ===\n")
            start = max(0, site - 0x100)
            end = min(len(stag4000_data), site + 0x100)
            chunk = stag4000_data[start:end]
            
            for offset in range(0, len(chunk), 4):
                addr = 0x80060000 + start + offset  # approximate load address
                if offset + 4 <= len(chunk):
                    word = struct.unpack("<I", chunk[offset : offset + 4])[0]
                    f.write(f"  0x{addr:08X}: {word:08X}\n")
    
    print(f"Wrote inspection to {OUT / 'transfer_stag4000_patches.txt'}")


def search_slus_patterns():
    """Search SLUS for any code that reads locationId and disables something."""
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        slus_data = bytes(disc.slus)
    
    print(f"SLUS: {len(slus_data)} bytes")
    
    # Search for the pattern: lui $r?, 0x8006 followed (within a few words) by lbu/lb $r?, 0x0 or 0xD
    # lui opcode: 0x3C (bits 26-31 in MIPS, but in little-endian at the low byte)
    
    lui_pattern = bytes([0x0F, 0x3C])  # lui $r?, immediate (little-endian, incomplete)
    
    # Let's just find all lbu/lb at offsets 0x0 and 0xD and examine their context
    with open(OUT / "transfer_slus_locationid_loads.txt", "w") as f:
        # Look for lbu/lb 0x0(reg) and lbu/lb 0xD(reg)
        for offset in range(len(slus_data) - 4):
            word = struct.unpack("<I", slus_data[offset : offset + 4])[0]
            
            # Check for lbu $r?, 0x0(reg): opcode 0x90, offset 0x0000
            # Check for lbu $r?, 0xD(reg): opcode 0x90, offset 0x000D
            opcode = (word >> 26) & 0x3F
            immediate = word & 0xFFFF
            
            if opcode == 0x24:  # addiu
                imm_signed = immediate if immediate < 0x8000 else immediate - 0x10000
                if imm_signed == 0x0 or imm_signed == 0xD:
                    # Could be loading locationId
                    # Show context
                    start = max(0, offset - 16)
                    end = min(len(slus_data), offset + 20)
                    f.write(f"\n=== Potential locationId load at SLUS+0x{offset:06X} ===\n")
                    for ctx_off in range(start, end, 4):
                        ctx_word = struct.unpack("<I", slus_data[ctx_off : ctx_off + 4])[0]
                        f.write(f"  SLUS+0x{ctx_off:06X}: {ctx_word:08X}\n")
    
    print(f"Wrote scan to {OUT / 'transfer_slus_locationid_loads.txt'}")


def search_file_382_to_413():
    """
    DW2-TT patches suggest STAG* files (402, 403, 410) handle menu/field logic.
    Let's search all of them plus nearby files for locationId reads and sb stores.
    """
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        
        # Stage files range: typically 400-420
        with open(OUT / "transfer_stage_files_scan.txt", "w") as f:
            for idx in range(380, 425):
                try:
                    data = bytes(disc.read_file(idx))
                except Exception:
                    continue
                
                if len(data) == 0:
                    continue
                
                # Search for:
                # - lbu at offset 0x0 or 0xD (locationId reads)
                # - sb (store byte) instructions
                
                lui_count = 0
                lbu_0_count = 0
                lbu_d_count = 0
                sb_count = 0
                
                for off in range(0, len(data) - 4, 4):
                    word = struct.unpack("<I", data[off : off + 4])[0]
                    opcode = (word >> 26) & 0x3F
                    imm = word & 0xFFFF
                    
                    if opcode == 0x0F:  # lui
                        if imm == 0x8006:
                            lui_count += 1
                    elif opcode == 0x24:  # addiu
                        imm_signed = imm if imm < 0x8000 else imm - 0x10000
                        if imm_signed == 0x0:
                            lbu_0_count += 1
                        elif imm_signed == 0xD:
                            lbu_d_count += 1
                    elif opcode == 0x28:  # sb (opcode for store byte)
                        sb_count += 1
                
                if lui_count > 0 or lbu_0_count > 0 or lbu_d_count > 0 or sb_count > 0:
                    f.write(f"\nfile_{idx}: lui(0x8006)={lui_count} lbu_0={lbu_0_count} lbu_d={lbu_d_count} sb={sb_count}\n")
    
    print(f"Wrote stage file scan to {OUT / 'transfer_stage_files_scan.txt'}")


def main() -> int:
    print("Searching for Transfer menu disable mechanism...\n")
    search_stag4000()
    search_slus_patterns()
    search_file_382_to_413()
    print("\nDone. Check .investigation/out/ for results.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
