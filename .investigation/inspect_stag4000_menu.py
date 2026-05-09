#!/usr/bin/env python3
"""
Disassemble sections of STAG4000.PRO to find menu-disable logic.
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

# Import the MIPS disassembler from the existing investigation code
sys.path.insert(0, str(HERE))

# Try to use capstone if available
try:
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_BIG_ENDIAN
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False
    print("capstone not available, using manual patterns")


def disasm_window(data: bytes, base_addr: int, start_off: int, end_off: int) -> str:
    """Disassemble a window using capstone if available."""
    if not HAVE_CAPSTONE:
        return "(capstone not available)"
    
    chunk = data[start_off:end_off]
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN)
    
    out = []
    for instr in md.disasm(chunk, base_addr + start_off):
        out.append(f"  0x{instr.address:08X}: {instr.mnemonic} {instr.op_str}")
    return "\n".join(out) if out else "(empty)"


def find_lbu_0_contexts(data: bytes):
    """Find all lbu/lb at offset 0x0, show surrounding code."""
    results = []
    
    for off in range(0, len(data) - 4, 4):
        word = struct.unpack("<I", data[off : off + 4])[0]
        opcode = (word >> 26) & 0x3F
        immediate = word & 0xFFFF
        
        # Check for lbu/lb at offset 0x0
        if opcode == 0x24 and immediate == 0x0:  # addiu? No, that's wrong
            # Actually lbu is opcode 0x24 (100100 = 0x24)
            # But the immediate field is the offset for indexed loads
            # Let me check the actual MIPS opcode table
            pass
    
    # This is getting complicated. Let me use a simpler approach:
    # Just extract and print chunks around known patterns
    
    for idx in range(len(data) - 4):
        word = struct.unpack("<I", data[idx : idx + 4])[0]
        
        # Check for lbu $r?, 0x0($r?)
        # MIPS encoding: opcode(6) rs(5) rt(5) offset(16)
        # lbu: opcode 0x24
        opcode = (word >> 26) & 0x3F
        offset_field = word & 0xFFFF
        
        if opcode == 0x24 and offset_field == 0x0:
            # Found a potential lbu at offset 0
            results.append({
                'file_offset': idx,
                'word': word,
                'context_start': max(0, idx - 32),
                'context_end': min(len(data), idx + 48),
            })
    
    return results


def main() -> int:
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        stag4000 = bytes(disc.read_file(410))
    
    print(f"STAG4000.PRO ({len(stag4000)} bytes)")
    print(f"Load address: ~0x80000000 + file_offset (guessing)")
    
    # Find lbu at offset 0x0
    lbu_0_contexts = find_lbu_0_contexts(stag4000)
    print(f"\nFound {len(lbu_0_contexts)} lbu at offset 0x0:")
    
    with open(OUT / "transfer_stag4000_lbu_contexts.txt", "w") as f:
        for ctx in lbu_0_contexts[:20]:  # Show first 20
            f.write(f"\n=== STAG4000 + 0x{ctx['file_offset']:04X} (lbu at 0x0) ===\n")
            
            chunk = stag4000[ctx['context_start']:ctx['context_end']]
            base = 0x80000000  # Guess
            for off in range(0, len(chunk), 4):
                addr = base + ctx['context_start'] + off
                word = struct.unpack("<I", chunk[off:off+4])[0]
                
                # Mark the line with lbu
                marker = " <<< LBU" if ctx['context_start'] + off == ctx['file_offset'] else ""
                f.write(f"  0x{addr:08X}: {word:08X}{marker}\n")
    
    print(f"Wrote contexts to {OUT / 'transfer_stag4000_lbu_contexts.txt'}")
    
    # Also examine the known patch sites
    print("\nExamining known DW2-TT patch sites in STAG4000:")
    with open(OUT / "transfer_stag4000_known_patches.txt", "w") as f:
        for site_name, site_off, context_size in [
            ("DigiBeetlePatcher", 0x940, 0x200),
            ("DigimonGiftPatcher_1", 0x7060, 0x200),
            ("DigimonGiftPatcher_2", 0x706C, 0x200),
        ]:
            f.write(f"\n=== {site_name} at +0x{site_off:04X} ===\n")
            start = max(0, site_off - 64)
            end = min(len(stag4000), site_off + context_size)
            chunk = stag4000[start:end]
            
            for off in range(0, len(chunk), 4):
                addr = 0x80000000 + start + off
                word = struct.unpack("<I", chunk[off:off+4])[0]
                marker = " <<< PATCH SITE" if start + off == site_off else ""
                f.write(f"  0x{addr:08X}: {word:08X}{marker}\n")
    
    print(f"Wrote patch sites to {OUT / 'transfer_stag4000_known_patches.txt'}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
