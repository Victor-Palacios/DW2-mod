#!/usr/bin/env python3
"""
Use capstone to disassemble STAG4000.PRO and find menu-disable logic.
Focus on the known DW2-TT patch sites.
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

# Estimate load address for STAG4000.PRO
STAG4000_LOAD_BASE = 0x80060000  # based on story_progress being at 0x8005E632 within a STAG file


def disasm_region(data: bytes, file_offset: int, context_size: int = 0x200):
    """Disassemble a region of STAG4000.PRO."""
    start = max(0, file_offset - context_size // 2)
    end = min(len(data), file_offset + context_size // 2)
    chunk = data[start:end]
    
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    
    lines = []
    base_addr = STAG4000_LOAD_BASE + start
    
    for instr in md.disasm(chunk, base_addr):
        marker = " <<<< TARGET" if instr.address == STAG4000_LOAD_BASE + file_offset else ""
        lines.append(f"  0x{instr.address:08X}: {instr.mnemonic:<8} {instr.op_str:<30} {marker}")
    
    return "\n".join(lines)


def main() -> int:
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        stag4000 = bytes(disc.read_file(410))
    
    print(f"STAG4000.PRO: {len(stag4000)} bytes")
    print(f"Estimated load base: 0x{STAG4000_LOAD_BASE:08X}\n")
    
    # Examine known patch sites
    known_sites = [
        ("DigiBeetlePatcher", 0x940),
        ("DigimonGiftPatcher_1", 0x7060),
        ("DigimonGiftPatcher_2", 0x706C),
    ]
    
    with open(OUT / "transfer_stag4000_disasm.txt", "w") as f:
        for site_name, site_off in known_sites:
            f.write(f"\n{'='*80}\n")
            f.write(f"{site_name} at STAG4000 + 0x{site_off:04X}\n")
            f.write(f"{'='*80}\n\n")
            
            disasm = disasm_region(stag4000, site_off, context_size=0x200)
            f.write(disasm)
            f.write("\n")
    
    print(f"Wrote disassembly to {OUT / 'transfer_stag4000_disasm.txt'}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
