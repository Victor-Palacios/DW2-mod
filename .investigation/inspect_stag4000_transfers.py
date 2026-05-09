#!/usr/bin/env python3
"""
Manually disassemble sections of STAG4000.PRO looking for menu initialization code.
"""

from __future__ import annotations

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

STAG4000_LOAD_BASE = 0x80060000


def disasm_region_detailed(data: bytes, file_offset: int, window_size: int = 0x400):
    """Disassemble a region and look for pattern."""
    start = max(0, file_offset - window_size // 2)
    end = min(len(data), file_offset + window_size // 2)
    
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    
    lines = []
    chunk = data[start:end]
    base_addr = STAG4000_LOAD_BASE + start
    
    for instr in md.disasm(chunk, base_addr):
        marker = ""
        if instr.address == STAG4000_LOAD_BASE + file_offset:
            marker = " <<<TARGET"
        lines.append({
            'addr': instr.address,
            'offset': instr.address - STAG4000_LOAD_BASE,
            'mnemonic': instr.mnemonic,
            'op_str': instr.op_str,
            'marker': marker,
        })
    
    return lines


def main() -> int:
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        stag4000 = bytes(disc.read_file(410))
    
    print(f"STAG4000.PRO: {len(stag4000)} bytes")
    
    # Let's search for sequences that write to menu item structs
    # Menu items usually have offsets like 0x10, 0x20, 0x30 (item size)
    # Let's look for repeated sb/sh patterns within loops or if-blocks
    
    # First, let's examine a large swath (0x0 to 0x2000) for menu-init patterns
    with open(OUT / "transfer_stag4000_full_region.txt", "w") as f:
        lines = disasm_region_detailed(stag4000, 0x0, window_size=0x2000)
        
        f.write("=== STAG4000.PRO + 0x0 to 0x1000 ===\n\n")
        for line in lines[:256]:
            f.write(f"  0x{line['addr']:08X}: {line['mnemonic']:<8} {line['op_str']:<30} {line['marker']}\n")
        
        f.write("\n\n=== Looking for repeated sb/sh patterns (menu item disable) ===\n\n")
        
        # Find sequences of sb/sh instructions
        i = 0
        while i < len(lines):
            if lines[i]['mnemonic'] in ['sb', 'sh']:
                # Found a store, look for more nearby
                f.write(f"\nStore sequence at 0x{lines[i]['addr']:08X}:\n")
                for j in range(max(0, i - 2), min(len(lines), i + 10)):
                    f.write(f"  0x{lines[j]['addr']:08X}: {lines[j]['mnemonic']:<8} {lines[j]['op_str']:<30}\n")
                i += 8
            else:
                i += 1
    
    print(f"Wrote full region analysis to {OUT / 'transfer_stag4000_full_region.txt'}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
