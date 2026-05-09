#!/usr/bin/env python3
"""
Search SLUS for the Transfer menu disable check.
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

# SLUS is at a fixed offset in the disc
SLUS_LOAD_BASE = 0x80010000


def find_menu_check_patterns(slus_data: bytes) -> list[dict]:
    """Find patterns of lbu (location load) -> sb (status store) within SLUS."""
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    
    instructions = []
    for instr in md.disasm(slus_data, SLUS_LOAD_BASE):
        instructions.append({
            'addr': instr.address,
            'offset': instr.address - SLUS_LOAD_BASE,
            'mnemonic': instr.mnemonic.lower(),
            'op_str': instr.op_str,
        })
    
    # Find lbu instructions (locationId loads)
    results = []
    for i, instr in enumerate(instructions):
        if instr['mnemonic'] == 'lbu':
            # Check for 0x0 or 0xD offsets
            if '0x0)' in instr['op_str'] or '0xd)' in instr['op_str'].lower():
                # Found a potential locationId load
                # Look ahead for an sb (store byte) within ~30 instructions
                for j in range(i + 1, min(i + 30, len(instructions))):
                    if instructions[j]['mnemonic'] == 'sb':
                        # Found a potential disable pattern
                        context = {
                            'lbu_addr': instr['addr'],
                            'lbu_offset': instr['offset'],
                            'lbu_op': instr['op_str'],
                            'sb_addr': instructions[j]['addr'],
                            'sb_offset': instructions[j]['offset'],
                            'sb_op': instructions[j]['op_str'],
                            'distance': j - i,
                            'lbu_idx': i,
                            'sb_idx': j,
                            'instructions': instructions,
                        }
                        results.append(context)
                        break
    
    return results


def main() -> int:
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        slus_data = bytes(disc.slus)
    
    print(f"SLUS: {len(slus_data)} bytes")
    print(f"Load base: 0x{SLUS_LOAD_BASE:08X}\n")
    
    print("Searching for lbu + sb patterns (locationId load + status store)...")
    patterns = find_menu_check_patterns(slus_data)
    print(f"Found {len(patterns)} potential patterns\n")
    
    # Write out the first 30 patterns
    with open(OUT / "transfer_slus_lbu_sb_patterns.txt", "w") as f:
        for i, pat in enumerate(patterns[:30]):
            f.write(f"\n--- Pattern {i+1} ---\n")
            f.write(f"lbu at SLUS+0x{pat['lbu_offset']:06X} (0x{pat['lbu_addr']:08X}): {pat['lbu_op']}\n")
            f.write(f"sb  at SLUS+0x{pat['sb_offset']:06X} (0x{pat['sb_addr']:08X}): {pat['sb_op']}\n")
            f.write(f"Distance: {pat['distance']} instructions\n")
    
    print(f"Wrote {len(patterns[:30])} patterns to {OUT / 'transfer_slus_lbu_sb_patterns.txt'}")
    
    # Write detailed context for first 5 patterns
    with open(OUT / "transfer_slus_pattern_contexts.txt", "w") as f:
        for i, pat in enumerate(patterns[:5]):
            f.write(f"\n{'='*80}\n")
            f.write(f"Pattern {i+1}: lbu at 0x{pat['lbu_addr']:08X}, sb at 0x{pat['sb_addr']:08X}\n")
            f.write(f"{'='*80}\n\n")
            
            # Show 5 instructions before lbu, all from lbu to sb, 5 after sb
            start_idx = max(0, pat['lbu_idx'] - 5)
            end_idx = min(len(pat['instructions']), pat['sb_idx'] + 6)
            
            for j in range(start_idx, end_idx):
                instr = pat['instructions'][j]
                marker = ""
                if j == pat['lbu_idx']:
                    marker = " <<< LBU (locationId load)"
                elif j == pat['sb_idx']:
                    marker = " <<< SB (status store)"
                f.write(f"  0x{instr['addr']:08X}: {instr['mnemonic']:<8} {instr['op_str']:<30} {marker}\n")
    
    print(f"Wrote detailed contexts to {OUT / 'transfer_slus_pattern_contexts.txt'}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
