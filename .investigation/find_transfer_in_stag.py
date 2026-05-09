#!/usr/bin/env python3
"""
Search STAG files (402, 403, 410) for lbu at 0x0/0xD followed by sb.
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

# Estimate STAG load base
STAG_LOAD_BASE = 0x80060000


def find_patterns_in_file(file_idx: int, file_name: str) -> list[dict]:
    """Find lbu at 0x0/0xD + sb patterns in a single file."""
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        data = bytes(disc.read_file(file_idx))
    
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    
    instructions = []
    for instr in md.disasm(data, STAG_LOAD_BASE):
        instructions.append({
            'addr': instr.address,
            'offset': instr.address - STAG_LOAD_BASE,
            'mnemonic': instr.mnemonic.lower(),
            'op_str': instr.op_str,
        })
    
    # Find lbu at 0x0 or 0xD
    results = []
    for i, instr in enumerate(instructions):
        if instr['mnemonic'] == 'lbu':
            if '0x0)' in instr['op_str'] or '0xd)' in instr['op_str'].lower():
                # Look for sb within next 30 instructions
                for j in range(i + 1, min(i + 30, len(instructions))):
                    if instructions[j]['mnemonic'] == 'sb':
                        results.append({
                            'lbu_idx': i,
                            'lbu_addr': instr['addr'],
                            'lbu_offset': instr['offset'],
                            'lbu_op': instr['op_str'],
                            'sb_idx': j,
                            'sb_addr': instructions[j]['addr'],
                            'sb_offset': instructions[j]['offset'],
                            'sb_op': instructions[j]['op_str'],
                            'distance': j - i,
                            'instructions': instructions,
                        })
                        break
    
    return results


def main() -> int:
    stag_files = [
        (400, "file_400"),
        (402, "STAG2000.PRO"),
        (403, "STAG3000.PRO"),
        (410, "STAG4000.PRO"),
    ]
    
    all_patterns = {}
    
    for file_idx, file_name in stag_files:
        print(f"Scanning {file_name} (file {file_idx})...")
        patterns = find_patterns_in_file(file_idx, file_name)
        all_patterns[file_name] = patterns
        print(f"  Found {len(patterns)} patterns\n")
    
    # Write summary
    with open(OUT / "transfer_stag_lbu_sb_patterns.txt", "w") as f:
        for file_name, patterns in all_patterns.items():
            f.write(f"\n{'='*80}\n{file_name}\n{'='*80}\n\n")
            f.write(f"Found {len(patterns)} lbu at 0x0/0xD + sb patterns:\n\n")
            
            for idx, pat in enumerate(patterns[:20]):
                f.write(f"\n--- Pattern {idx+1} ---\n")
                f.write(f"lbu at file+0x{pat['lbu_offset']:06X} (RAM 0x{pat['lbu_addr']:08X}): {pat['lbu_op']}\n")
                f.write(f"sb  at file+0x{pat['sb_offset']:06X} (RAM 0x{pat['sb_addr']:08X}): {pat['sb_op']}\n")
                f.write(f"Distance: {pat['distance']} instructions\n")
                
                # Show context
                start_idx = max(0, pat['lbu_idx'] - 5)
                end_idx = min(len(pat['instructions']), pat['sb_idx'] + 6)
                f.write("\nContext:\n")
                for j in range(start_idx, end_idx):
                    instr = pat['instructions'][j]
                    marker = ""
                    if j == pat['lbu_idx']:
                        marker = " <<< LBU"
                    elif j == pat['sb_idx']:
                        marker = " <<< SB"
                    f.write(f"  0x{instr['addr']:08X}: {instr['mnemonic']:<8} {instr['op_str']:<30} {marker}\n")
    
    print(f"Wrote patterns to {OUT / 'transfer_stag_lbu_sb_patterns.txt'}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
