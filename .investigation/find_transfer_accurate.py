#!/usr/bin/env python3
"""
Search for Transfer menu disable using accurate load addresses from file headers.
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


def extract_load_address_from_header(data: bytes) -> int | None:
    """
    Some STAG files encode their load address in the header.
    Try to find it by looking for a pointer-like value (0x8006xxxx).
    """
    for offset in range(0, min(128, len(data)), 4):
        word = struct.unpack("<I", data[offset:offset+4])[0]
        if 0x80060000 <= word < 0x80068000:
            return word
    return None


def disasm_file_with_accurate_addr(file_idx: int, file_name: str):
    """Disassemble a file using its actual load address."""
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        data = bytes(disc.read_file(file_idx))
    
    # Try to find the load address from the header
    load_addr = extract_load_address_from_header(data)
    if not load_addr:
        print(f"  Could not determine load address for {file_name}")
        return None
    
    print(f"  {file_name}: load address = 0x{load_addr:08X}")
    
    # Now find patterns in this file
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    
    instructions = []
    try:
        for instr in md.disasm(data, load_addr):
            instructions.append({
                'addr': instr.address,
                'offset': instr.address - load_addr,
                'mnemonic': instr.mnemonic.lower(),
                'op_str': instr.op_str,
            })
    except Exception as e:
        print(f"    Disasm failed: {e}")
        return None
    
    # Look for beq/bne that might disable Transfer based on location
    # Pattern: load locationId -> compare -> conditional branch -> sb (store disabled flag)
    
    # Simplified: just look for lbu + branch + sb patterns
    results = []
    for i, instr in enumerate(instructions):
        if instr['mnemonic'] in ['lbu', 'lb']:
            # Found a load, look for branch and sb
            for j in range(i + 1, min(i + 20, len(instructions))):
                if instructions[j]['mnemonic'] in ['beq', 'bne', 'beqz', 'bnez']:
                    # Found a branch
                    for k in range(j + 1, min(j + 15, len(instructions))):
                        if instructions[k]['mnemonic'] == 'sb':
                            results.append({
                                'lbu': instr,
                                'branch': instructions[j],
                                'sb': instructions[k],
                                'distance': k - i,
                            })
                            break
                    break
    
    return {
        'file_name': file_name,
        'load_addr': load_addr,
        'instr_count': len(instructions),
        'patterns': results[:10],
    }


def main() -> int:
    stag_files = [
        (400, "file_400"),
        (402, "STAG2000.PRO"),
        (403, "STAG3000.PRO"),
        (410, "STAG4000.PRO"),
    ]
    
    print("Disassembling STAG files with accurate load addresses:\n")
    
    with open(OUT / "transfer_accurate_disasm.txt", "w") as f:
        for file_idx, file_name in stag_files:
            result = disasm_file_with_accurate_addr(file_idx, file_name)
            if result:
                f.write(f"\n{file_name} (file {file_idx}):\n")
                f.write(f"  Load address: 0x{result['load_addr']:08X}\n")
                f.write(f"  Instructions: {result['instr_count']}\n")
                f.write(f"  lbu + branch + sb patterns: {len(result['patterns'])}\n")
                
                for idx, pat in enumerate(result['patterns'][:5]):
                    f.write(f"\n  Pattern {idx+1}:\n")
                    f.write(f"    lbu at 0x{pat['lbu']['addr']:08X}: {pat['lbu']['op_str']}\n")
                    f.write(f"    {pat['branch']['mnemonic']} at 0x{pat['branch']['addr']:08X}: {pat['branch']['op_str']}\n")
                    f.write(f"    sb at 0x{pat['sb']['addr']:08X}: {pat['sb']['op_str']}\n")
                    f.write(f"    Total distance: {pat['distance']} instructions\n")
    
    print(f"\nWrote results to {OUT / 'transfer_accurate_disasm.txt'}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
