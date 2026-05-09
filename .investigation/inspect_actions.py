#!/usr/bin/env python3
"""
Disassemble file_402 (STAG2000.PRO) at offsets 0x3C44 and 0x436C — the
two action stubs paired with `is_story_lt_10` in the gate table at
file_403 + 0xFCE0. Understanding what each one does lets us confirm
whether the gate is actually the Tera Domain entrance.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import patch_dw2 as dw2

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

BIN = HERE / "dw2.bin"
STAG_LOAD_BASE = 0x80060000


def main() -> int:
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        s2 = bytes(disc.read_file(402))   # STAG2000.PRO

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    md.skipdata = True
    md.skipdata_setup = ("data", None, None)

    # Disassemble each action function up to its `jr $ra` (or until we
    # see a clear function boundary).
    for off in (0x3C44, 0x436C):
        print(f"\n========= file_402 (STAG2000.PRO) offset 0x{off:04X}  /  RAM 0x{STAG_LOAD_BASE + off:08X} =========")
        # Disassemble at most 256 bytes; stop at jr $ra + nop.
        chunk = s2[off : off + 320]
        for ins in md.disasm(chunk, STAG_LOAD_BASE + off):
            print(f"  0x{ins.address:08X}: {ins.bytes.hex():<8} {ins.mnemonic:<8} {ins.op_str}")
            if ins.mnemonic == "jr" and "$ra" in ins.op_str:
                # one more delay-slot instruction, then stop
                continue
            if ins.address - (STAG_LOAD_BASE + off) > 200:
                break

    return 0


if __name__ == "__main__":
    sys.exit(main())
