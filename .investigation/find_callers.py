#!/usr/bin/env python3
"""
Step 4: find every `jal stub_lt_N` call across SLUS + every STAGxxxx.PRO,
for N in 1..11. The N=10 callers are the Tera Domain gate candidates;
the others give us baseline understanding of how scripts use the
story-progress library.

We assume STAGxxxx.PRO files all load at RAM 0x80060000 (header pointer
analysis confirms this for STAG2000, 3000, 4000). For each `jal X` we
find, we report (file, file_offset, target_addr_within_loaded_region).

We also tabulate every `jal` whose target is within file_402 (the
"story library") in the 0x80063AF0..0x80063E80 range.
"""

from __future__ import annotations

import struct
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import patch_dw2 as dw2

OUT = HERE / "out"
OUT.mkdir(exist_ok=True)
BIN = HERE / "dw2.bin"

STAG_LOAD_BASE = 0x80060000

# Inferred from disassembly of file_402:
STORY_LIB = {
    # --- READERS: lbu story_progress ; (sltiu $v0, $v0, N) ---
    "is_story_lt_2":  0x80063AF0,
    "is_story_lt_3":  0x80063B00,
    "is_story_lt_4":  0x80063B10,
    "is_story_lt_5":  0x80063B20,
    "is_story_lt_6":  0x80063B30,
    "is_story_lt_7":  0x80063B40,
    "is_story_lt_8":  0x80063B50,
    "is_story_lt_9":  0x80063B60,
    "is_story_lt_10": 0x80063B70,   # <-- candidate Tera Domain gate
    "is_story_lt_11": 0x80063B80,
    # --- WRITERS: sb $v0(=N) into story_progress ---
    "set_story_1":  0x80063DE0,
    "set_story_2":  0x80063DF0,
    "set_story_3":  0x80063E00,
    "set_story_4":  0x80063E10,
    "set_story_5":  0x80063E20,
    "set_story_6":  0x80063E30,
    "set_story_7":  0x80063E40,
    "set_story_8":  0x80063E50,
    "set_story_9":  0x80063E60,
    "set_story_10": 0x80063E70,   # <-- post-credits writer
}

ADDR_TO_LABEL = {addr: label for label, addr in STORY_LIB.items()}


def jal_encoding(target_addr: int) -> int:
    """Return 32-bit jal instruction word for an absolute target (assumes
    target is in same 256MiB region as PC, which is always true on PSX
    with kuseg/kseg0/kseg1)."""
    return 0x0C000000 | ((target_addr >> 2) & 0x03FFFFFF)


def scan_jal_targets(data: bytes, *, file_label: str):
    """Return list of (file_offset, target_addr, label_or_none) for every
    `jal` instruction in `data` whose absolute target lies in the
    STORY_LIB range, or in (STAG_LOAD_BASE + 0x3AF0)..(STAG_LOAD_BASE +
    0x3E80) more generally.
    """
    LOW, HIGH = 0x80063AF0, 0x80063E80
    hits = []
    n = len(data)
    for off in range(0, n - 3, 4):
        word = int.from_bytes(data[off : off + 4], "little")
        # jal opcode = 000011 = 0x03; top 6 bits of instr = opcode.
        if (word >> 26) != 0x03:
            continue
        target = ((word & 0x03FFFFFF) << 2) | 0x80000000
        if LOW <= target < HIGH:
            label = ADDR_TO_LABEL.get(target)
            hits.append((off, target, label))
    return hits


def main() -> int:
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        slus_text = bytes(disc.slus)[0x800 : 0x800 + struct.unpack_from("<I", bytes(disc.slus), 0x1C)[0]]

        files: list[tuple[str, bytes]] = [
            ("SLUS_011.93", slus_text),
        ]
        # Probe a wide range of file indices (most STAG/script files seem to
        # cluster in 395..415, but let's also scan a wider net to make sure
        # we don't miss any callers).
        for cand in range(390, 420):
            try:
                data = bytes(disc.read_file(cand))
                if len(data) >= 4096 and data[:4] != b"\x00\x00\x00\x00":
                    files.append((f"file_{cand}", data))
            except Exception:
                pass

        # Big sweep: also grab every "STAGxxxx" file index. From DW2-TT we
        # know STAG1100, 2000, 3000, 4000 exist. Plus "domain"/"area" files.
        # Check a broader range too: PvP map STAG3000 patch hints other
        # stages exist. Look at file_400 (engine?) and many around it.
        for cand in list(range(0, 50)) + list(range(50, 450, 25)):
            if cand in {f[1] and 0 for f in []}:
                continue
            try:
                data = bytes(disc.read_file(cand))
                if len(data) >= 4096 and data[:4] != b"\x00\x00\x00\x00":
                    name = f"file_{cand}"
                    if not any(n == name for n, _ in files):
                        files.append((name, data))
            except Exception:
                pass

    print(f"Scanning {len(files)} files for jal targets in [0x80063AF0, 0x80063E80)...")

    grouped: dict[str, list] = defaultdict(list)  # label -> list of (file, off)
    raw_hits: list[tuple[str, int, int, str | None]] = []
    for name, data in files:
        hits = scan_jal_targets(data, file_label=name)
        for off, tgt, label in hits:
            grouped[label or f"<unknown@0x{tgt:08X}>"].append((name, off))
            raw_hits.append((name, off, tgt, label))

    # Console summary
    print(f"\nTotal call sites found: {len(raw_hits)}")
    for label in sorted(STORY_LIB):
        addr = STORY_LIB[label]
        sites = grouped.get(label, [])
        print(f"  {label:<20s} ({hex(addr)}): {len(sites)} call sites")
        for fname, foff in sites:
            print(f"    {fname} @ file 0x{foff:08X}")
    other = [k for k in grouped if k.startswith("<unknown")]
    if other:
        print(f"\n  Unknown-target jal in story-lib range: {len(other)} distinct targets")
        for k in other:
            print(f"    {k}: {len(grouped[k])} sites")

    # File output: detail per-call-site, with disassembly context.
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    md.skipdata = True
    md.skipdata_setup = ("data", None, None)

    file_data = {n: d for n, d in files}

    with open(OUT / "story_lib_callers.txt", "w") as f:
        f.write("Call sites for the story_progress library (file_402/STAG2000.PRO).\n")
        f.write("STAGxxxx.PRO files are assumed to load at RAM 0x80060000;\n")
        f.write("for STAG files the disassembly shown is at runtime addresses.\n\n")

        for label in sorted(STORY_LIB):
            addr = STORY_LIB[label]
            sites = grouped.get(label, [])
            f.write(f"=== {label} (target 0x{addr:08X}, {len(sites)} call sites) ===\n")
            for fname, foff in sites:
                data = file_data[fname]
                # Disassemble a 12-instruction window centred on this jal.
                window_start = max(0, foff - 32)
                window_end   = min(len(data), foff + 32)
                if fname == "SLUS_011.93":
                    base = 0x80010000 + window_start
                elif fname.startswith("file_") or fname.startswith("STAG"):
                    base = STAG_LOAD_BASE + window_start
                else:
                    base = window_start
                ins_list = list(md.disasm(data[window_start:window_end], base))
                f.write(f"\n  {fname}: jal at file 0x{foff:08X} (RAM 0x{(STAG_LOAD_BASE if fname.startswith(('file_','STAG')) else 0x80010000)+foff:08X})\n")
                for ins in ins_list:
                    is_jal = (ins.address == (STAG_LOAD_BASE if fname.startswith(("file_","STAG")) else 0x80010000) + foff)
                    f.write(f"      {'>>> ' if is_jal else '    '}0x{ins.address:08X}: {ins.bytes.hex():<8} {ins.mnemonic:<8} {ins.op_str}\n")
            f.write("\n")

    print(f"\nWrote {OUT / 'story_lib_callers.txt'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
