#!/usr/bin/env python3
"""
Step 4b: full-disc sweep for callers of the story_progress stubs in
file_402/STAG2000.PRO.

Scans every entry in the SLUS file-LUT (3675 entries) for `jal X` words
whose target lies in the story-lib runtime range [0x80063AF0,
0x80063E80). Reports per-file hit counts and the ASCII dump of any
trailing PSX-EXE-like header so we can identify what kind of file it is.
"""

from __future__ import annotations

import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import patch_dw2 as dw2

OUT = HERE / "out"
OUT.mkdir(exist_ok=True)
BIN = HERE / "dw2.bin"

STAG_LOAD_BASE = 0x80060000

STORY_LIB = {
    "is_story_lt_2":  0x80063AF0,
    "is_story_lt_3":  0x80063B00,
    "is_story_lt_4":  0x80063B10,
    "is_story_lt_5":  0x80063B20,
    "is_story_lt_6":  0x80063B30,
    "is_story_lt_7":  0x80063B40,
    "is_story_lt_8":  0x80063B50,
    "is_story_lt_9":  0x80063B60,
    "is_story_lt_10": 0x80063B70,
    "is_story_lt_11": 0x80063B80,
    "set_story_1":  0x80063DE0,
    "set_story_2":  0x80063DF0,
    "set_story_3":  0x80063E00,
    "set_story_4":  0x80063E10,
    "set_story_5":  0x80063E20,
    "set_story_6":  0x80063E30,
    "set_story_7":  0x80063E40,
    "set_story_8":  0x80063E50,
    "set_story_9":  0x80063E60,
    "set_story_10": 0x80063E70,
}
ADDR_TO_LABEL = {addr: label for label, addr in STORY_LIB.items()}
LIB_LO, LIB_HI = 0x80063AF0, 0x80063E80


def scan_jal_targets(data: bytes):
    hits = []
    for off in range(0, len(data) - 3, 4):
        word = int.from_bytes(data[off : off + 4], "little")
        if (word >> 26) != 0x03:  # jal opcode
            continue
        target = ((word & 0x03FFFFFF) << 2) | 0x80000000
        if LIB_LO <= target < LIB_HI:
            hits.append((off, target, ADDR_TO_LABEL.get(target)))
    return hits


def main() -> int:
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        # SLUS too.
        slus_hdr_size = struct.unpack_from("<I", bytes(disc.slus), 0x1C)[0]
        slus_text = bytes(disc.slus)[0x800 : 0x800 + slus_hdr_size]

        # Tally hits per file.
        per_file: dict[str, list] = {}
        per_label: Counter[str | None] = Counter()
        unique_targets: Counter[int] = Counter()

        # Scan SLUS first.
        hits = scan_jal_targets(slus_text)
        if hits:
            per_file["SLUS_011.93"] = hits
            for _, tgt, lbl in hits:
                per_label[lbl] += 1
                unique_targets[tgt] += 1

        # Scan every LUT entry.
        n_files_total = len(disc.lba)
        n_scanned = 0
        n_with_hits = 0
        for idx in range(n_files_total):
            if disc.size[idx] == 0:
                continue
            try:
                data = bytes(disc.read_file(idx))
            except Exception:
                continue
            n_scanned += 1
            if len(data) < 4:
                continue
            hits = scan_jal_targets(data)
            if not hits:
                continue
            n_with_hits += 1
            per_file[f"file_{idx}"] = hits
            for _, tgt, lbl in hits:
                per_label[lbl] += 1
                unique_targets[tgt] += 1

    print(f"Scanned {n_scanned} non-empty files (out of LUT size {n_files_total})")
    print(f"{n_with_hits} files contain at least one jal into the story_progress lib range\n")

    print("Hits per known label:")
    for lbl in sorted(STORY_LIB):
        addr = STORY_LIB[lbl]
        print(f"  {lbl:<20s} (0x{addr:08X}): {per_label.get(lbl, 0)}")
    print(f"\nUnknown-target hits in lib range (off-by-stub-boundary?):")
    for tgt, n in unique_targets.most_common():
        if tgt not in ADDR_TO_LABEL:
            print(f"  0x{tgt:08X}: {n} sites")

    # Detailed per-file table.
    with open(OUT / "story_lib_callers_full.txt", "w") as f:
        f.write(f"Full-disc sweep: jal targets in [0x{LIB_LO:08X}, 0x{LIB_HI:08X}).\n\n")
        f.write(f"Files scanned: {n_scanned}, files with hits: {n_with_hits}\n\n")
        for fname in sorted(per_file):
            f.write(f"=== {fname} ===\n")
            for off, tgt, lbl in per_file[fname]:
                lbl_s = lbl or f"<unknown@0x{tgt:08X}>"
                f.write(f"  file 0x{off:08X}: jal -> 0x{tgt:08X}  ({lbl_s})\n")
            f.write("\n")

    print(f"\nWrote {OUT / 'story_lib_callers_full.txt'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
