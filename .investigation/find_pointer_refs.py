#!/usr/bin/env python3
"""
Step 4c: Search every disc file for raw 32-bit LE pointers to each
story_progress stub. If the stubs are dispatched via a jump table, the
table will literally contain `70 3B 06 80` for is_story_lt_10, etc.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import patch_dw2 as dw2

OUT = HERE / "out"
OUT.mkdir(exist_ok=True)
BIN = HERE / "dw2.bin"

STORY_LIB = {
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


def search_word(data: bytes, word: int) -> list[int]:
    needle = word.to_bytes(4, "little")
    out: list[int] = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def main() -> int:
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        slus_data = bytes(disc.slus)

        all_files: list[tuple[str, bytes]] = [("SLUS_011.93", slus_data)]
        for idx in range(len(disc.lba)):
            if disc.size[idx] == 0:
                continue
            try:
                data = bytes(disc.read_file(idx))
                if len(data) >= 4:
                    all_files.append((f"file_{idx}", data))
            except Exception:
                pass

    print(f"Searching {len(all_files)} files for raw stub pointer refs...\n")

    with open(OUT / "story_lib_pointer_refs.txt", "w") as f:
        for label in sorted(STORY_LIB):
            ptr = STORY_LIB[label]
            print(f"=== {label} ({hex(ptr)}) ===")
            f.write(f"=== {label} ({hex(ptr)}) ===\n")
            total = 0
            for name, data in all_files:
                hits = search_word(data, ptr)
                if hits:
                    total += len(hits)
                    line = f"  {name}: {len(hits)} ref(s) at " + ", ".join(f"0x{h:08X}" for h in hits[:8])
                    if len(hits) > 8:
                        line += f", ... ({len(hits) - 8} more)"
                    print(line)
                    f.write(line + "\n")
            print(f"  total: {total}\n")
            f.write(f"  total: {total}\n\n")

    print(f"\nWrote {OUT / 'story_lib_pointer_refs.txt'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
