#!/usr/bin/env python3
"""
DW2 Patcher — applies a curated set of Digimon World 2 (USA) patches to a
CHD-format disc image and re-encodes the result back to CHD.

Edit the CONFIG block below, then run:

    python3 patch_dw2.py

Requires `chdman` on PATH (install via `brew install rom-tools`).

This is a Python port of the relevant pieces of acemon33/DW2-TT
(https://github.com/acemon33/DW2-TT, GPL-3.0). All offsets, patch payloads,
and the disc-image / SLUS look-up-table layout are taken directly from that
project's source. US version only.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# CONFIG — edit these values, then run the script.
# ---------------------------------------------------------------------------

INPUT_CHD: str = "Digimon World 2 (USA).chd"
OUTPUT_CHD: str = "Digimon World 2 (USA).patched.chd"

EXP_MULTIPLIER: float = 5.0
BITS_MULTIPLIER: float = 5.0

ENABLE_DIGIMON_GIFT: bool = True
ENABLE_NEXT_LEVEL_LIMIT: bool = True
ENABLE_MP_ON_GUARD_25: bool = True
ENABLE_TECH_ORDERING: bool = True

# Experimental: open Tera Domain at story_progress >= 9 (start of Mission 19,
# Core Tower) rather than the vanilla >= 10 (post-credits). One-byte edit to
# the gate's table entry in STAG3000.PRO; see .investigation/REPORT.md.
ENABLE_TERA_DOMAIN_EARLY_UNLOCK: bool = False

# Constant added to the higher parent's DP when DNA Digivolving (vanilla = 1).
# E.g. with N=3, fusing a DP-4 + DP-2 yields a DP-7 child instead of DP-5.
# Set to 1 to leave vanilla behaviour untouched.
DP_GAIN_PER_FUSION: int = 3

# ---------------------------------------------------------------------------
# Disc / SLUS constants (US version).
# Source: DW2-TT/dw2_exp_multiplier/Base/{PsxSector,DW2Slus,FileIndex}.cs
# ---------------------------------------------------------------------------

SECTOR_RAW = 2352  # full Mode 2 Form 1 sector
SECTOR_HEADER = 24  # sync (12) + header (4) + sub-header (8)
SECTOR_DATA = 2048  # user payload
SECTOR_TRAILER = 280  # EDC (4) + ECC (276)

# SLUS_011.93 (the game executable) sits inside the disc image as a "file"
# at a fixed location. DW2-TT treats it as 318 sectors starting at byte
# offset 0xDC80 from the start of the image, which is sector 0x18 (= 24).
SLUS_BYTE_OFFSET = 0xDC80
SLUS_SECTOR_LBA = SLUS_BYTE_OFFSET // SECTOR_RAW  # 0x18
SLUS_SECTOR_COUNT = 318

# Look-up table (3675 files): for each file index i, lba[i] is the absolute
# disc LBA in 2352-byte sector units, and size[i] is the file's length in
# 2048-byte data sectors.
US_FILE_COUNT = 3675
US_LBA_TABLE_OFFSET = 0x33F94  # uint32[3675] little-endian
US_LBA_TABLE_LEN = 0x396B
US_SIZE_TABLE_OFFSET = 0x37900  # uint16[3675] little-endian
US_SIZE_TABLE_LEN = 0x1CB5

# File indices we patch.
IDX_STAG2000_PRO = 402
IDX_STAG3000_PRO = 403
IDX_STAG4000_PRO = 410
IDX_ENEMYSET_BIN = 3183

# PSX executable header — every PSX SLUS file begins with this 8-byte magic.
PSX_EXE_MAGIC = b"PS-X EXE"

# ---------------------------------------------------------------------------
# Patch payloads (US version) — taken verbatim from DW2-TT.
# ---------------------------------------------------------------------------

# Digimon Gift — DW2-TT/Patcher/Misc/DigimonGiftPatcher.cs
# In STAG4000.PRO. Two 4-byte writes at 0x7060 and 0x706C, both originally
# zeroed.
DIGIMON_GIFT_OFFSET_1 = 0x7060
DIGIMON_GIFT_BYTES_1 = bytes([0x03, 0x00, 0x06, 0x24])
DIGIMON_GIFT_OFFSET_2 = 0x706C
DIGIMON_GIFT_BYTES_2 = bytes([0x05, 0x00, 0x06, 0xA2])
DIGIMON_GIFT_VANILLA = bytes([0x00, 0x00, 0x00, 0x00])

# Next Level Limit — DW2-TT/Patcher/BattleFeature/NextLevelLimitPatcher.cs
# In STAG3000.PRO. Single 4-byte write at 0xE688.
NEXT_LEVEL_OFFSET = 0xE688
NEXT_LEVEL_BYTES = bytes([0x6C, 0xC6, 0x01, 0x08])
NEXT_LEVEL_VANILLA = bytes([0x7E, 0xC6, 0x01, 0x08])

# MP-on-Guard 25% — DW2-TT/Patcher/BattleEnhancement/MpOnGuardPatcher.cs
# In STAG3000.PRO. 36-byte block at 0x9774.
MP_ON_GUARD_OFFSET = 0x9774
MP_ON_GUARD_BYTES = bytes(
    [
        0x04, 0x00, 0x05, 0x24,
        0x1B, 0x00, 0x85, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x12, 0x18, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x32, 0x00, 0xC2, 0x94,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ]
)
# DW2-TT validates 36 known vanilla bytes at the same offset before patching.
MP_ON_GUARD_VANILLA = bytes(
    [
        0x67, 0x66, 0xA5, 0x34, 0x00, 0x24, 0x04, 0x00,
        0x03, 0x14, 0x04, 0x00, 0x18, 0x00, 0x45, 0x00,
        0xC3, 0x27, 0x04, 0x00, 0x32, 0x00, 0xC2, 0x94,
        0x10, 0x38, 0x00, 0x00, 0x83, 0x18, 0x07, 0x00,
        0x23, 0x18, 0x64, 0x00,
    ]
)

# Tech Ordering — DW2-TT/Patcher/BattleFeature/TechOrderingPatcher.cs
# Adds an R1-trigger menu option in the post-battle Learn Tech screen that
# lets the player rearrange a Digimon's techs. Patches STAG3000.PRO at four
# small redirection sites and writes a 136-byte trampoline into the unused
# region near the end of the file (which maps to RAM around 0x80074198).
TECH_ORDERING_REDIRECTS: tuple[tuple[int, bytes, bytes], ...] = (
    (0x4680,
     bytes([0x00, 0x00, 0x00, 0x00]),
     bytes([0x00, 0x00, 0x59, 0x34])),
    (0x484C,
     bytes([0x73, 0x00, 0xC0, 0x13]),
     bytes([0x66, 0xD0, 0x01, 0x08])),
    (0xE94C,
     bytes([0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x40, 0x10]),
     bytes([0x6E, 0xD0, 0x01, 0x08, 0x03, 0x00, 0x44, 0x30])),
    (0x4A24,
     bytes([0x9C, 0x00, 0xBF, 0x8F]),
     bytes([0x74, 0xD0, 0x01, 0x08])),
)
TECH_ORDERING_TRAMPOLINE_OFFSET = 0x10E38
TECH_ORDERING_TRAMPOLINE_BYTES = bytes(
    [
        0x05, 0x00, 0xC0, 0x17, 0x02, 0x00, 0x27, 0x2F,
        0x03, 0x00, 0xE0, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x5F, 0x9F, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00,
        0xED, 0x9E, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x80, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x2D, 0xC7, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x30, 0xC7, 0x01, 0x08, 0x00, 0x00, 0x04, 0x36,
        0x06, 0x80, 0x14, 0x3C, 0x10, 0xF7, 0x91, 0x8E,
        0x07, 0x80, 0x14, 0x3C, 0x0D, 0x00, 0x20, 0x12,
        0x00, 0x00, 0x12, 0x24, 0x0C, 0x40, 0x93, 0x92,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x76, 0x2E,
        0x09, 0x00, 0xC0, 0x12, 0x0C, 0x40, 0x93, 0x92,
        0x01, 0x00, 0x52, 0x26, 0x02, 0x00, 0x60, 0x16,
        0x02, 0x00, 0x13, 0x24, 0x04, 0x00, 0x13, 0x24,
        0x0C, 0x40, 0x93, 0xA2, 0x03, 0x00, 0x55, 0x2E,
        0xF8, 0xFF, 0xA0, 0x16, 0x01, 0x00, 0x94, 0x26,
        0x63, 0x9F, 0x01, 0x08, 0x9C, 0x00, 0xBF, 0x8F,
    ]
)
# DW2-TT validates this 0x88-byte window of zeros (immediately after the
# trampoline target) as the "is this region free?" check rather than
# verifying the trampoline bytes themselves.
TECH_ORDERING_FREE_REGION_OFFSET = 0x10EC0
TECH_ORDERING_FREE_REGION_LEN = 0x88


# Tera Domain early unlock — original to this project, not in DW2-TT.
# `STAG3000.PRO`'s overworld script tables hold a single record at file
# offset 0xFCE0 of the form
#     condition_ptr / then_action_ptr / else_action_ptr / pad / param
# whose condition pointer is `is_story_lt_10` (RAM 0x80063B70). That stub
# is referenced exactly once on the entire 461 MB disc; it is the gate
# that opens the Tera Domain map entry post-credits.
#
# `STAG2000.PRO` already contains an unused `is_story_lt_9` stub at RAM
# 0x80063B60 (16-byte sister of `is_story_lt_10` with sltiu immediate 9).
# Re-pointing the gate at it lowers the threshold from "story_progress
# >= 10" to ">= 9" — i.e. Tera Domain becomes accessible at the start
# of Mission 19 (Core Tower) rather than after the credits.
#
# Caveat: `story_progress` is bumped 8 -> 9 at *entry* of Mission 19,
# not after Analogman is defeated, so the unlock fires ~1 mission earlier
# than "second-to-last boss beaten". See `.investigation/REPORT.md`.
TERA_DOMAIN_GATE_OFFSET = 0xFCE0
TERA_DOMAIN_GATE_VANILLA = bytes([0x70, 0x3B, 0x06, 0x80])  # &is_story_lt_10
TERA_DOMAIN_GATE_PATCHED = bytes([0x50, 0x3B, 0x06, 0x80])  # &is_story_lt_8


# DP Gain per fusion — adapted from DW2-TT/ASM Hacks/US/DP Sum-Up.asm.
# The DNA-Digivolution result code in STAG2000.PRO computes
# `result_DP = parent_DP + 1` via two `addiu rt, rs, 1` MIPS instructions
# (one for the higher-DP parent, one for the lower-DP edge case). We flip
# the immediate (1) to N, raising DP gained per fusion. Patches both branches
# for predictability.
DP_GAIN_OFFSET_HIGH = 0x151C
DP_GAIN_VANILLA_HIGH = bytes([0x01, 0x00, 0x82, 0x24])  # addiu $v0, $a0, 1
DP_GAIN_OFFSET_LOW = 0x1520
DP_GAIN_VANILLA_LOW = bytes([0x01, 0x00, 0x62, 0x24])   # addiu $v0, $v1, 1


# ENEMYSET.BIN structure — DW2-TT/Entity/Enemyset.cs
ENEMYSET_LEN = 100
ENEMY_LEN = 30
ENEMIES_PER_SET = 3
ENEMY_OFFSETS = (8, 38, 68)  # within a 100-byte enemyset
EXP_FIELD_OFFSET = 6   # within a 30-byte enemy record
BITS_FIELD_OFFSET = 8
EXP_BITS_CLAMP = 0x7FFF  # DW2-TT clamps at Int16.MaxValue


# ===========================================================================
# Sector I/O — the disc is a stream of 2352-byte Mode 2 Form 1 sectors.
# We only ever read/write the 2048-byte payload of each sector, leaving
# the 24-byte header and 280-byte EDC/ECC trailer untouched.
# ===========================================================================


def read_data_sectors(fh, lba: int, count: int) -> bytearray:
    """Read `count` 2048-byte payloads starting at sector `lba`."""
    out = bytearray(count * SECTOR_DATA)
    for i in range(count):
        fh.seek(lba * SECTOR_RAW + i * SECTOR_RAW + SECTOR_HEADER)
        chunk = fh.read(SECTOR_DATA)
        if len(chunk) != SECTOR_DATA:
            raise IOError(
                f"Short read at LBA {lba + i}: got {len(chunk)}/{SECTOR_DATA} bytes"
            )
        out[i * SECTOR_DATA : (i + 1) * SECTOR_DATA] = chunk
    return out


def write_data_sectors(fh, lba: int, data: bytes) -> None:
    """Write `data` across enough sectors starting at `lba`, leaving each
    sector's header and trailer untouched. `data` is padded with zeros to a
    sector boundary."""
    count = (len(data) + SECTOR_DATA - 1) // SECTOR_DATA
    padded = data + bytes(count * SECTOR_DATA - len(data))
    for i in range(count):
        fh.seek(lba * SECTOR_RAW + i * SECTOR_RAW + SECTOR_HEADER)
        fh.write(padded[i * SECTOR_DATA : (i + 1) * SECTOR_DATA])


# ===========================================================================
# SLUS look-up table — DW2 stores its file table as two parallel arrays
# embedded inside the SLUS_011.93 executable.
# ===========================================================================


class DiscImage:
    """Wraps an open BIN file and provides indexed file read/write."""

    def __init__(self, fh) -> None:
        self.fh = fh
        self.slus = bytearray(read_data_sectors(fh, SLUS_SECTOR_LBA, SLUS_SECTOR_COUNT))

        if not self.slus.startswith(PSX_EXE_MAGIC):
            raise ValueError(
                f"Expected PSX executable magic {PSX_EXE_MAGIC!r} at LBA "
                f"{SLUS_SECTOR_LBA}, found {bytes(self.slus[:8])!r}. "
                "This doesn't look like a Digimon World 2 disc image."
            )

        self.lba: list[int] = list(
            struct.unpack_from(
                f"<{US_FILE_COUNT}I", self.slus, US_LBA_TABLE_OFFSET
            )
        )
        self.size: list[int] = list(
            struct.unpack_from(
                f"<{US_FILE_COUNT}H", self.slus, US_SIZE_TABLE_OFFSET
            )
        )

    def read_file(self, idx: int) -> bytearray:
        return read_data_sectors(self.fh, self.lba[idx], self.size[idx])

    def write_file(self, idx: int, data: bytes) -> None:
        sector_count = (len(data) + SECTOR_DATA - 1) // SECTOR_DATA
        if sector_count > self.size[idx]:
            # All four patches in this script modify in place, so this should
            # never trigger. DW2-TT handles this case by relocating the file
            # to the end of the disc and rewriting the LUT, which we have
            # deliberately not ported.
            raise ValueError(
                f"File idx {idx} grew from {self.size[idx]} to {sector_count} "
                "sectors; relocating files is not supported."
            )
        write_data_sectors(self.fh, self.lba[idx], data)


# ===========================================================================
# Patches.
# ===========================================================================


def patch_exp_bits(buf: bytearray, exp_mul: float, bits_mul: float) -> tuple[int, int]:
    """In-place EXP/Bits multiplication on an ENEMYSET.BIN buffer.

    Returns (modified_enemy_count, capped_value_count).
    """
    modified = 0
    capped = 0
    for set_off in range(0, len(buf), ENEMYSET_LEN):
        if buf[set_off] == 0:
            break  # DW2-TT terminates on first zero Id (matches its reader)
        for eo in ENEMY_OFFSETS:
            base = set_off + eo
            exp_b = base + EXP_FIELD_OFFSET
            bits_b = base + BITS_FIELD_OFFSET

            old_exp = int.from_bytes(buf[exp_b : exp_b + 2], "little")
            old_bits = int.from_bytes(buf[bits_b : bits_b + 2], "little")

            new_exp = int(old_exp * exp_mul)
            new_bits = int(old_bits * bits_mul)

            if new_exp > EXP_BITS_CLAMP:
                new_exp = EXP_BITS_CLAMP
                capped += 1
            if new_bits > EXP_BITS_CLAMP:
                new_bits = EXP_BITS_CLAMP
                capped += 1

            buf[exp_b : exp_b + 2] = new_exp.to_bytes(2, "little")
            buf[bits_b : bits_b + 2] = new_bits.to_bytes(2, "little")
            modified += 1
    return modified, capped


def _expect(buf: bytes, off: int, expected: bytes, label: str) -> None:
    """Validate that the bytes at `off` match `expected`. Aborts cleanly on
    mismatch so re-running on an already-patched ROM doesn't corrupt it."""
    actual = bytes(buf[off : off + len(expected)])
    if actual != expected:
        raise ValueError(
            f"{label}: expected {expected.hex(' ')} at offset 0x{off:X}, "
            f"got {actual.hex(' ')}. Either this isn't a vanilla US image "
            f"or this patch has already been applied."
        )


def patch_digimon_gift(buf: bytearray) -> None:
    _expect(buf, DIGIMON_GIFT_OFFSET_1, DIGIMON_GIFT_VANILLA, "Digimon Gift @0x7060")
    _expect(buf, DIGIMON_GIFT_OFFSET_2, DIGIMON_GIFT_VANILLA, "Digimon Gift @0x706C")
    buf[DIGIMON_GIFT_OFFSET_1 : DIGIMON_GIFT_OFFSET_1 + len(DIGIMON_GIFT_BYTES_1)] = DIGIMON_GIFT_BYTES_1
    buf[DIGIMON_GIFT_OFFSET_2 : DIGIMON_GIFT_OFFSET_2 + len(DIGIMON_GIFT_BYTES_2)] = DIGIMON_GIFT_BYTES_2


def patch_next_level_limit(buf: bytearray) -> None:
    _expect(buf, NEXT_LEVEL_OFFSET, NEXT_LEVEL_VANILLA, "Next Level Limit")
    buf[NEXT_LEVEL_OFFSET : NEXT_LEVEL_OFFSET + len(NEXT_LEVEL_BYTES)] = NEXT_LEVEL_BYTES


def patch_mp_on_guard(buf: bytearray) -> None:
    _expect(buf, MP_ON_GUARD_OFFSET, MP_ON_GUARD_VANILLA, "MP on Guard")
    buf[MP_ON_GUARD_OFFSET : MP_ON_GUARD_OFFSET + len(MP_ON_GUARD_BYTES)] = MP_ON_GUARD_BYTES


def patch_tech_ordering(buf: bytearray) -> None:
    """Add R1-trigger Tech Ordering menu in the post-battle Learn Tech screen."""
    for off, vanilla, _patched in TECH_ORDERING_REDIRECTS:
        _expect(buf, off, vanilla, f"Tech Ordering @0x{off:X}")
    free = bytes(
        buf[TECH_ORDERING_FREE_REGION_OFFSET :
            TECH_ORDERING_FREE_REGION_OFFSET + TECH_ORDERING_FREE_REGION_LEN]
    )
    if free != bytes(TECH_ORDERING_FREE_REGION_LEN):
        raise ValueError(
            f"Tech Ordering: free region @0x{TECH_ORDERING_FREE_REGION_OFFSET:X} "
            f"({TECH_ORDERING_FREE_REGION_LEN} bytes) is not all zeros — "
            "either this isn't a vanilla US image or this patch has already "
            "been applied."
        )

    for off, _vanilla, patched in TECH_ORDERING_REDIRECTS:
        buf[off : off + len(patched)] = patched
    buf[TECH_ORDERING_TRAMPOLINE_OFFSET :
        TECH_ORDERING_TRAMPOLINE_OFFSET + len(TECH_ORDERING_TRAMPOLINE_BYTES)] = TECH_ORDERING_TRAMPOLINE_BYTES


def patch_tera_domain_early_unlock(buf: bytearray) -> None:
    """Repoint Tera Domain's script-table gate at `is_story_lt_9`."""
    _expect(
        buf,
        TERA_DOMAIN_GATE_OFFSET,
        TERA_DOMAIN_GATE_VANILLA,
        "Tera Domain early unlock",
    )
    buf[TERA_DOMAIN_GATE_OFFSET : TERA_DOMAIN_GATE_OFFSET + len(TERA_DOMAIN_GATE_PATCHED)] = TERA_DOMAIN_GATE_PATCHED


def patch_dp_gain(buf: bytearray, n: int) -> None:
    """Replace the `+1` in the DNA fusion DP formula with `+n`."""
    _expect(buf, DP_GAIN_OFFSET_HIGH, DP_GAIN_VANILLA_HIGH, "DP Gain (highest+N)")
    _expect(buf, DP_GAIN_OFFSET_LOW, DP_GAIN_VANILLA_LOW, "DP Gain (lowest+N)")
    new_imm = n.to_bytes(2, "little")
    buf[DP_GAIN_OFFSET_HIGH : DP_GAIN_OFFSET_HIGH + 2] = new_imm
    buf[DP_GAIN_OFFSET_LOW : DP_GAIN_OFFSET_LOW + 2] = new_imm


# ===========================================================================
# Pipeline: chdman extract -> patch -> chdman create.
# ===========================================================================


def run(cmd: list[str]) -> None:
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise RuntimeError(f"Command failed: {' '.join(cmd)}")


def main() -> int:
    chdman = shutil.which("chdman")
    if chdman is None:
        sys.stderr.write(
            "Error: `chdman` is not on PATH.\n"
            "Install it with:    brew install rom-tools\n"
        )
        return 1

    in_path = Path(INPUT_CHD).resolve()
    out_path = Path(OUTPUT_CHD).resolve()
    if not in_path.is_file():
        sys.stderr.write(f"Error: input file not found: {in_path}\n")
        return 1

    print(f"DW2 Patcher")
    print(f"  input : {in_path}")
    print(f"  output: {out_path}")
    print(f"  EXP x{EXP_MULTIPLIER}, Bits x{BITS_MULTIPLIER}")
    print(f"  Digimon Gift     : {ENABLE_DIGIMON_GIFT}")
    print(f"  Next Level Limit : {ENABLE_NEXT_LEVEL_LIMIT}")
    print(f"  MP on Guard 25%  : {ENABLE_MP_ON_GUARD_25}")
    print(f"  Tech Ordering    : {ENABLE_TECH_ORDERING}")
    print(f"  Tera early unlock: {ENABLE_TERA_DOMAIN_EARLY_UNLOCK}")
    print(f"  DP per fusion    : +{DP_GAIN_PER_FUSION} (vanilla = +1)")
    print()

    with tempfile.TemporaryDirectory(prefix="dw2patch_") as tmpdir:
        tmp = Path(tmpdir)
        bin_path = tmp / "dw2.bin"
        cue_path = tmp / "dw2.cue"

        print("[1/3] Extracting CHD -> BIN/CUE...")
        run([chdman, "extractcd", "-i", str(in_path), "-o", str(cue_path), "-ob", str(bin_path), "-f"])

        print("[2/3] Applying patches...")
        with open(bin_path, "r+b") as fh:
            disc = DiscImage(fh)
            print(f"  Detected DW2 (USA) image; LUT has {len(disc.lba)} entries.")

            # ENEMYSET.BIN — EXP/Bits multiplier (also runs at 1.0 to be a no-op
            # if user wanted only ASM patches; harmless either way).
            if EXP_MULTIPLIER != 1.0 or BITS_MULTIPLIER != 1.0:
                enemyset = disc.read_file(IDX_ENEMYSET_BIN)
                modified, capped = patch_exp_bits(enemyset, EXP_MULTIPLIER, BITS_MULTIPLIER)
                disc.write_file(IDX_ENEMYSET_BIN, bytes(enemyset))
                print(
                    f"  ENEMYSET.BIN: modified {modified} enemy records "
                    f"({capped} value(s) clamped to {EXP_BITS_CLAMP})."
                )

            # STAG2000.PRO — DP gain per fusion.
            if DP_GAIN_PER_FUSION != 1:
                stag2 = disc.read_file(IDX_STAG2000_PRO)
                patch_dp_gain(stag2, DP_GAIN_PER_FUSION)
                disc.write_file(IDX_STAG2000_PRO, bytes(stag2))
                print(f"  STAG2000.PRO: DP gain per fusion set to +{DP_GAIN_PER_FUSION}.")

            # STAG3000.PRO — Next Level Limit + MP on Guard + Tech Ordering
            #              + Tera Domain early unlock.
            if (ENABLE_NEXT_LEVEL_LIMIT or ENABLE_MP_ON_GUARD_25
                    or ENABLE_TECH_ORDERING or ENABLE_TERA_DOMAIN_EARLY_UNLOCK):
                stag3 = disc.read_file(IDX_STAG3000_PRO)
                if ENABLE_NEXT_LEVEL_LIMIT:
                    patch_next_level_limit(stag3)
                    print("  STAG3000.PRO: Next Level Limit applied.")
                if ENABLE_MP_ON_GUARD_25:
                    patch_mp_on_guard(stag3)
                    print("  STAG3000.PRO: MP on Guard 25% applied.")
                if ENABLE_TECH_ORDERING:
                    patch_tech_ordering(stag3)
                    print("  STAG3000.PRO: Tech Ordering applied.")
                if ENABLE_TERA_DOMAIN_EARLY_UNLOCK:
                    patch_tera_domain_early_unlock(stag3)
                    print("  STAG3000.PRO: Tera Domain early unlock applied.")
                disc.write_file(IDX_STAG3000_PRO, bytes(stag3))

            # STAG4000.PRO — Digimon Gift.
            if ENABLE_DIGIMON_GIFT:
                stag4 = disc.read_file(IDX_STAG4000_PRO)
                patch_digimon_gift(stag4)
                disc.write_file(IDX_STAG4000_PRO, bytes(stag4))
                print("  STAG4000.PRO: Digimon Gift applied.")

        print("[3/3] Re-encoding BIN/CUE -> CHD...")
        if out_path.exists():
            out_path.unlink()
        run([chdman, "createcd", "-i", str(cue_path), "-o", str(out_path), "-f"])

    print()
    print(f"Done. Patched image written to: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
