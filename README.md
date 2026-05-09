# DW2-mod

A small Python tool that patches a Digimon World 2 (USA) `.chd` disc image
with EXP/Bits multipliers and a few quality-of-life tweaks. Runs natively on
macOS (Apple Silicon).

## Credit

The core patch logic — every MIPS payload, every file offset, the SLUS
look-up-table layout, and the save-file structure — comes from
[acemon33/DW2-TT](https://github.com/acemon33/DW2-TT) (GPL-3.0). This
project is a Python port of the relevant pieces of that tool, plus one
additional patch (Tera Domain early unlock) derived from the same
disassembly conventions DW2-TT uses.

## What this mod does

DW2-TT is a Windows GUI tool. This repo is the same patches, applied
non-interactively to a `.chd` disc image on macOS / Linux. Run the script
once and you get a patched `.chd` you can load directly in DuckStation (or
any PSX emulator that accepts CHD).

## Patches applied

- **EXP multiplier** (default 5x) and **Bits multiplier** (default 5x) —
  edits `ENEMYSET.BIN` directly. Values are clamped at 32767 (same cap as
  the upstream tool).
- **Digimon Gift** — wild Digimon stop moving while accepting a gift.
- **Next Level Limit** — a Digimon can gain multiple levels in one battle.
- **MP on Guard 25%** — guarding Digimon recover MP at a 25% rate.
- **Tech Ordering** — press R1 in the post-battle Learn Tech menu to
  rearrange a Digimon's techs.
- **DP gain per fusion** (default +3) — increases the DP added to the
  result of a DNA Digivolution. Vanilla is +1, so e.g. fusing DP-4 + DP-2
  yields a DP-7 child instead of DP-5. Reaches Mega-tier DP thresholds
  much faster.
- **Tera Domain early unlock** *(experimental)* — the post-game Tera
  Domain map entry is gated by the `is_story_lt_10` script function in
  `STAG3000.PRO`'s overworld script tables. This patch repoints the gate
  at the existing `is_story_lt_9` stub instead, so Tera Domain becomes
  accessible as soon as `story_progress` reaches 9 (start of Mission 19,
  Core Tower) rather than 10 (post-credits). Single-byte edit at file
  offset `0xFCE0` of `STAG3000.PRO`. See `.investigation/REPORT.md` for
  the full reverse-engineering write-up.

US (NTSC-U) version only. The script verifies it has a vanilla disc before
patching and aborts cleanly on a re-run (so you can't accidentally
double-patch).

## Prerequisites

```bash
brew install rom-tools   # provides chdman
```

Python 3.10+ (stdlib only — no `pip install` needed).

## Usage

1. Open `patch_dw2.py` and edit the `CONFIG` block at the top:

   ```python
   INPUT_CHD       = "Digimon World 2 (USA).chd"
   OUTPUT_CHD      = "Digimon World 2 (USA).patched.chd"
   EXP_MULTIPLIER  = 5.0
   BITS_MULTIPLIER = 5.0
   ENABLE_DIGIMON_GIFT             = True
   ENABLE_NEXT_LEVEL_LIMIT         = True
   ENABLE_MP_ON_GUARD_25           = True
   ENABLE_TECH_ORDERING            = True
   ENABLE_TERA_DOMAIN_EARLY_UNLOCK = True   # experimental
   DP_GAIN_PER_FUSION              = 3      # vanilla = 1
   ```

2. Run it:

   ```bash
   python3 patch_dw2.py
   ```

The original `.chd` is left untouched; the patched image is written to
`OUTPUT_CHD` next to it. Load the patched `.chd` in DuckStation (or any
other PSX emulator that accepts CHD).

## Optional: virtual environment

A `digimon2/` venv is included for convenience but isn't required.

```bash
source digimon2/bin/activate
```

## Notes

- The script only modifies the 2048-byte data payload of each PSX sector,
  leaving headers and EDC/ECC trailers alone. Emulators (DuckStation,
  Beetle PSX HW, etc.) don't care about EDC/ECC mismatches on payload-only
  edits. If you ever burn the result to physical media, run a separate
  EDC/ECC regenerator first.
- Bits x10 saturates at 32767 for any enemy that already drops 3,277+ bits
  (some late-game bosses). EXP x3 saturates above 10,923 base XP.
- The Tera Domain early-unlock patch over-shoots the player's progress
  by ~1 mission: the gate flips at the *start* of Mission 19 (Core Tower)
  rather than after Analogman is defeated, because `story_progress` is
  bumped from 8 to 9 at mission entry, not at boss kill. Treat as
  experimental until verified in-game.
