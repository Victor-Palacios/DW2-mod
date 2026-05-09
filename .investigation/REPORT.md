# Investigation: unlocking Tera Domain after the 2nd-to-last boss

> ⚠️ **The hypothesis below was tested in-game and proved wrong.** See
> [`POSTSCRIPT_tera_domain.md`](POSTSCRIPT_tera_domain.md) for what the
> falsification revealed and what to investigate next. The structural
> findings (story library layout, RAM addresses, record shape) are still
> correct; the *interpretation* of which gate the `0xFCE0` record
> controls is wrong.

**Status:** investigation only — no changes made to `patch_dw2.py` or the
disc image. Per scope: locate the gate, identify the exact byte(s) to
change, and assess risk.

**Question asked:** can the post-game Tera Domain be made accessible as
soon as the player has beaten the 2nd-to-last boss
(Guardian/Analogman, Core Tower) instead of after the credits roll
(post-Magnamon, Chaos Tower)?

**Short answer:** yes, with a single 1-byte ROM patch — but with one
caveat about *exactly when* the gate would now open, and one piece of
in-game verification still outstanding.

---

## How the in-game story-progress flag works

DW2 keeps a `story_progress` byte on disk at save-slot offset `0x1050`
(this is the field the DW2-TT save editor exposes as "Game Story"). On
load, this byte is mirrored into PSX RAM at:

```
RAM 0x8005E632
```

confirmed by finding the unique writer in `STAG2000.PRO` (file index
402, file offset `0x3E70..0x3E7C`) which uses
`lui $v1, 0x8006; addiu $v0, $zero, 0xA; sb $v0, -0x19CE($v1)` —
i.e. "store 10 at 0x80060000-0x19CE = 0x8005E632".

`STAG2000.PRO` actually contains a small **library of 20 stubs** for
manipulating this byte, at file offsets `0x3AF0..0x3E7F` (RAM
`0x80063AF0..0x80063E7F`):

| RAM addr      | function           | notes                       |
| ------------- | ------------------ | --------------------------- |
| 0x80063AF0    | `is_story_lt_2()`  | returns `(story < 2)`       |
| 0x80063B00    | `is_story_lt_3()`  |                             |
| 0x80063B10    | `is_story_lt_4()`  |                             |
| 0x80063B20    | `is_story_lt_5()`  |                             |
| 0x80063B30    | `is_story_lt_6()`  |                             |
| 0x80063B40    | `is_story_lt_7()`  |                             |
| 0x80063B50    | `is_story_lt_8()`  |                             |
| 0x80063B60    | `is_story_lt_9()`  | **currently unused on disc**|
| **0x80063B70**| **`is_story_lt_10()`** | **the Tera Domain gate** |
| 0x80063B80    | `is_story_lt_11()` | called twice from STAG3000  |
| 0x80063DE0..0x80063E70 | `set_story_1` .. `set_story_10` | writers; only the post-credits cutscene calls `set_story_10` |

Every reader stub is exactly 16 bytes:

```
lui   $v0, 0x8006
lbu   $v0, -0x19CE($v0)     ; load story_progress
j     0x80066F24            ; jump to common return helper
sltiu $v0, $v0, N           ; (delay slot) $v0 = (story < N)
```

The threshold `N` is the 16-bit immediate of the trailing `sltiu`
instruction.

---

## Where Tera Domain's gate lives

I scanned every one of the 3,675 files in the disc's LUT for any
reference to `0x80063B70` (the `is_story_lt_10` stub). Result:

```
is_story_lt_10 (0x80063B70):  1 reference total
  └─ STAG3000.PRO (file index 403), file offset 0x0000FCE0
```

That is it. Across 461 MB of game data, the "is the player still
pre-credits?" function is referenced in exactly one place. That one
reference sits inside a function-pointer record in
`STAG3000.PRO`'s overworld script tables:

```
file_403 0xFCE0 : 70 3b 06 80    -> is_story_lt_10           (CONDITION)
file_403 0xFCE4 : 44 3c 06 80    -> 0x80063C44 in STAG2000   (then-action)
file_403 0xFCE8 : 6c 43 06 80    -> 0x8006436C in STAG2000   (else-action)
file_403 0xFCEC : 00 00 00 00
file_403 0xFCF0 : 24 03 00 00    -> 0x324 (parameter, e.g. dest ID)
```

i.e. "if `story_progress < 10`, run the locked-action; otherwise run the
unlock-action with parameter 0x324". This is the gate that opens at the
end of credits.

I cross-checked that no other "is the player past stage X?" stub
(`is_story_lt_2..11`) is referenced near this address with a similar
record shape, and that `is_story_lt_10` itself appears nowhere else on
the disc.

---

## Two equivalent 1-byte patches

To open the same gate at story_progress `>= 9` instead of `>= 10`, pick
either:

### Patch A — change the stub immediate

* **File:** `STAG2000.PRO` (file index 402)
* **File offset:** `0x3B7C`
* **Vanilla bytes:** `0a 00 42 2c`   (`sltiu $v0, $v0, 0xA`)
* **Patched bytes:** `09 00 42 2c`   (`sltiu $v0, $v0, 0x9`)
* **Disc LBA:** 140730 + (0x3B7C / 2048) = LBA 140737, payload offset
  0x37C within that sector. The 2048-byte sector payload edit pattern
  the existing `patch_dw2.py` uses already supports this (it goes
  through `DiscImage.write_file(IDX_STAG2000_PRO, ...)`).

This changes the meaning of `is_story_lt_10` *globally* to
`is_story_lt_9`. Since nothing else on the disc references this stub,
that's safe — but the rename is a slight maintenance hazard if anyone
later adds new content that wants the original semantics.

### Patch B — change the table entry pointer  (cleaner)

* **File:** `STAG3000.PRO` (file index 403)
* **File offset:** `0xFCE0`
* **Vanilla bytes:** `70 3b 06 80`   (= 0x80063B70 = `is_story_lt_10`)
* **Patched bytes:** `60 3b 06 80`   (= 0x80063B60 = `is_story_lt_9`)
* **Disc LBA:** 140758 + (0xFCE0 / 2048) = LBA 140789, payload offset
  0x4E0 within that sector. Also a single sector-payload edit.

This points the table entry at the existing-but-currently-unused
`is_story_lt_9` stub. Library code is left intact; only this one event
record changes.

**Recommended:** Patch B. Same effect, smaller blast radius, and the
patched 4 bytes belong to a record that we know is *only* the Tera
Domain gate.

---

## When the gate would actually open

This is the caveat to be honest about. The patch lowers the threshold
from "story_progress ≥ 10" to "story_progress ≥ 9". Comparing the
DW2-TT mission flag presets:

| story_progress | mission preset                      |
| -------------- | ----------------------------------- |
| 8              | Mission 18: ROM Domain              |
| 9              | Mission 19: Core Tower (Analogman)  |
| 9              | Mission 20: Chaos Tower (Magnamon)  |
| 10             | Post Game: Tera Domain (vanilla)    |

`story_progress` is bumped from 8 to 9 at the **start** of the Mission
19 / Core Tower mission, *not* at the end of it. So with the patch
applied, the gate would open as soon as the player begins Mission 19,
which is **before** they fight Analogman, not after.

If "after Analogman is defeated, before Magnamon" is a hard requirement
rather than a rough guideline, this patch over-shoots by ~one mission.
A tighter trigger would have to be a bit-test on one of the flags that
flips between Mission 19 and Mission 20:

| save offset | M19 → M20 delta |
| ----------- | --------------- |
| 0x101C      | bit 0x02 added  |
| 0x1033      | bit 0x10 added  |
| 0x1036      | bit 0x20 added  |
| 0x103B      | bit 0x08 added  |

That would be a meaningfully bigger patch — replace the
`is_story_lt_10` table entry with a *new* helper that does
`andi (byte_at_save+0x101C), 0x02` (or similar) and inverts. Doable but
not 4 bytes.

---

## What's still unverified

I have very high confidence in everything **structural** above:

* `story_progress` lives at RAM `0x8005E632` ✓ (proven from writer)
* The 20-stub library exists with exact thresholds 1..11 ✓ (disassembly)
* `is_story_lt_10` has exactly one disc-wide reference, at
  `STAG3000.PRO + 0xFCE0` ✓ (full-disc byte search)
* The reference sits in a `condition / then / else / param` record
  shape ✓ (matches other records nearby in `file_403`)

I have **inferred** but not yet *proven*:

* That this gate is specifically the Tera Domain entrance, as opposed
  to some other thing the game unlocks at end-of-credits (e.g. the
  Jijimon→Ben mayor change, post-credits NPC dialogue, the "you've
  completed the game" world-map flag, Kimeramon-side-quest enable,
  etc.). Strong indirect evidence: nothing else "post-credits" in DW2
  is a *map-entry* gate, and the table parameter `0x324` looks
  destination-shaped — but I have not yet matched `0x324` against a
  known map / domain ID.

To go from "very likely" to "proven" requires either:

1. Loading the **patched** disc in DuckStation against a save where
   `story_progress = 9` (e.g. an existing save that's just begun
   Mission 19, or a save edited by the DW2-TT editor to that state)
   and walking up to where Tera Domain's entry icon would appear. If
   it appears, confirmed. If something else changed instead, we'd
   know we patched the wrong gate.
2. Reverse-engineering the script-VM dispatcher that walks
   `STAG3000.PRO`'s tables (out of scope for this report).

---

## Recommendation re: the save-warp follow-up

You said: "build the save-edit tool only after the investigation, and
only if the investigation concludes [it's] safe (very little to no
risk)."

My read: the **save-edit tool itself** is essentially zero-risk to add
— editing a `.mcr` / `.gme` memory-card save is a non-destructive
operation against a separate file, and it's an extremely well-known
format (DW2-TT does it; its layout is in its `Entity/SaveFile.cs`).
What's risky is *which save state* we'd pre-cook for testing.

The minimum safe test save is "story_progress = 9 with the M19 flag
preset from DW2-TT's vanilla `config.xml`" — i.e. exactly the save the
DW2-TT editor would produce when you pick "Mission 19: Core Tower" from
its dropdown. If you already have a real save you've reached Core Tower
on, even better; we wouldn't need to write any save-edit code at all.

So the conservative ordering is:

1. (you) Decide whether the over-shoot to "Mission 19 start" rather
   than "Analogman defeated" is acceptable.
2. If yes, decide between Patch A and Patch B (I'd take B).
3. Apply Patch B to a copy of the disc and load it against a real or
   editor-produced "Mission 19 start" save; check that Tera Domain
   appears on the world map.
4. Only **then**, if everything looks good, decide whether to wire it
   into `patch_dw2.py` as `ENABLE_TERA_DOMAIN_EARLY_UNLOCK = True` and
   whether to also add a tiny memcard-save warper for convenience.

---

## Files in this folder (deletable when done)

```
.investigation/
├── REPORT.md              ← this file
├── dw2.bin / dw2.cue       (extracted disc, ~440 MB)
├── investigate.py          (initial heuristic scanner)
├── find_gate.py            (locates `li 0x0A → sb` writers)
├── find_readers.py         (every load/store of 0x8005E632)
├── find_callers.py         (jal callers of story-lib stubs, partial)
├── find_callers_full.py    (jal callers, full 3675-file sweep)
├── find_pointer_refs.py    (raw uint32 LE search for stub addresses)
├── inspect_stag.py         (STAG file headers / load-address inference)
├── inspect_gate.py         (raw + disasm around STAG3000.PRO + 0xFCE0)
├── inspect_actions.py      (disassembly of the two action funcs)
└── out/
    ├── readers_story_progress.txt
    ├── writers_li10_then_sb.txt
    ├── story_lib_callers_full.txt
    ├── story_lib_pointer_refs.txt
    └── (others)
```

The whole `.investigation/` directory is throwaway — none of it is
imported by `patch_dw2.py`.
