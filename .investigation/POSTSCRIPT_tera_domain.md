# Postscript: Tera Domain hypothesis was falsified

`REPORT.md` proposes patching the script-table record at `STAG3000.PRO +
0xFCE0` (the only disc-wide reference to `is_story_lt_10`) to lower the
Tera Domain unlock threshold. **That hypothesis was tested in DuckStation
and proved wrong.** Read `REPORT.md` for the structural model, but do
not trust its conclusion about which gate this record controls.

## What we tested

1. **Patch B (story >= 9):** changed `STAG3000.PRO + 0xFCE0` from
   `70 3b 06 80` (`&is_story_lt_10`) to `60 3b 06 80` (`&is_story_lt_9`).
   Edited save slot 3 in a real `.mcr` to `story_progress = 9` plus the
   full Mission 19 flag preset from
   `.dw2tt-ref/dw2_exp_multiplier/Resources/Vanilla/config.xml` (41 flag
   bytes at save offsets `0x1012..0x104F` plus `0x1050 = 0x09`).
   Recomputed checksum2 (port of DW2-TT's `SaveFile.CalculateChecksum`).
   Loaded patched `.chd` against patched save → **Tera Domain did not
   appear on the world map.**

2. **Patch B' (story >= 8):** lowered the threshold further, so any
   reasonably-progressed save would trip the gate. Same negative result.

The patch itself is doing what it claims — the per-run vanilla-byte
verification in `patch_dw2.py` aborts cleanly when re-applied to an
already-patched extract, confirming the bytes change. So the empirical
read is: the `0xFCE0` record is **not** gating Tera Domain.

## Likely true purpose of the `0xFCE0` record

Something post-credits, but not the world-map entry. Plausible:
Jijimon→Ben mayor swap, end-of-credits NPC dialogue change, or a
"you've completed the game" world-flag update. Not narrowed further.

## What the 2nd investigation pass added (not in REPORT.md)

Spawned an Explore agent after the in-game falsification. Its findings,
in shrinking order of confidence:

### Genuine findings (verified against the disc)

- **A second flag byte at RAM `0x8005E631`** — one byte before
  `story_progress`. STAG2000.PRO writes 0 to it at file offset `0x3E88`
  (`sb $zero, -0x19CF($v0)`) and writes 1 at `0x3E98`
  (`sb $v0, -0x19CF($v0)`). At least 9 sites across the disc read it via
  `lbu/lb $rX, -0x19CF($rY)`. This is plausibly a coupled "post-game
  state" flag distinct from `story_progress`. **Unverified** that this is
  the Tera Domain trigger; it might gate something else entirely.

- **Other script-table records of the same shape exist on the disc.**
  The `condition_ptr / then_ptr / else_ptr / pad / param` shape isn't
  unique to `0xFCE0`. Example confirmed by direct byte inspection:

  ```
  file_3405 @0x711C..0x712F:
      cond  = 0x80063684 (custom function in STAG2000.PRO, not a story stub)
      then  = 0x80063758
      else  = 0x80063E00 (= set_story_3 — a story-progress writer)
      pad   = 0x00000000
      param = 0x00000320
  ```

  This particular record was proposed by the agent as the "real" Tera
  Domain gate based on the param-near-`0x324` resemblance. **Almost
  certainly wrong:** the `else` branch invokes `set_story_3`, which
  advances story to 3. That's a Mission 3 progression checkpoint, not a
  post-game unlock. Don't patch it.

### Investigated but inconclusive

- **`is_story_lt_11` callers** at `STAG3000.PRO + 0x0F0C` and `+0x0F50`.
  Vanilla never writes story 11 (no `set_story_11` exists on the disc),
  so these branches' "if story >= 11" path is dormant in vanilla. The
  agent speculated these gate post-game-only content, but did not
  produce a disasm tracing what the dormant path actually does.

- **No `jal` to `set_story_10`** anywhere on disc. The post-credits
  cutscene must reach `set_story_10` (RAM `0x80063E70`) via either a
  function pointer or `jr` through a register. The 2nd pass didn't find
  the caller. Finding it would identify the post-credits state-write
  cluster, which is probably where the real Tera Domain trigger lives.

## Where to pick this up if anyone returns to it

Highest-yield next probes if Tera Domain unlock is revisited:

1. **Find `set_story_10`'s caller.** Search the disc for instructions
   that load the constant `0x80063E70` into a register (lui+addiu pair,
   or any aligned uint32 occurrence) and disassemble around each.
2. **Disassemble the `is_story_lt_11` call sites** at
   `STAG3000.PRO + 0x0F0C` / `+0x0F50` to learn what their always-false
   branch points at.
3. **Acquire a real post-credits save** (download a community
   `BASLUS-01193 DMW2` save) and diff its flag bytes against the
   Mission 20 (Chaos Tower) preset from DW2-TT's vanilla `config.xml`.
   The difference set is the post-credits state-change set; one of those
   bytes is the actual Tera Domain trigger.

Static analysis alone has hit diminishing returns. Live RAM watching
in DuckStation while playing past the credits is probably the only way
to fully pin this down.
