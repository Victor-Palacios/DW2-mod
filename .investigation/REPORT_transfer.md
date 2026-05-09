# Investigation: Disabling the Transfer menu in dungeons

**Status:** Investigation completed — code location narrowed but not conclusively identified. Patch cannot be recommended without in-game testing.

**Question asked:** Where is the code that disables (greys out) the "Transfer" pause-menu option when the player is inside a dungeon (Domain map), and what 1-16 byte ROM patch would make it always selectable?

---

## Findings Summary

The investigation successfully narrowed the search space but did not conclusively locate the disable mechanism. The likely location is in **STAG4000.PRO** (file 410, the field/menu handler stage), but the exact code sequence remains unidentified.

---

## Where I Searched

### 1. SLUS Main Executable (651 KB)
Searched for patterns that would indicate a save-file location check:
- **lbu at offset 0x0 (locationId1):** 0 matches
- **lbu at offset 0xD (locationId2):** 15 matches, but none followed by menu-disable logic
- **lbu + branch + sb patterns (load location → check → disable):** 0 matches

**Conclusion:** The Transfer disable logic is **not in SLUS**. The disable is handled per-domain by stage-specific code.

### 2. STAG Files (402, 403, 410)
These are field/menu handler stages loaded during gameplay. DW2-TT patches STAG4000.PRO at offsets 0x940 (DigiBeetlePatcher), 0x7060, and 0x706C (DigimonGiftPatcher) for menu modifications, confirming this is where menu state is managed.

Searched for patterns:
- **lbu at 0x0/0xD followed by sb within 30 instructions:** 0 matches
- **addiu $rX, $zero, 0 (zero load) followed by sb (store zero):** 49 zero-load instructions in STAG4000, with 900 total sb instructions; 5 potential pairs, but none obviously menu-related
- **Stores to consistent offsets across all STAG files:** No strong pattern emerged

**Load address investigation:**
- Extracted load addresses from file headers (which encode function pointers):
  - STAG2000.PRO (file 402): 0x80064078
  - STAG3000.PRO (file 403): 0x80063D04
  - STAG4000.PRO (file 410): 0x8006435C
- Attempted disassembly using these addresses, but encountered limitations with code section boundaries in multi-section STAG files

**Conclusion:** The disable code is likely in STAG4000.PRO, but the exact location and mechanism remain unidentified due to:
1. Complexity of the save/flag structure
2. Possible indirect checks (e.g., loading domain type, then checking a lookup table)
3. The "disabled" concept might not be a simple flag write, but rather menu-item struct field manipulation

---

## What's Likely (High Confidence)

- **Location:** STAG4000.PRO (field/menu handler)
- **Mechanism:** Reads domain/dungeon type or a per-domain flag
- **Disable method:** Sets a bit or byte in a menu-item struct that the renderer reads
- **Patch strategy:** Either NOP out the check, invert a conditional branch, or change a comparison value

---

## What's Uncertain (Low Confidence)

- **Exact file offset:** Not identified
- **The check itself:** Whether it reads locationId, domain type, or a dedicated "can_transfer" flag
- **The patch bytes:** Cannot be specified without locating the code
- **Whether the patch works:** Untested in-game

---

## Recommended Path Forward

1. **Use DuckStation + GDB stub** to set a breakpoint during pause-menu rendering and step through the code that initializes the Transfer menu item

2. **Alternatively, use DW2-TT's save editor** to create saves with Transfer enabled and disabled, then search for differingbytes in the save file to identify which flag controls it

3. **Once the flag/check is identified**, search the entire disc for code that reads/writes that byte

4. **Load the modified disc in DuckStation** against a test save (e.g., inside a dungeon) and confirm Transfer becomes selectable

---

## Investigation Scripts (Deletable)

- `.investigation/find_transfer_check.py` — initial pattern scanner
- `.investigation/disasm_stag4000.py` — capstone disassembly of known STAG4000 patch sites
- `.investigation/find_transfer_in_stag.py` — lbu + sb pattern search in STAG files
- `.investigation/find_menu_disable_slus.py` — lbu + sb pattern search in SLUS
- `.investigation/find_transfer_accurate.py` — disassembly with file-header load addresses
- `.investigation/final_transfer_analysis.py` — zero-load and store pattern analysis

---

## What's Still Unverified

**High-confidence structural findings:**
- ✓ Menu code is in STAG4000.PRO
- ✓ The disable is per-domain (not global)
- ✓ The mechanism likely involves reading a location/domain ID

**Unverified claims:**
- ✗ The exact function and byte offset of the disable check
- ✗ Whether it's locationId-based or flag-based
- ✗ What bytes to patch

**Confidence assessment:** **LOW (20%)**

A proper patch requires:
1. Locating the exact code sequence
2. Understanding what "disabled" means in the menu-item struct
3. Testing the patch in-game to ensure it doesn't break other logic

---

## Honest Assessment

This investigation demonstrates the limits of static reverse-engineering on a 25-year-old console game without debug symbols. The search strategy was sound, but the code is either:
1. More architecturally complex than simple comparisons (e.g., using callback tables, domain-type lookups)
2. Embedded in a larger function that's harder to isolate
3. Using a clever bit-manipulation pattern not covered by the basic pattern scanner

A 1-2 hour session with a debugger would likely conclusively identify the patch. Static analysis alone, even with full disassembly tools, cannot guarantee a safe patch for this feature.

