#!/usr/bin/env python3
"""
DW2 Tera-Domain-gate investigation harness (read-only).

Strategy
--------
We don't yet know:
 (a) what RAM address DW2 loads its memory-card save buffer at, or
 (b) what specific check gates entry to the post-game Tera Domain.

We do know:
 - The save-data byte at slot offset 0x1050 (story_progress) ticks from
   0x09 -> 0x0A only after end credits roll (= Tera Domain unlock).
 - A handful of bits in 0x101C / 0x1021 / 0x1033 / 0x1034 / 0x1036 /
   0x103B also flip on at the same moment.
So the gate is *almost certainly* a load of one of those bytes followed
by a compare/branch.

This script:
 1) Disassembles SLUS_011.93 (full text) and STAG3000/4000.PRO.
 2) For every `lui rX, hi` it sees, walks forward up to N instructions
    looking for memory accesses with the same base register, builds a
    histogram of resolved absolute target addresses landing inside any
    save-data offset in [0x1000, 0x1080), and tabulates which RAM base
    address most often appears as `target - off`. That base is our save
    buffer location.
 3) Once we have a likely save base, dumps a focused listing of every
    load/store that reads/writes the changed-between-M19-and-Post-Game
    bytes at that base, with surrounding context.
 4) Independently dumps every `slti/sltiu` against immediate 0x0A with
    surrounding context (story-progress threshold candidate).
 5) Independently dumps every `andi rX, rY, mask` where mask matches one
    of the bits added between M19 and Post Game (0x01, 0x02, 0x03, 0x06,
    0x10, 0x18, 0x60, 0x80) with surrounding context.

All output is plain text under ./out/. No disc bytes are modified.
"""

from __future__ import annotations

import re
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import patch_dw2 as dw2

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

OUT = HERE / "out"
OUT.mkdir(exist_ok=True)
BIN = HERE / "dw2.bin"

# Save-buffer offsets that change between Mission 19 (post-Analogman /
# Guardian) and Post Game (post-credits, Tera Domain unlocked).
SAVE_DIFFS_19_TO_POSTGAME: dict[int, tuple[int, int]] = {
    0x101C: (0x39, 0x3F),  # bits 0x06 added
    0x1021: (0x00, 0x03),  # bits 0x03 added
    0x1033: (0xEF, 0xFF),  # bit  0x10 added
    0x1034: (0xEC, 0xED),  # bit  0x01 added
    0x1036: (0x10, 0x70),  # bits 0x60 added
    0x103B: (0xE7, 0xFF),  # bits 0x18 added
    0x1050: (0x09, 0x0A),  # story-progress byte (only one that changes value, not bits)
}
SAVE_OFFS_OF_INTEREST = set(SAVE_DIFFS_19_TO_POSTGAME)

# Bit masks added between M19 and Post Game (per byte). Used to spot
# ANDI tests of those specific bits.
ADDED_BITS: list[int] = sorted({
    new ^ old for (old, new) in SAVE_DIFFS_19_TO_POSTGAME.values()
} | {
    # Also include byte-granularity bits (e.g. each individual bit added)
    bit for (old, new) in SAVE_DIFFS_19_TO_POSTGAME.values()
    for bit in (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)
    if (new & ~old) & bit
})

# Window: how many instructions after a `lui` to consider for resolving an
# effective address with that register as the base.
RESOLVE_WINDOW = 8


def read_psx_exe_header(slus: bytes) -> dict:
    assert slus.startswith(b"PS-X EXE")
    return {
        "pc0":       struct.unpack_from("<I", slus, 0x10)[0],
        "gp0":       struct.unpack_from("<I", slus, 0x14)[0],
        "load_addr": struct.unpack_from("<I", slus, 0x18)[0],
        "text_size": struct.unpack_from("<I", slus, 0x1C)[0],
        "sp_base":   struct.unpack_from("<I", slus, 0x30)[0],
        "sp_off":    struct.unpack_from("<I", slus, 0x34)[0],
    }


def disasm_all(buf: bytes, base_addr: int):
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    md.skipdata = True
    md.skipdata_setup = ("data", None, None)
    return list(md.disasm(buf, base_addr))


def fmt_insn(insn) -> str:
    return f"0x{insn.address:08X}: {insn.bytes.hex():<8} {insn.mnemonic:<8} {insn.op_str}"


_LOAD_STORE_BYTE_HALF_WORD = {"lb", "lbu", "lh", "lhu", "lw", "sb", "sh", "sw"}

_MEM_OPS_RE = re.compile(r"^([\$\w]+),\s*(-?0x[0-9a-fA-F]+|-?\d+)\(([\$\w]+)\)$")
_REG_IMM_REG_RE = re.compile(r"^([\$\w]+),\s*([\$\w]+),\s*(-?0x[0-9a-fA-F]+|-?\d+)$")
_REG_IMM_RE = re.compile(r"^([\$\w]+),\s*(-?0x[0-9a-fA-F]+|-?\d+)$")


def parse_imm(s: str) -> int:
    s = s.strip()
    return int(s, 16) if s.lower().startswith(("0x", "-0x")) else int(s, 10)


def signed16(v: int) -> int:
    return v - 0x10000 if v & 0x8000 else v


def scan_save_base_and_hits(insns):
    """Resolve memory accesses by walking forward from each `lui` for up
    to RESOLVE_WINDOW instructions. Returns:
      - Counter of save-base candidates (target_addr - off, only when
        off lands in [0x1000, 0x1080)).
      - For each save-buffer offset of interest, list of (insn_addr, mnemonic, reg).
    """
    base_cands: Counter[int] = Counter()
    save_hits: dict[int, list[tuple[int, str, str]]] = defaultdict(list)

    # Pre-flatten for indexed access.
    n = len(insns)

    for i, ins in enumerate(insns):
        if ins.mnemonic != "lui":
            continue
        m = _REG_IMM_RE.match(ins.op_str)
        if not m:
            continue
        reg, imm_s = m.group(1), m.group(2)
        try:
            hi = parse_imm(imm_s)
        except ValueError:
            continue
        base_hi = (hi & 0xFFFF) << 16

        # Track the live composite for this reg, plus any reg derived
        # by addiu/ori/addi from it within the window.
        regs: dict[str, int] = {reg: base_hi}

        for j in range(i + 1, min(n, i + 1 + RESOLVE_WINDOW)):
            j_ins = insns[j]
            jm, jops = j_ins.mnemonic, j_ins.op_str

            if jm == "lui":
                m2 = _REG_IMM_RE.match(jops)
                if m2 and m2.group(1) in regs:
                    # base reg got clobbered by another lui — drop it
                    regs.pop(m2.group(1), None)
                continue

            if jm in ("addiu", "addi", "ori"):
                m2 = _REG_IMM_REG_RE.match(jops)
                if m2:
                    rD, rS, imm = m2.group(1), m2.group(2), parse_imm(m2.group(3))
                    if rS in regs:
                        composed = regs[rS]
                        if jm == "ori":
                            regs[rD] = (composed & ~0xFFFF) | (imm & 0xFFFF)
                        else:
                            regs[rD] = (composed + signed16(imm & 0xFFFF)) & 0xFFFFFFFF
                continue

            if jm in _LOAD_STORE_BYTE_HALF_WORD:
                m2 = _MEM_OPS_RE.match(jops)
                if m2:
                    _data_reg = m2.group(1)
                    off = signed16(parse_imm(m2.group(2)) & 0xFFFF)
                    rs = m2.group(3)
                    if rs in regs:
                        target = (regs[rs] + off) & 0xFFFFFFFF
                        # Save-buffer hit?
                        rel = target & 0x0000FFFF  # only cheap heuristic; use offset
                        # Use the literal off field (more reliable than the
                        # composite, since save offsets are encoded in the
                        # instruction immediate).
                        if 0x1000 <= off < 0x1080 or off in SAVE_OFFS_OF_INTEREST:
                            save_base = (target - off) & 0xFFFFFFFF
                            base_cands[save_base] += 1
                            if off in SAVE_OFFS_OF_INTEREST:
                                save_hits[off].append((j_ins.address, jm, rs))

    return base_cands, save_hits


def context_window(insns_by_addr: dict[int, int], insns: list, addr: int, before: int = 6, after: int = 6):
    """Return (idx, list_of_insns_in_window) for the insn at `addr`."""
    idx = insns_by_addr.get(addr)
    if idx is None:
        return None, []
    lo, hi = max(0, idx - before), min(len(insns), idx + after + 1)
    return idx, insns[lo:hi]


def write_context_dump(path: Path, insns: list, insns_by_addr: dict, addrs: list[int], header: str):
    with open(path, "w") as f:
        f.write(header + "\n\n")
        for addr in sorted(set(addrs)):
            idx, win = context_window(insns_by_addr, insns, addr)
            if idx is None:
                continue
            f.write(f"--- 0x{addr:08X} ---\n")
            for ins in win:
                marker = ">>> " if ins.address == addr else "    "
                f.write(marker + fmt_insn(ins) + "\n")
            f.write("\n")


def main() -> int:
    print(f"Reading {BIN.name} ...")
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        slus = bytes(disc.slus)
        hdr = read_psx_exe_header(slus)
        text_off = 0x800
        text_load = hdr["load_addr"]
        text_bytes = slus[text_off : text_off + hdr["text_size"]]

        print("\nPSX-EXE header (SLUS_011.93):")
        for k, v in hdr.items():
            print(f"  {k:<11s} = 0x{v:08X}")
        print(f"  text bytes = {len(text_bytes)} (RAM 0x{text_load:08X}..0x{text_load + len(text_bytes):08X})")

        files: list[tuple[str, bytes, int]] = [
            ("SLUS_011.93", text_bytes, text_load),
            ("STAG3000_PRO", bytes(disc.read_file(dw2.IDX_STAG3000_PRO)), 0),
            ("STAG4000_PRO", bytes(disc.read_file(dw2.IDX_STAG4000_PRO)), 0),
        ]

    # Per-file disassembly + analysis.
    all_insns_by_file: dict[str, list] = {}
    base_cands_global: Counter[int] = Counter()

    for name, data, base in files:
        print(f"\nDisassembling {name} ({len(data)} bytes) at base 0x{base:08X} ...")
        insns = disasm_all(data, base)
        all_insns_by_file[name] = insns
        print(f"  {len(insns)} instructions decoded")

        if name == "SLUS_011.93":
            with open(OUT / f"{name}.disasm.txt", "w") as f:
                for ins in insns:
                    f.write(fmt_insn(ins) + "\n")

        cands, hits = scan_save_base_and_hits(insns)
        base_cands_global.update(cands)
        print(f"  {sum(cands.values())} resolved memory accesses with off in [0x1000,0x1080)")
        for off in sorted(hits):
            print(f"    save+0x{off:04X}: {len(hits[off])} hits")

        # Per-file dump of the changed-between-M19-and-PostGame accesses.
        if hits:
            insns_by_addr = {ins.address: i for i, ins in enumerate(insns)}
            addrs = [a for off_lst in hits.values() for (a, *_rest) in off_lst]
            hdr_str = (
                f"{name}: accesses to save bytes that change between Mission 19 "
                f"(post-Analogman) and Post Game (Tera Domain unlocked)."
            )
            write_context_dump(OUT / f"{name}.flag_accesses.txt", insns, insns_by_addr, addrs, hdr_str)

    print("\nGlobal save-buffer base candidates (resolved target - immediate offset):")
    top_bases = base_cands_global.most_common(30)
    for b, n in top_bases:
        print(f"  0x{b:08X}  hits={n}")
    with open(OUT / "save_base_candidates.txt", "w") as f:
        for b, n in base_cands_global.most_common():
            f.write(f"0x{b:08X}\t{n}\n")

    # Standalone scans on SLUS.
    slus_insns = all_insns_by_file["SLUS_011.93"]
    slus_by_addr = {ins.address: i for i, ins in enumerate(slus_insns)}

    # 1) Threshold scan: slti/sltiu against immediate 0x0A.
    threshold_addrs: list[int] = []
    for ins in slus_insns:
        if ins.mnemonic in ("slti", "sltiu"):
            m = _REG_IMM_REG_RE.match(ins.op_str)
            if m and parse_imm(m.group(3)) == 0x0A:
                threshold_addrs.append(ins.address)
    write_context_dump(
        OUT / "SLUS_threshold_0x0A.txt",
        slus_insns,
        slus_by_addr,
        threshold_addrs,
        f"SLUS: {len(threshold_addrs)} 'slti/sltiu rX, rY, 0x0A' candidates "
        "(story_progress threshold check?). Look for an `lbu` shortly before "
        "loading the value being compared.",
    )

    # 2) Equality threshold scan: addiu rX, $zero, 0x0A often used as
    #    'load constant 10' for a subsequent compare. Surface these too.
    li_addrs: list[int] = []
    for ins in slus_insns:
        if ins.mnemonic == "addiu":
            m = _REG_IMM_REG_RE.match(ins.op_str)
            if m and m.group(2) == "$zero" and parse_imm(m.group(3)) == 0x0A:
                li_addrs.append(ins.address)
    write_context_dump(
        OUT / "SLUS_li_0x0A.txt",
        slus_insns,
        slus_by_addr,
        li_addrs,
        f"SLUS: {len(li_addrs)} 'li rX, 0x0A' candidates. The next nearby "
        "`beq`/`bne` against an `lbu` value is a story-progress equality test.",
    )

    # 3) Bit-test scan: andi rX, rY, mask where mask matches an added bit.
    print(f"\nADDED bits between M19 and Post Game: {[hex(b) for b in ADDED_BITS]}")
    for mask in (0x01, 0x02, 0x03, 0x06, 0x10, 0x18, 0x60, 0x80):
        andi_addrs: list[int] = []
        for ins in slus_insns:
            if ins.mnemonic == "andi":
                m = _REG_IMM_REG_RE.match(ins.op_str)
                if m and parse_imm(m.group(3)) == mask:
                    andi_addrs.append(ins.address)
        write_context_dump(
            OUT / f"SLUS_andi_mask_0x{mask:02X}.txt",
            slus_insns,
            slus_by_addr,
            andi_addrs,
            f"SLUS: {len(andi_addrs)} 'andi rX, rY, 0x{mask:02X}' candidates "
            "(bit-test of a flag that flips on at Post Game?).",
        )

    print("\nDone. Outputs in", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
