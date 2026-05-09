#!/usr/bin/env python3
"""
Step 2: locate the writer that sets `story_progress = 0x0A` (the byte
that flips on at the end of credits, unlocking Tera Domain). Once we
have that writer's effective base+offset, every read of the same byte
elsewhere is a candidate Tera Domain gate.

We look across SLUS_011.93 + every STAGxxxx.PRO and ENEMYSET-adjacent
file. Pattern we're hunting:

    addiu  $rA, $zero, 0x0A          ; "li rA, 10"
    ...
    sb     $rA, off($rB)             ; store into the story_progress byte

We don't require these to be adjacent (other instructions may live
between them in the writer prologue), but we do require $rA to remain
the source of the sb without an intervening overwrite.

We also look for the bit-setter pattern:

    lbu    $rA, off($rB)             ; load the flag byte
    ...
    ori    $rC, $rA, MASK            ; set the bit(s)
    sb     $rC, off($rB)             ; store back

where MASK is one of the bits that flips on between Mission 19 and
Post Game (0x06 in 0x101C, 0x03 in 0x1021, 0x10 in 0x1033, 0x01 in
0x1034, 0x60 in 0x1036, 0x18 in 0x103B).

All output goes to ./out/. No bytes are modified.
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import patch_dw2 as dw2

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

OUT = HERE / "out"
OUT.mkdir(exist_ok=True)
BIN = HERE / "dw2.bin"

ADDED_BITS_PER_OFFSET: dict[int, int] = {
    0x101C: 0x06,
    0x1021: 0x03,
    0x1033: 0x10,
    0x1034: 0x01,
    0x1036: 0x60,
    0x103B: 0x18,
}

_REG_IMM_RE = re.compile(r"^([\$\w]+),\s*(-?0x[0-9a-fA-F]+|-?\d+)$")
_REG_IMM_REG_RE = re.compile(r"^([\$\w]+),\s*([\$\w]+),\s*(-?0x[0-9a-fA-F]+|-?\d+)$")
_MEM_OPS_RE = re.compile(r"^([\$\w]+),\s*(-?0x[0-9a-fA-F]+|-?\d+)\(([\$\w]+)\)$")


def parse_imm(s: str) -> int:
    s = s.strip()
    return int(s, 16) if s.lower().startswith(("0x", "-0x")) else int(s, 10)


def signed16(v: int) -> int:
    return v - 0x10000 if v & 0x8000 else v


def disasm_all(buf: bytes, base_addr: int):
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    md.skipdata = True
    md.skipdata_setup = ("data", None, None)
    return list(md.disasm(buf, base_addr))


def fmt_insn(insn) -> str:
    return f"0x{insn.address:08X}: {insn.bytes.hex():<8} {insn.mnemonic:<8} {insn.op_str}"


def find_li10_then_sb(insns, *, name: str, max_gap: int = 8):
    """Find every `addiu rA, $zero, 0x0A` followed within `max_gap`
    instructions by `sb rA, off($rB)` where rA hasn't been clobbered.
    Returns list of (addiu_idx, sb_idx, off, rB, addiu_addr, sb_addr).
    """
    n = len(insns)
    hits: list[dict] = []
    for i, ins in enumerate(insns):
        if ins.mnemonic != "addiu":
            continue
        m = _REG_IMM_REG_RE.match(ins.op_str)
        if not m:
            continue
        rD, rS, imm_s = m.group(1), m.group(2), m.group(3)
        try:
            imm = parse_imm(imm_s)
        except ValueError:
            continue
        if rS != "$zero" or imm != 0x0A:
            continue

        # Walk forward up to max_gap looking for sb of rD.
        for j in range(i + 1, min(n, i + 1 + max_gap)):
            j_ins = insns[j]
            jm, jops = j_ins.mnemonic, j_ins.op_str

            # If anything writes back into rD before we see the sb,
            # abandon this candidate.
            if _writes_register(jm, jops) == rD:
                break

            if jm == "sb":
                m2 = _MEM_OPS_RE.match(jops)
                if not m2:
                    continue
                src_reg = m2.group(1)
                if src_reg != rD:
                    continue
                off = signed16(parse_imm(m2.group(2)) & 0xFFFF)
                rb = m2.group(3)
                hits.append({
                    "name": name,
                    "addiu_addr": ins.address,
                    "sb_addr": j_ins.address,
                    "off": off,
                    "rb": rb,
                    "i": i,
                    "j": j,
                })
                break
    return hits


def find_bit_setter(insns, *, name: str, target_off: int, mask: int, max_gap: int = 16):
    """Find lbu rA, off($rB); ...; ori rC, rA, MASK; sb rC, off($rB).
    Scoped to a particular off+mask combo.
    """
    n = len(insns)
    out = []
    for i, ins in enumerate(insns):
        if ins.mnemonic not in ("lbu", "lb"):
            continue
        m = _MEM_OPS_RE.match(ins.op_str)
        if not m:
            continue
        rA = m.group(1)
        try:
            off = signed16(parse_imm(m.group(2)) & 0xFFFF)
        except ValueError:
            continue
        rB = m.group(3)
        if off != target_off:
            continue

        # Look forward for ori rC, rA, MASK
        for j in range(i + 1, min(n, i + 1 + max_gap)):
            j_ins = insns[j]
            jm, jops = j_ins.mnemonic, j_ins.op_str
            if jm == "ori":
                m2 = _REG_IMM_REG_RE.match(jops)
                if m2 and m2.group(2) == rA and parse_imm(m2.group(3)) == mask:
                    rC = m2.group(1)
                    # Now look for sb rC, off($rB) within another small window.
                    for k in range(j + 1, min(n, j + 1 + max_gap)):
                        k_ins = insns[k]
                        if k_ins.mnemonic != "sb":
                            continue
                        m3 = _MEM_OPS_RE.match(k_ins.op_str)
                        if not m3:
                            continue
                        if m3.group(1) == rC and m3.group(3) == rB and \
                           signed16(parse_imm(m3.group(2)) & 0xFFFF) == off:
                            out.append({
                                "name": name,
                                "lbu_addr": ins.address,
                                "ori_addr": j_ins.address,
                                "sb_addr": k_ins.address,
                                "off": off,
                                "mask": mask,
                                "rB": rB,
                            })
                            break
                    break
            if _writes_register(jm, jops) == rA:
                break
    return out


def _writes_register(mnemonic: str, op_str: str) -> str | None:
    """Crudely return the destination register name for instructions
    that produce a register result, else None."""
    if mnemonic in ("addiu", "addi", "ori", "andi", "xori", "slti", "sltiu",
                    "addu", "subu", "and", "or", "xor", "nor", "sll", "srl",
                    "sra", "sllv", "srlv", "srav", "lui", "li", "move",
                    "lw", "lh", "lhu", "lb", "lbu", "mflo", "mfhi", "negu", "not", "neg"):
        first = op_str.split(",", 1)[0].strip()
        if first.startswith("$"):
            return first
    return None


def context_dump(path: Path, header: str, insns_by_file: dict[str, list], hits: list[dict]):
    with open(path, "w") as f:
        f.write(header + "\n\n")
        for h in hits:
            insns = insns_by_file[h["name"]]
            anchor_idx = h.get("sb_addr") or h.get("lbu_addr")
            # Find index by linear scan (cheap enough for our hit counts).
            idx = next(i for i, ins in enumerate(insns) if ins.address == anchor_idx)
            lo, hi = max(0, idx - 8), min(len(insns), idx + 4)
            f.write(f"--- {h['name']} hit (off=0x{h['off']:04X} via {h.get('rb', h.get('rB'))}) ---\n")
            for ins in insns[lo:hi]:
                marker = ">>> " if ins.address in (h.get("sb_addr"), h.get("lbu_addr"),
                                                    h.get("addiu_addr"), h.get("ori_addr")) else "    "
                f.write(marker + fmt_insn(ins) + "\n")
            f.write("\n")


def main() -> int:
    print(f"Reading {BIN.name} ...")
    with open(BIN, "rb") as fh:
        disc = dw2.DiscImage(fh)
        slus = bytes(disc.slus)
        from struct import unpack_from
        load_addr = unpack_from("<I", slus, 0x18)[0]
        text_size = unpack_from("<I", slus, 0x1C)[0]
        text_bytes = slus[0x800 : 0x800 + text_size]

        files: list[tuple[str, bytes, int]] = [
            ("SLUS_011.93", text_bytes, load_addr),
            ("STAG3000_PRO", bytes(disc.read_file(dw2.IDX_STAG3000_PRO)), 0),
            ("STAG4000_PRO", bytes(disc.read_file(dw2.IDX_STAG4000_PRO)), 0),
        ]

        # Probe nearby file indices for STAG2000 / other STAG files.
        # DW2-TT's backupRestoreFileIndexes mentions STAG1100, STAG2000.
        # Adjacent indices to STAG3000_PRO=403 / STAG4000_PRO=410:
        for cand in range(395, 415):
            if cand in (dw2.IDX_STAG3000_PRO, dw2.IDX_STAG4000_PRO):
                continue
            try:
                data = bytes(disc.read_file(cand))
                if len(data) >= 4096 and data[:4] != b"\x00\x00\x00\x00":
                    files.append((f"file_{cand}", data, 0))
            except Exception:
                pass

    insns_by_file: dict[str, list] = {}
    for name, data, base in files:
        insns_by_file[name] = disasm_all(data, base)
        print(f"  {name}: {len(insns_by_file[name])} instructions")

    # ---------- Hunt #1: who sets story_progress = 0x0A? -----------------
    print("\nHunting for `li rA, 0x0A` -> `sb rA, off($rB)` writers across all files...")
    li10_writers: list[dict] = []
    for name, insns in insns_by_file.items():
        hits = find_li10_then_sb(insns, name=name, max_gap=12)
        li10_writers.extend(hits)
        if hits:
            print(f"  {name}: {len(hits)} li-10 -> sb pairs")

    context_dump(
        OUT / "writers_li10_then_sb.txt",
        "Every `addiu rA, $zero, 0x0A` followed within 12 insns by "
        "`sb rA, off($rB)` (no intervening clobber of rA). "
        "These are candidates for code that sets story_progress = 0x0A "
        "(=> Tera Domain unlocked).",
        insns_by_file,
        li10_writers,
    )
    # Show distribution of (off, rB) for quick inspection.
    by_offrb: Counter[tuple[int, str]] = Counter(
        (h["off"], h["rb"]) for h in li10_writers
    )
    with open(OUT / "writers_li10_distribution.txt", "w") as f:
        f.write("Distribution of (offset, base_reg) for li-10 -> sb writers:\n\n")
        for (off, rb), n in by_offrb.most_common():
            f.write(f"  off=0x{off:04X}({off:>5d})  base={rb:<5s}  hits={n}\n")
    print(f"  wrote {OUT / 'writers_li10_then_sb.txt'} and writers_li10_distribution.txt")

    # ---------- Hunt #2: bit-setters for the M19->PostGame flips ---------
    print("\nHunting for `lbu/ori/sb` bit-setter patterns matching M19->PostGame deltas...")
    bit_setters: list[dict] = []
    for off, mask in ADDED_BITS_PER_OFFSET.items():
        for name, insns in insns_by_file.items():
            hits = find_bit_setter(insns, name=name, target_off=off, mask=mask)
            bit_setters.extend(hits)
            if hits:
                print(f"  off=0x{off:04X} mask=0x{mask:02X} in {name}: {len(hits)} hits")

    context_dump(
        OUT / "writers_bit_setters.txt",
        "lbu rA, off($rB); ori rC, rA, MASK; sb rC, off($rB) where (off, "
        "mask) matches a bit added between Mission 19 (post-Analogman) "
        "and Post Game (Tera Domain unlocked).",
        insns_by_file,
        bit_setters,
    )
    print(f"  wrote {OUT / 'writers_bit_setters.txt'}")

    print("\nDone. Inspect ./out/writers_*.txt manually to identify the actual writer.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
