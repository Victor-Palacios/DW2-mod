#!/usr/bin/env python3
"""
Step 3: Find every load (lbu/lb) of `story_progress` at RAM 0x8005E632.

In DW2, the post-credits writer in STAG2000.PRO uses:
    lui   $v1, 0x8006        ; v1 = 0x80060000
    sb    $v0, -0x19CE($v1)  ; store v0 at 0x8005E632

The standard MIPS encoding pairs `lui rX, 0x8006` with a 16-bit signed
offset of -0x19CE (= 0xE632 unsigned). Some compilers split the
composition across an `addiu/ori` first; we handle both.

We then dump full context windows for each reader hit, plus everything
within ~6 instructions afterwards (so we capture the slti/sltiu/beq/bne
that almost certainly forms the gate decision).

Output: ./out/readers_story_progress.txt
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import patch_dw2 as dw2

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

OUT = HERE / "out"
OUT.mkdir(exist_ok=True)
BIN = HERE / "dw2.bin"

STORY_PROGRESS_ADDR = 0x8005E632

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


def find_address_users(insns, target_addr: int, *, window: int = 12):
    """Return list of (insn_idx, mnemonic, kind) where kind is 'load' or
    'store' or 'addr' (just an effective-address compute), for every
    instruction that touches `target_addr` via lui+(addiu|ori)?+memop or
    lui+memop.
    """
    n = len(insns)
    hits: list[dict] = []
    for i, ins in enumerate(insns):
        if ins.mnemonic != "lui":
            continue
        m = _REG_IMM_RE.match(ins.op_str)
        if not m:
            continue
        reg = m.group(1)
        try:
            hi = parse_imm(m.group(2))
        except ValueError:
            continue
        base_hi = (hi & 0xFFFF) << 16

        # Trace reg through forward window.
        regs: dict[str, int] = {reg: base_hi}

        for j in range(i + 1, min(n, i + 1 + window)):
            j_ins = insns[j]
            jm, jops = j_ins.mnemonic, j_ins.op_str

            if jm == "lui":
                m2 = _REG_IMM_RE.match(jops)
                if m2 and m2.group(1) in regs:
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

            if jm in ("lb", "lbu", "lh", "lhu", "lw", "sb", "sh", "sw"):
                m2 = _MEM_OPS_RE.match(jops)
                if m2:
                    off = signed16(parse_imm(m2.group(2)) & 0xFFFF)
                    rs = m2.group(3)
                    if rs in regs:
                        target = (regs[rs] + off) & 0xFFFFFFFF
                        if target == target_addr:
                            kind = "store" if jm.startswith("s") else "load"
                            hits.append({
                                "lui_idx": i,
                                "lui_addr": ins.address,
                                "memop_idx": j,
                                "memop_addr": j_ins.address,
                                "memop": jm,
                                "kind": kind,
                            })
    return hits


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
        for cand in range(395, 415):
            if cand in (dw2.IDX_STAG3000_PRO, dw2.IDX_STAG4000_PRO):
                continue
            try:
                data = bytes(disc.read_file(cand))
                if len(data) >= 4096 and data[:4] != b"\x00\x00\x00\x00":
                    files.append((f"file_{cand}", data, 0))
            except Exception:
                pass

    print(f"\nSearching for accesses to story_progress @ 0x{STORY_PROGRESS_ADDR:08X} ...")
    out_lines: list[str] = [
        f"Reads/writes of story_progress (RAM 0x{STORY_PROGRESS_ADDR:08X}, "
        "= save slot offset 0x1050).",
        "",
    ]
    total_loads = 0
    total_stores = 0

    for name, data, base in files:
        insns = disasm_all(data, base)
        hits = find_address_users(insns, STORY_PROGRESS_ADDR)
        if not hits:
            continue
        loads  = [h for h in hits if h["kind"] == "load"]
        stores = [h for h in hits if h["kind"] == "store"]
        total_loads  += len(loads)
        total_stores += len(stores)
        print(f"  {name}: {len(loads)} loads, {len(stores)} stores")
        out_lines.append(f"=== {name} (loads={len(loads)} stores={len(stores)}) ===")
        for h in hits:
            mi = h["memop_idx"]
            lo = max(0, h["lui_idx"])
            hi = min(len(insns), mi + 6)
            out_lines.append("")
            out_lines.append(f"--- {h['kind'].upper()} via {h['memop']} at 0x{h['memop_addr']:08X} (lui at 0x{h['lui_addr']:08X}) ---")
            for ins in insns[lo:hi]:
                marker = ">>> " if ins.address in (h["memop_addr"], h["lui_addr"]) else "    "
                out_lines.append(marker + fmt_insn(ins))
        out_lines.append("")

    (OUT / "readers_story_progress.txt").write_text("\n".join(out_lines) + "\n")
    print(f"\nTotal: {total_loads} loads + {total_stores} stores -> {OUT / 'readers_story_progress.txt'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
