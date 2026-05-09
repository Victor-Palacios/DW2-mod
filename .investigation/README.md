# `.investigation/` — DW2 reverse-engineering working directory

Throwaway artifacts and per-feature reports. None of this is imported by
`patch_dw2.py`; the whole folder can be deleted without breaking the
patcher.

## Convention

Each feature/question gets:

- A `REPORT_<topic>.md` (or just `REPORT.md` for the first one) with the
  initial investigation.
- A `POSTSCRIPT_<topic>.md` *if and when* the conclusion is later
  contradicted by testing or a follow-up pass. Don't rewrite the
  original report — leave it as the historical artifact, add a
  `> ⚠️` callout at the top pointing at the postscript.
- Helper scripts (`find_*.py`, `inspect_*.py`) that produced any
  artifacts in `out/`.
- `out/<topic>_<thing>.txt` for raw scan results worth keeping.

The disc image (`dw2.bin`/`dw2.cue`) is gitignored — extract it from the
project's `Digimon World 2 (USA).chd` with `chdman extractcd` if you
need to re-run the scanners.

## Feature ledger

| Topic | Status | Files |
|---|---|---|
| Tera Domain early unlock | Falsified — patch ships disabled | `REPORT.md` + `POSTSCRIPT_tera_domain.md` |

When a new investigation starts, append a row here so future readers
can see at a glance what's been tried and what worked.
