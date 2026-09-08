# -*- coding: utf-8 -*-
r"""Run the scanner over the real catalogue, and publish what it finds.

Both READMEs in this family name the same open step: everything so far is
offline and synthetic, and the honest next move is to point the scanner at the
actual UnifAI action catalogue and report the result **including "nothing", if
that is the answer**.

The data was captured on 08.09.2026 from the public search API -- 183 distinct
actions across 45 toolkits, 822 free-text ``description`` fields -- and lives in
``messung_2026-09-08/actions_full.json``.

On disclosure
-------------
If this finds a genuine injection in a live third-party toolkit, that is a
security finding about somebody else's published code. It goes to UnifAI
privately and it does **not** go into a public issue naming the toolkit. This
script therefore prints toolkit names to the local console for triage and writes
an anonymised summary for anything that might be published. Nothing here sends
anything anywhere.
"""
from __future__ import annotations

import io
import json
import os
import sys
from collections import Counter
from typing import Dict, List, Tuple

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

HIER = os.path.dirname(os.path.abspath(__file__))
WURZEL = os.path.dirname(HIER)
sys.path.insert(0, WURZEL)

from unifai_guard import Severity, scan_action, scan_text  # noqa: E402

DATEN = os.path.join(WURZEL, "messung_2026-09-08", "actions_full.json")


def lade() -> Dict[str, dict]:
    with io.open(DATEN, encoding="utf-8") as fh:
        return json.load(fh)


def als_action(schluessel: str, eintrag: dict) -> dict:
    """Bring one record into the shape scan_action expects."""
    pd = eintrag.get("payload")
    if isinstance(pd, str):
        try:
            pd = json.loads(pd)
        except (ValueError, TypeError):
            pd = {}
    if isinstance(pd, dict) and isinstance(pd.get("properties"), dict):
        pd = pd["properties"]
    return {
        "action": schluessel,
        "description": eintrag.get("description") or "",
        "payloadDescription": pd if isinstance(pd, dict) else {},
    }


def main() -> int:
    if not os.path.exists(DATEN):
        print("  Daten fehlen: %s" % DATEN)
        return 2

    roh = lade()
    print("")
    print("  " + "=" * 74)
    print("   DER SCANNER AM ECHTEN KATALOG")
    print("  " + "=" * 74)
    print("   Daten  : %s" % os.path.relpath(DATEN, WURZEL))
    print("   Erhoben: 08.09.2026, oeffentliche Such-API, 50 Abfragen")
    print("")

    toolkits = {k.rsplit("--", 1)[0] for k in roh}
    felder = 0
    for e in roh.values():
        pd = e.get("payload")
        if isinstance(pd, dict):
            felder += sum(1 for v in pd.get("properties", pd).values()
                          if isinstance(v, dict) and isinstance(v.get("description"), str))

    print("   %d Actions · %d Toolkits · %d Freitext-Felder"
          % (len(roh), len(toolkits), felder))
    print("")

    befunde: List[Tuple[str, str, object]] = []
    nach_schwere: Counter = Counter()
    nach_detektor: Counter = Counter()
    sauber = 0

    for schluessel, eintrag in sorted(roh.items()):
        rep = scan_action(als_action(schluessel, eintrag))
        if rep.clean:
            sauber += 1
            continue
        nach_schwere[rep.max_severity] += 1
        for f in rep.findings:
            nach_detektor[f.detector] += 1
        befunde.append((schluessel, rep.summary(), rep))

    print("  ERGEBNIS")
    print("  " + "-" * 74)
    print("   sauber, kein einziger Fund : %d von %d" % (sauber, len(roh)))
    for s in sorted(nach_schwere, reverse=True):
        print("   %-26s : %d" % (str(s), nach_schwere[s]))
    print("")

    if nach_detektor:
        print("  WELCHE DETEKTOREN")
        print("  " + "-" * 74)
        for det, n in nach_detektor.most_common():
            print("   %-26s %d" % (det, n))
        print("")

    ernst = [(k, r) for k, _s, r in befunde
             if r.max_severity >= Severity.HIGH]
    if ernst:
        print("  \U0001F534 HIGH ODER HOEHER — einzeln ansehen, NICHT oeffentlich nennen")
        print("  " + "-" * 74)
        for k, r in ernst:
            print("   %s" % k)
            for f in r.at_or_above(Severity.HIGH):
                print("       %s" % f)
        print("")
    else:
        print("  ✅ Kein einziger Fund ab HIGH im gesamten Katalog.")
        print("     Das ist ein Ergebnis, kein fehlendes Ergebnis — und es gehoert")
        print("     genauso veroeffentlicht wie ein Fund.")
        print("")

    # Anonymised summary, safe to quote publicly.
    zusammen = {
        "erhoben": "2026-09-08",
        "quelle": "UnifAI public search API, 50 queries, union",
        "actions": len(roh),
        "toolkits": len(toolkits),
        "description_felder": felder,
        "ohne_befund": sauber,
        "nach_schwere": {str(s): n for s, n in nach_schwere.items()},
        "nach_detektor": dict(nach_detektor),
        "ab_high": len(ernst),
        "hinweis": ("Toolkit-Namen sind hier bewusst nicht enthalten. Ein Fund in "
                    "einem fremden, veroeffentlichten Toolkit geht privat an UnifAI, "
                    "nicht in ein oeffentliches Issue."),
    }
    ziel = os.path.join(WURZEL, "messung_2026-09-08", "scan_ergebnis.json")
    with io.open(ziel, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(zusammen, fh, ensure_ascii=False, indent=2)
    print("  Anonymisierte Zusammenfassung: %s" % os.path.relpath(ziel, WURZEL))
    print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
