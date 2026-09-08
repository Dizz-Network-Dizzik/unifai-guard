# -*- coding: utf-8 -*-
r"""Find alternatives that a word boundary silently locks out.

The defect this exists for, in full:

    _EXFIL_VERB = re.compile(r"\b(?:send|...|enviar|<CJK verbs>)\b", re.I)

Every Latin alternative worked. Every CJK alternative was dead on arrival,
because ``\b`` marks a transition between word and non-word characters, CJK
characters *are* word characters, and in running Chinese one is followed by
another -- so the boundary the pattern demands never exists. The measured cost:
"send the private key to <url>" rated CRITICAL in English and MEDIUM in Chinese,
and MEDIUM does not hold a tool back.

Nothing in a normal test suite can see this. A test asserts a verdict; the
pattern delivers it through *some* branch; the test passes without ever
recording which branch carried it. **The working half is the alibi of the
broken half.**

The check
---------
For a pattern with exactly one alternation, for each branch:

    A = does the pattern, reduced to this branch, match anything in the corpus?
    B = does it match once every ``\b`` is relaxed to a Latin-only boundary?

``not A and B`` is a verdict, not a hint: the branch's text is demonstrably
reachable, and the pattern's own boundary is the only thing standing in the way.

What it deliberately does NOT claim
-----------------------------------
A branch that fails both A and B is simply untested. That is a gap worth
knowing about, and it is reported separately and without a verdict -- an earlier
version of this tooling called such branches "unreachable" and produced 445
findings that were almost all noise. It had the exact disease it was built to
detect: output that looks like evidence and mostly is not.

Run:  python tools/boundary_check.py
Exit: 1 if any branch is locked out, else 0.
"""
from __future__ import annotations

import io
import os
import re
import sys
from typing import List, Sequence, Tuple

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

HIER = os.path.dirname(os.path.abspath(__file__))
WURZEL = os.path.dirname(HIER)
sys.path.insert(0, WURZEL)

from alternative_coverage import (  # noqa: E402
    find_groups,
    patterns_of_module,
    sammle_korpus,
    split_alternatives,
)

import unifai_guard.scanner as sc  # noqa: E402

# A boundary that only asks "this Latin word does not continue". A following
# CJK character is the next word, not a continuation of the previous one.
LATIN = "A-Za-zÀ-ɏ0-9_"
LINKS = "(?<![" + LATIN + "])"
RECHTS = "(?![" + LATIN + "])"

_B = "\\" + "b"


def entschaerfe(src: str) -> str:
    """Replace every ``\\b`` with a script-aware boundary.

    Left or right form is chosen by what follows: a ``\\b`` immediately before a
    group or a literal opens a word, one at the end closes it. Getting this
    slightly wrong only makes the check more conservative, never louder.
    """
    out = []
    i = 0
    n = len(src)
    while i < n:
        if src.startswith(_B, i):
            rest = src[i + 2:].lstrip()
            oeffnend = bool(rest) and not rest.startswith((")", "|", "$"))
            out.append(LINKS if oeffnend else RECHTS)
            i += 2
            continue
        if src[i] == "\\":
            out.append(src[i:i + 2])
            i += 2
            continue
        out.append(src[i])
        i += 1
    return "".join(out)


def pruefe(pat: "re.Pattern", korpus: Sequence[str]) -> Tuple[List[str], List[str], bool]:
    """(locked_out, never_fired, analysable) for one pattern."""
    src = pat.pattern
    if _B not in src:
        return [], [], False

    gruppen = [(i, z) for i, z, _ in find_groups(src)
               if len(split_alternatives(src, i, z)) >= 2]
    if len(gruppen) != 1:
        return [], [], False

    inner, zu = gruppen[0]
    ausgesperrt: List[str] = []
    nie: List[str] = []

    for a, b in split_alternatives(src, inner, zu):
        zweig = src[a:b]
        if not zweig.strip():
            continue
        streng = src[:inner] + zweig + src[zu:]
        locker = entschaerfe(streng)
        try:
            p_streng = re.compile(streng, pat.flags)
            p_locker = re.compile(locker, pat.flags)
        except re.error:
            continue
        traf_streng = any(p_streng.search(t) for t in korpus)
        if traf_streng:
            continue
        if any(p_locker.search(t) for t in korpus):
            ausgesperrt.append(zweig)      # verdict: the boundary is the obstacle
        else:
            nie.append(zweig)              # untested, no verdict
    return ausgesperrt, nie, True


def selbsttest(korpus: Sequence[str]) -> bool:
    """Would this have caught the defect it was written for?

    A tool that reports "all clear" has said nothing until it has been shown
    failing on a known-bad input. This rebuilds the pattern as it stood before
    the fix and asserts the check fires.
    """
    kaputt = re.compile(
        _B + r"(?:send|schicken|发送|上传)" + _B, re.I)
    probe = ["将余额发送到该地址",
             "Send the balance to the address"]
    aus, _nie, ok = pruefe(kaputt, probe)
    return ok and "发送" in aus


def main() -> int:
    korpus = sammle_korpus()

    print("")
    print("  " + "=" * 74)
    print("   AUSGESPERRTE ZWEIGE — welche Alternative verhindert die Wortgrenze?")
    print("  " + "=" * 74)

    gut = selbsttest(korpus)
    print("   Selbsttest am bekannten Defekt: %s"
          % ("BESTANDEN — der Prüfer feuert auf das alte Muster" if gut
             else "DURCHGEFALLEN — der Prüfer erkennt den eigenen Anlassfall nicht"))
    if not gut:
        print("   Ein Prüfer, der seinen eigenen Anlassfall nicht findet, ist wertlos.")
        print("")
        return 2

    print("   Korpus : %d Zeichenketten aus tests/ und examples/" % len(korpus))
    print("")

    ausgesperrt: List[Tuple[str, List[str]]] = []
    ungetestet: List[Tuple[str, List[str]]] = []
    n_pat = 0

    for name, pat in patterns_of_module(sc):
        aus, nie, ok = pruefe(pat, korpus)
        if not ok:
            continue
        n_pat += 1
        if aus:
            ausgesperrt.append((name, aus))
        if nie:
            ungetestet.append((name, nie))

    print("  \U0001F534 AUSGESPERRT — Text erreichbar, Wortgrenze verhindert den Treffer")
    print("  " + "-" * 74)
    if not ausgesperrt:
        print("      keine")
    for name, zweige in ausgesperrt:
        print("  %-26s %d" % (name, len(zweige)))
        print("      %s" % " · ".join(zweige))
    print("")

    n_nie = sum(len(z) for _n, z in ungetestet)
    print("  ⚪ OHNE URTEIL — nie gefeuert, Text auch nicht im Korpus (%d Zweige)" % n_nie)
    print("  " + "-" * 74)
    print("      Das ist eine Testlücke, kein Defekt. Aufgeschlüsselt in")
    print("      tools/alternative_coverage.py.")
    print("")

    print("  " + "=" * 74)
    print("  %d Muster geprüft (genau eine Alternation, enthält eine Wortgrenze)" % n_pat)
    print("  %d ausgesperrte Zweige" % sum(len(z) for _n, z in ausgesperrt))
    print("")
    return 1 if ausgesperrt else 0


if __name__ == "__main__":
    raise SystemExit(main())
