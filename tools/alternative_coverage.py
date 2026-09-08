# -*- coding: utf-8 -*-
r"""Which alternatives in this package's patterns have never once matched?

The question comes from a real defect. The send-verb pattern read:

    \b(?:send|...|senden|schicken|uebermitteln|enviar|CJK-verbs...)\b

and its Chinese alternatives could never fire, because ``\b`` cannot mark a
boundary between two CJK characters. The pattern kept matching English all day,
so nothing ever looked wrong. **The working half was the alibi of the broken
half.**

That class is invisible to ordinary tests. A test asserts "this text is
CRITICAL", the pattern delivers CRITICAL through *some* branch, the test passes,
and nobody learns which branch carried it. A pattern with forty alternatives can
have thirty dead ones and a green suite.

So this tool asks what the tests cannot, and splits the answer in two:

  RED   -- the branch's own text DOES occur in the corpus, and the pattern
           reduced to that single branch still never matches. The word is
           there; the pattern cannot reach it. **That is a defect.**

  AMBER -- the branch's text never occurs in the corpus at all. Nothing is
           provably broken; nobody has ever exercised it.

Conflating those two was the first version's mistake: reducing a multi-group
pattern to one branch also requires the *other* groups to match, so branches
looked dead merely because the rest of the pattern was absent from the corpus.
Requiring the branch's own text to be present is what makes the test fair.

Run:  python tools/alternative_coverage.py
Exit: 1 if anything is RED, else 0.
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

import unifai_guard.scanner as sc  # noqa: E402


# --------------------------------------------------------------------------- #
#  Taking an alternation apart, without guessing
# --------------------------------------------------------------------------- #
def split_alternatives(src: str, start: int, end: int) -> List[Tuple[int, int]]:
    """Spans of the top-level alternatives in ``src[start:end]``.

    Depth-aware: a ``|`` inside a nested group or a character class is not a
    separator, and an escaped ``\\|`` is a literal.
    """
    spans: List[Tuple[int, int]] = []
    depth = 0
    in_class = False
    i = start
    stueck = start
    while i < end:
        c = src[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            spans.append((stueck, i))
            stueck = i + 1
        i += 1
    spans.append((stueck, end))
    return spans


_GROUP_HEAD = re.compile(r"\(\?(?:P<[^>]*>|P=[^)]*\)|[aiLmsux]*:|<[=!]|[=!:#>])")


def find_groups(src: str) -> List[Tuple[int, int, int]]:
    """Every group as ``(inner_start, inner_end, close_index)``."""
    out: List[Tuple[int, int, int]] = []
    stack: List[int] = []
    in_class = False
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
        elif c == "(":
            stack.append(i)
        elif c == ")" and stack:
            auf = stack.pop()
            m = _GROUP_HEAD.match(src, auf)
            inner = m.end() if m else auf + 1
            out.append((inner, i, i))
        i += 1
    return out


# --------------------------------------------------------------------------- #
#  The corpus: every string this package is tested against
# --------------------------------------------------------------------------- #
def sammle_korpus() -> List[str]:
    korpus: List[str] = []
    muster = re.compile(
        r'"""(.*?)"""|\'\'\'(.*?)\'\'\'|"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'', re.S)
    for ordner in ("tests", "examples"):
        pfad = os.path.join(WURZEL, ordner)
        if not os.path.isdir(pfad):
            continue
        for name in sorted(os.listdir(pfad)):
            if not name.endswith(".py"):
                continue
            with io.open(os.path.join(pfad, name), encoding="utf-8") as fh:
                quelle = fh.read()
            for m in muster.finditer(quelle):
                s = next((g for g in m.groups() if g), "")
                if len(s) < 8:
                    continue
                korpus.append(s)
                if "\\u" in s or "\\x" in s or "\\N" in s:
                    try:
                        korpus.append(s.encode("latin-1", "backslashreplace")
                                       .decode("unicode_escape"))
                    except (UnicodeDecodeError, UnicodeEncodeError):
                        pass
    return korpus


# --------------------------------------------------------------------------- #
#  The measurement
# --------------------------------------------------------------------------- #
def patterns_of_module(modul) -> List[Tuple[str, "re.Pattern"]]:
    out: List[Tuple[str, "re.Pattern"]] = []
    for name in sorted(dir(modul)):
        v = getattr(modul, name)
        if isinstance(v, re.Pattern):
            out.append((name, v))
        elif isinstance(v, (list, tuple)):
            for i, e in enumerate(v):
                if isinstance(e, re.Pattern):
                    out.append(("%s[%d]" % (name, i), e))
                elif isinstance(e, (list, tuple)) and e and isinstance(e[0], str):
                    try:
                        out.append(("%s[%d]" % (name, i), re.compile(e[0], re.I)))
                    except re.error:
                        pass
    return out


def pruefe_pattern(pat: "re.Pattern",
                   korpus: Sequence[str]) -> Tuple[List[str], List[str], int, bool]:
    r"""Return (unreachable, untested, total_branches, analysable).

    **Only patterns with exactly ONE alternation group are analysable**, and
    that restriction is the whole difference between a useful tool and a noisy
    one. A pattern like ``(?:always|must)\s+(?:set|use)\s+(?:max|entire)`` is a
    conjunction: reducing the first group to ``always`` still needs the other
    two groups satisfied by the *same* string. If no corpus entry happens to say
    "always set max" in that exact shape, every branch of every group reports
    dead -- and none of them is.

    The first version of this tool did exactly that and produced 445 findings,
    almost all of them noise. It had the very disease it was written to detect:
    output that looks like evidence and mostly is not. Restricting to
    single-alternation patterns makes the reduction exact, and the CJK defect
    that prompted all this sits squarely inside that scope.
    """
    src = pat.pattern
    unerreichbar: List[str] = []
    ungetestet: List[str] = []
    gesamt = 0

    gruppen = [(i, z) for i, z, _ in find_groups(src)
               if len(split_alternatives(src, i, z)) >= 2]
    if len(gruppen) != 1:
        return [], [], 0, False

    for inner, zu in gruppen:
        spans = split_alternatives(src, inner, zu)
        for a, b in spans:
            zweig = src[a:b]
            if not zweig.strip():
                continue
            gesamt += 1

            try:
                ganz = re.compile(src[:inner] + zweig + src[zu:], pat.flags)
            except re.error:
                continue
            if any(ganz.search(t) for t in korpus):
                continue                        # this branch demonstrably fires

            try:
                blank = re.compile(zweig, pat.flags)
            except re.error:
                ungetestet.append(zweig)
                continue
            if any(blank.search(t) for t in korpus):
                unerreichbar.append(zweig)      # text is there, pattern cannot reach it
            else:
                ungetestet.append(zweig)        # simply never exercised
    return unerreichbar, ungetestet, gesamt, True


def _liste(zweige: Sequence[str], breite: int = 64) -> List[str]:
    zeilen, zeile = [], ""
    for z in zweige:
        k = z if len(z) <= 22 else z[:21] + "…"
        if len(zeile) + len(k) > breite:
            zeilen.append(zeile.rstrip(" ·"))
            zeile = ""
        zeile += k + " · "
    if zeile:
        zeilen.append(zeile.rstrip(" ·"))
    return zeilen


def main() -> int:
    korpus = sammle_korpus()
    muster = patterns_of_module(sc)

    print("")
    print("  " + "=" * 74)
    print("   ALTERNATIVEN-ABDECKUNG — welcher Zweig hat je gefeuert?")
    print("  " + "=" * 74)
    print("   Korpus : %d Zeichenketten aus tests/ und examples/" % len(korpus))
    print("   Muster : %d kompilierte Ausdrücke in scanner.py" % len(muster))
    print("")

    gesamt = n_unerr = n_unget = 0
    n_analysierbar = n_uebersprungen = 0
    rot: List[Tuple[str, List[str]]] = []
    gelb: List[Tuple[str, List[str]]] = []

    for name, pat in muster:
        unerr, unget, anzahl, analysierbar = pruefe_pattern(pat, korpus)
        if not analysierbar:
            n_uebersprungen += 1
            continue
        n_analysierbar += 1
        gesamt += anzahl
        n_unerr += len(unerr)
        n_unget += len(unget)
        if unerr:
            rot.append((name, unerr))
        if unget:
            gelb.append((name, unget))

    def zeige(titel: str, befunde: List[Tuple[str, List[str]]]) -> None:
        print("  " + titel)
        print("  " + "-" * 74)
        if not befunde:
            print("      keine")
        for name, zweige in sorted(befunde, key=lambda x: -len(x[1])):
            print("  %-26s %d" % (name, len(zweige)))
            for zeile in _liste(zweige):
                print("      %s" % zeile)
        print("")

    zeige("\U0001F534 UNERREICHBAR — das Wort steht im Korpus, das Muster kommt nicht hin", rot)
    zeige("\U0001F7E1 UNGETESTET — das Wort kommt im Korpus gar nicht vor", gelb)

    benutzt = gesamt - n_unerr - n_unget
    print("  " + "=" * 74)
    print("  %d Muster mit genau EINER Alternation — nur die sind so messbar."
          % n_analysierbar)
    print("  %d übersprungen: mehrere Alternationen, dort ist ein Zweig nicht"
          % n_uebersprungen)
    print("     isolierbar (Und-Verknüpfung), und jede Messung wäre Rauschen.")
    print("")
    print("  %d Alternativen insgesamt" % gesamt)
    print("  %d unerreichbar · %d ungetestet · %d nachweislich benutzt"
          % (n_unerr, n_unget, benutzt))
    if gesamt:
        print("  nachweislich benutzt: %.0f %%" % (100.0 * benutzt / gesamt))
    print("")
    print("  \U0001F534 ist ein Befund: das Muster KANN eine Zeichenkette nicht erreichen,")
    print("     die im eigenen Korpus steht. Genau so sah der CJK-Fall aus.")
    print("  \U0001F7E1 ist eine Lücke, kein Fehler — aber in einem Sicherheitsfilter")
    print("     ist ein Zweig, den nie jemand hat feuern sehen, auch keine Zusicherung.")
    print("")
    return 1 if n_unerr else 0


if __name__ == "__main__":
    raise SystemExit(main())
