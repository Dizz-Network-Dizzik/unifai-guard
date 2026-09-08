# -*- coding: utf-8 -*-
"""The description is an input channel. Nobody treats it like one.

Dynamic tool discovery means an agent finds tools it has never seen, written by
people it has never heard of, and reads their descriptions to decide what to do.
UnifAI says so plainly in its own documentation: ``payloadDescription`` "doesn't
have to be in a certain format, as long as agents can understand it as natural
language", and "agents read it and decide what parameters to use".

That is a sound design decision for ergonomics. It also means the description
field is a place where a third party writes text that goes straight into the
agent's reasoning -- with no schema to constrain it and no review step before the
agent acts on it.

This module scans that text before the agent trusts it. It is deliberately boring:
no model, no network, no dependencies. It looks for the shapes that separate
"documentation of a parameter" from "instruction to the reader", and it reports
what it found rather than deciding for you.

Three passes, because one is not enough
---------------------------------------
1. **Raw**   -- characters that are present but invisible, and letters that are
   not the letters they look like. These have to be seen before anything is
   normalised away.
2. **Canonical** -- the same text with format characters removed, NFKC applied
   and known homoglyphs folded to ASCII. Phrase detectors run here, so
   ``ignore all previous`` written in mathematical bold or with a zero-width
   space in the middle reads as what it is.
3. **Decoded** -- base64, percent-encoding, HTML entities, ``\\uXXXX`` escapes,
   hex, rot13, reversed text, Unicode tag characters and variation-selector
   smuggling. Whatever comes out is canonicalised and run through the phrase
   detectors again. Text that had to be encoded to survive review is judged by
   what it says once decoded.

What it is not
--------------
It is not a filter that makes untrusted tools safe. Anyone who knows the rules can
write around them. It raises the cost of the obvious attacks and it makes the
non-obvious ones visible in a log, which is the honest claim -- see the README,
including its list of bypasses that are still open on purpose.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import enum
import html
import re
import unicodedata
from dataclasses import dataclass, field as _dc_field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote

__all__ = ["Severity", "Finding", "ScanReport", "scan_text", "scan_action", "scan_toolkit"]


class Severity(enum.IntEnum):
    """Ordered so ``max()`` and ``>=`` mean what they look like."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - display only
        return self.name


@dataclass(frozen=True)
class Finding:
    detector: str
    severity: Severity
    message: str
    excerpt: str = ""
    where: str = ""

    def __str__(self) -> str:  # pragma: no cover - display only
        loc = " [%s]" % self.where if self.where else ""
        ex = "  ->  %s" % _clip(self.excerpt) if self.excerpt else ""
        return "%-8s %-22s%s %s%s" % (self.severity, self.detector, loc, self.message, ex)


@dataclass
class ScanReport:
    findings: List[Finding] = _dc_field(default_factory=list)
    scanned_chars: int = 0

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    @property
    def clean(self) -> bool:
        return not self.findings

    def at_or_above(self, level: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity >= level]

    def blocks_at(self, level: Severity) -> bool:
        return bool(self.at_or_above(level))

    def summary(self) -> str:
        if not self.findings:
            return "clean (%d chars scanned)" % self.scanned_chars
        counts: Dict[Severity, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        parts = ["%d %s" % (counts[s], s) for s in sorted(counts, reverse=True)]
        return "%d finding(s): %s" % (len(self.findings), ", ".join(parts))

    def report(self) -> str:
        lines = [self.summary()]
        for f in sorted(self.findings, key=lambda x: -x.severity):
            lines.append("  " + str(f))
        return "\n".join(lines)

    def extend(self, other: "ScanReport") -> "ScanReport":
        self.findings.extend(other.findings)
        self.scanned_chars += other.scanned_chars
        return self


# --------------------------------------------------------------------------- #
#  Invisible and disguised characters
# --------------------------------------------------------------------------- #

# Characters that carry no visible mark. In prose written for a human reader they
# are a typographic accident; in a tool description they are how you hide a
# sentence from the person reviewing it while leaving it perfectly legible to the
# model.
_ZERO_WIDTH = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x2060: "WORD JOINER",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE",
    0x00AD: "SOFT HYPHEN",
    0x034F: "COMBINING GRAPHEME JOINER",
    0x061C: "ARABIC LETTER MARK",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0x115F: "HANGUL CHOSEONG FILLER",
    0x1160: "HANGUL JUNGSEONG FILLER",
    0x17B4: "KHMER VOWEL INHERENT AQ",
    0x17B5: "KHMER VOWEL INHERENT AA",
    0x3164: "HANGUL FILLER",
    0xFFA0: "HALFWIDTH HANGUL FILLER",
    0x2028: "LINE SEPARATOR",
    0x2029: "PARAGRAPH SEPARATOR",
}
# Directional *marks* (as opposed to overrides) are ordinary inside Arabic and
# Hebrew text. Reported, not shouted about.
_WEAK_MARKS = {0x200E, 0x200F, 0x061C}
_WEAK_MARK_NAMES = {_ZERO_WIDTH[cp] for cp in _WEAK_MARKS}
_BIDI = {
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
}

# U+E0000..E007F are the Unicode tag characters -- an exact, invisible copy of
# ASCII. U+E0100..E01EF are the variation selector supplement; a single one after
# an ideograph is a legitimate glyph choice, a run of them is a byte channel.
_TAG_LO, _TAG_HI = 0xE0000, 0xE007F
_VS_SUP_LO, _VS_SUP_HI = 0xE0100, 0xE01EF
_VS_LO, _VS_HI = 0xFE00, 0xFE0F


def _is_vs(cp: int) -> bool:
    return _VS_LO <= cp <= _VS_HI or _VS_SUP_LO <= cp <= _VS_SUP_HI


# Letters that are not the letters they look like. Only true confusables belong
# here: folding 'ä' to 'a' would break every honest German description, so the
# table carries Cyrillic/Greek/Cherokee/Armenian/Coptic/Lisu/Canadian-syllabics
# lookalikes and nothing else.
_CONFUSABLES = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ѕ": "s", "і": "i", "ј": "j", "к": "k", "м": "m",
    "н": "h", "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ԁ": "d",
    "ԛ": "q", "ԝ": "w", "ѵ": "v", "ё": "e", "є": "e", "ї": "i", "ѡ": "w",
    "А": "A", "В": "B", "Е": "E", "І": "I", "Ј": "J", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "Ѕ": "S", "Ԛ": "Q",
    "Ԝ": "W", "Ѵ": "V", "Ё": "E",
    # Greek
    "α": "a", "β": "b", "γ": "y", "ε": "e", "η": "n", "ι": "i", "κ": "k", "μ": "u",
    "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w", "ϲ": "c",
    "ϳ": "j", "ϱ": "p", "ϵ": "e",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Armenian
    "օ": "o", "ո": "n", "ա": "a", "ս": "u", "ր": "r", "գ": "q", "յ": "j", "ք": "p",
    "հ": "h", "ե": "e",
    # Cherokee
    "Ꭺ": "A", "Ꭼ": "E", "Ꮋ": "H", "Ꮖ": "T", "Ꮯ": "C", "Ꮪ": "S", "Ꮲ": "P", "Ꮐ": "G",
    "Ꮶ": "K", "Ꮮ": "L", "Ꮇ": "M", "Ꮢ": "R", "Ꮙ": "V", "Ꮃ": "W", "Ꮓ": "Z", "Ꭰ": "D",
    "Ᏼ": "B", "Ꮤ": "W", "Ꭶ": "F", "Ꮅ": "L",
    # Coptic
    "ⲟ": "o", "ⲣ": "p", "ⲉ": "e", "ⲁ": "a", "ⲧ": "t", "ⲛ": "n", "ⲥ": "c", "ⲕ": "k",
    "ⲭ": "x", "ⲙ": "m", "ⲏ": "h", "ⲓ": "i",
    # Lisu
    "ꓐ": "B", "ꓚ": "C", "ꓓ": "D", "ꓔ": "T", "ꓝ": "F", "ꓖ": "G", "ꓧ": "H", "ꓲ": "I",
    "ꓙ": "J", "ꓘ": "K", "ꓡ": "L", "ꓟ": "M", "ꓠ": "N", "ꓳ": "O", "ꓑ": "P", "ꓣ": "R",
    "ꓢ": "S", "ꓴ": "U", "ꓦ": "V", "ꓪ": "W", "ꓫ": "X", "ꓬ": "Y", "ꓜ": "Z", "ꓮ": "A",
    "ꓱ": "E",
    # Canadian Aboriginal syllabics
    "ᖇ": "R", "ᗅ": "A", "ᗞ": "D", "ᗪ": "D", "ᗰ": "M", "ᗯ": "W", "ᘉ": "N", "ᑎ": "N",
    "ᑭ": "P", "ᒪ": "L", "ᕼ": "H", "ᗷ": "B", "ᖴ": "F", "ᕮ": "E", "ᑌ": "U", "ᖶ": "T",
    "ᑕ": "C", "ᖯ": "b",
    # Latin letterlikes that NFKC leaves alone
    "ı": "i", "ɪ": "i", "ɑ": "a", "ɡ": "g", "ℓ": "l", "ſ": "s",
    "ᴀ": "a", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ɢ": "g", "ʜ": "h", "ᴊ": "j", "ᴋ": "k",
    "ʟ": "l", "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p", "ʀ": "r", "ꜱ": "s", "ᴛ": "t",
    "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ʏ": "y", "ᴢ": "z",
}
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)
_CONFUSABLE_CPS = {ord(c) for c in _CONFUSABLES}

# Scripts a homoglyph attack is drawn from. Latin-1 accents are deliberately not
# here: 'Empfänger' and 'Cantidad mínima' are documentation, not evasion.
_SCRIPT_RANGES: List[Tuple[str, int, int]] = [
    ("Cyrillic", 0x0400, 0x052F),
    ("Greek", 0x0370, 0x03FF),
    ("Armenian", 0x0530, 0x058F),
    ("Canadian Syllabics", 0x1400, 0x167F),
    ("Cherokee", 0x13A0, 0x13FF),
    ("Cherokee", 0xAB70, 0xABBF),
    ("Coptic", 0x2C80, 0x2CFF),
    ("Georgian", 0x10A0, 0x10FF),
    ("Lisu", 0xA4D0, 0xA4FF),
    ("Deseret", 0x10400, 0x1044F),
]


def _script_of(ch: str) -> Optional[str]:
    cp = ord(ch)
    for name, lo, hi in _SCRIPT_RANGES:
        if lo <= cp <= hi:
            return name
    return None


def _canonical(text: str) -> str:
    """Format characters out, NFKC applied, confusables folded to ASCII.

    Everything downstream that matches on words matches here, so an attacker gains
    nothing from writing the word in a different alphabet or breaking it with an
    invisible character.
    """
    if not text:
        return ""
    kept = []
    for ch in text:
        cp = ord(ch)
        if cp in _ZERO_WIDTH or cp in _BIDI or _TAG_LO <= cp <= _TAG_HI or _is_vs(cp):
            continue
        if unicodedata.category(ch) == "Cf":
            continue
        kept.append(ch)
    return unicodedata.normalize("NFKC", "".join(kept)).translate(_CONFUSABLE_TABLE)


def _nfkc_disguised_letters(text: str) -> int:
    """Count non-ASCII letters that NFKC turns into plain ASCII letters.

    Mathematical bold, fullwidth and enclosed forms all land here. Greek and
    Cyrillic do not -- NFKC leaves them alone, which is what the per-word
    mixed-script check is for.
    """
    n = 0
    for ch in text:
        if ord(ch) < 128 or not ch.isalpha():
            continue
        folded = unicodedata.normalize("NFKC", ch)
        if folded != ch and all(c.isascii() and c.isalpha() for c in folded):
            n += 1
    return n


# --------------------------------------------------------------------------- #
#  Phrase detectors -- all of these run against the canonical text
# --------------------------------------------------------------------------- #

_ROLE_MARKERS = [
    r"<\|\s*im_(?:start|end)\s*\|>",
    r"<\|\s*(?:system|user|assistant|endoftext)\s*\|>",
    r"<\|\s*(?:start|end)_header_id\s*\|>",
    r"<\|\s*eot_id\s*\|>",
    r"\[/?INST\]",
    r"<</?SYS>>",
    r"</?(?:system|assistant|human)>",
    r"(?:^|\n)\s*###\s*(?:instruction|system|response)\b",
    r"(?:^|\n)\s*(?:system|assistant|human)\s*:",
    r"\bBEGIN\s+SYSTEM\s+PROMPT\b",
    # A turn does not need the model's own delimiters to be read as a turn.
    r"(?:^|\n)\s*(?:role|speaker|turn|from)\s*:\s*(?:system|assistant|user|human|developer)\b",
]

# Overrides. These say, in one form or another, "stop doing what you were doing".
_OVERRIDE = [
    (r"\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|earlier|above|preceding)\b", "ignore previous instructions"),
    (r"\bdisregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|earlier|above|instructions?|rules?)\b", "disregard instructions"),
    (r"\bforget\s+(?:everything|all|what|your)\b", "forget prior context"),
    (r"\bnew\s+(?:instructions?|rules?|system\s+prompt)\b", "declares new instructions"),
    (r"\boverride\s+(?:the\s+)?(?:previous|prior|system|safety|security|default)\b", "override directive"),
    (r"\byour\s+(?:real|true|actual|new)\s+(?:instructions?|task|goal|purpose)\b", "redefines the agent's task"),
    (r"\byou\s+are\s+(?:now|actually)\s+(?:a|an|in)\b", "re-roles the agent"),
    (r"\bdeveloper\s+mode\b", "claims a privileged mode"),
    # -- paraphrases that carry the same instruction without the flagged words --
    (r"\bsupersedes?\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|earlier|preceding|above|system)\b",
     "declares itself to replace earlier instructions"),
    (r"\b(?:previous|prior|earlier|preceding|system|above)\s+(?:instructions?|prompts?|rules?|constraints?|guidance|directives?)\s+"
     r"(?:are|is|no\s+longer|do\s+not|does\s+not|don'?t|have\s+been)\b",
     "declares earlier instructions void"),
    (r"\btakes?\s+precedence\s+over\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|earlier|system|other)\s+"
     r"(?:instructions?|prompts?|rules?|guidance|directives?)\b", "claims precedence over the system prompt"),
    (r"\bfrom\s+now\s+on\b[^.\n]{0,40}\byou\b", "redefines how the reader is to behave"),
    (r"\bpretend\s+(?:you\s+are|to\s+be)\b", "asks the reader to adopt a role"),
    (r"\bact\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|admin|administrator|root|privileged|"
     r"different|autonomous)\b", "re-roles the agent"),
    (r"\bif\s+you\s+are\s+(?:an?\s+)?(?:ai|llm|language\s+model|agent|assistant|bot|automated)\b",
     "addresses the model rather than documenting a parameter"),
    (r"\bas\s+an?\s+(?:ai|llm|language\s+model)\b[^.\n]{0,30}\byou\b",
     "addresses the model rather than documenting a parameter"),
    (r"\byour\s+(?:system\s+prompt|safety\s+(?:rules|guidelines)|guardrails)\b",
     "refers to the agent's own configuration"),
    # -- other languages --
    (r"\b(?:ignoriere|missachte|vergiss)\b", "ignore/forget (German)"),
    (r"\bdu\s+bist\s+(?:jetzt|nun|ab\s+sofort)\b", "re-roles the agent (German)"),
    (r"\bab\s+(?:jetzt|sofort)\b[^.\n]{0,40}\bdu\b", "redefines behaviour (German)"),
    (r"\b(?:ignora|olvida|desestima)\s+(?:todas?\s+)?(?:las\s+)?"
     r"(?:instrucciones|reglas|indicaciones)\b", "ignore instructions (Spanish)"),
    (r"\bahora\s+eres\b", "re-roles the agent (Spanish)"),
    (r"忽略(?:之前|以上|先前|所有)", "ignore previous (Chinese)"),
    (r"无视(?:之前|以上|所有)", "disregard previous (Chinese)"),
    (r"忘记(?:之前|以上)", "forget previous (Chinese)"),
    (r"从现在开始", "from now on (Chinese)"),
    (r"你现在是", "you are now (Chinese)"),
]

# Softer reframings. Not proof on their own, but they belong to the same family
# and they make a combination damning.
_OVERRIDE_SOFT = [
    (r"\bthe\s+(?:rules?|constraints?|restrictions?|limits?|policies)\s+"
     r"(?:above|described\s+earlier|mentioned\s+earlier|in\s+your\s+prompt)\b",
     "refers to constraints it has no business knowing about"),
    (r"\bfor\s+(?:testing|debug(?:ging)?|evaluation|demo)\s+purposes\b[^.\n]{0,60}"
     r"\b(?:you|skip|ignore|bypass|disable|no)\b", "frames the request as a test to lower the bar"),
    (r"\byou\s+(?:are\s+authori[sz]ed|have\s+permission|are\s+permitted|may\s+safely|are\s+cleared)\s+to\b",
     "grants the reader a permission it cannot grant"),
    (r"\b(?:standing|blanket|prior|existing|open)\s+(?:mandate|authori[sz]ation|approval|consent)\b",
     "claims an authorisation that lives outside the description"),
]

# Concealment. A parameter doc has no reason to ask for silence.
_CONCEAL = [
    (r"\bdo\s*n[o']?t\s+(?:tell|inform|mention|show|reveal|display)\b", "asks the agent to withhold"),
    (r"\bwithout\s+(?:telling|informing|notifying|asking)\s+the\s+(?:user|human|owner)\b", "asks to bypass the human"),
    (r"\bsilently\b", "asks for silence"),
    (r"\bdo\s+not\s+(?:log|record|report)\b", "asks to skip the record"),
    (r"\bkeep\s+(?:this|it)\s+(?:secret|hidden|between)\b", "asks for secrecy"),
    (r"\bno\s+need\s+to\s+(?:ask|confirm|verify|check)\b", "waives confirmation"),
    (r"\b(?:pre-?)?approved\s+by\s+the\s+(?:user|owner|admin)\b", "claims an approval it cannot have"),
    # -- the same request, phrased so none of the words above appear --
    (r"\brefrain\s+from\s+(?:telling|mentioning|informing|notifying|disclosing|reporting|surfacing|showing)\b",
     "asks the agent to withhold"),
    (r"\bavoid\s+(?:telling|mentioning|informing|notifying|surfacing|alerting|displaying|disclosing|"
     r"raising|prompting)\b", "asks the agent to withhold"),
    (r"\bsuppress(?:es|ing)?\s+(?:the\s+|any\s+|all\s+)?(?:confirmation|approval|prompt|dialog\w*|"
     r"notification|warning|output|message|banner)\b", "asks for the human-facing step to be removed"),
    (r"\bno\s+(?:confirmation|approval|prompt|review|consent|authori[sz]ation|sign-?off)\s+(?:is\s+)?"
     r"(?:required|needed|necessary)\b", "waives confirmation"),
    (r"\bwithout\s+(?:the\s+)?(?:user|human|operator|owner|further|additional|explicit|prior|any)\s*"
     r"(?:'s)?\s*(?:confirmation|approval|review|consent|oversight|interaction|prompting|knowledge|"
     r"involvement|sign-?off)\b", "asks to bypass the human"),
    (r"\bskip\s+(?:the\s+|any\s+)?(?:confirmation|approval|prompt|review|verification|consent|human|"
     r"authori[sz]ation)\b", "asks to skip the human-facing step"),
    (r"\bbypass(?:es|ing)?\s+(?:the\s+|any\s+)?(?:confirmation|approval|check|review|prompt|gate|guard|"
     r"policy|restriction|limit)\b", "asks to bypass a control"),
    (r"\bhuman\s+(?:in\s+the\s+loop|review|approval)\s+is\s+(?:not\s+|un)?(?:required|needed|necessary)\b",
     "waives human review"),
    (r"\bruns?\s+unattended\b|\bunattended\s+(?:mode|execution|operation)\b",
     "declares that no human is watching"),
    (r"\bwaive[ds]?\s+(?:the\s+|any\s+)?(?:review|approval|confirmation|oversight|consent|check)\b",
     "claims a control has been switched off"),
    (r"\b(?:checks?|reviews?|approvals?|confirmations?|oversight|consent|limits?)\s+"
     r"(?:are|is|has\s+been|have\s+been|were|was)\s+(?:waived|lifted|disabled|suspended)\b",
     "claims a control has been switched off"),
    # No third party can honestly state where the host's approval threshold sits,
    # and stating it is how a caller is steered to stay underneath it.
    (r"\b(?:below|under|beneath|less\s+than)\s+[\d,.]+\s*\w*\s*(?:are|is)\s+"
     r"(?:auto-?approved|automatically\s+approved|approved\s+automatically|exempt)\b",
     "claims to know where the approval threshold sits"),
    (r"\b(?:keep|split|divide|break)\b[^.\n]{0,60}\b(?:below|under|beneath)\s+(?:the\s+)?"
     r"(?:limit|threshold|ceiling|cap)\b", "suggests staying under a control"),
    (r"\bin\s+the\s+background\s+without\b", "asks to act out of sight"),
    (r"\b(?:quietly|discreetly|covertly)\b", "asks for silence"),
    # "Do not tell the user" written as a rule about the summary rather than about
    # the user. The surface noun has to be there *and* the user has to be the one
    # kept away from it -- "do not include the 0x prefix in this field" is a
    # formatting rule and stays quiet.
    (r"\bdo\s*n[o']?t\s+(?:include|list|surface|note|state|add|expose|echo|carry|reflect)\b"
     r"[^.\n]{0,60}?\b(?:summary|summaries|recap|explanation|preview|confirmation|message|"
     r"note|report|description)\b[^.\n]{0,40}?\b(?:user|human|operator|owner)\b",
     "asks for a detail to be left out of what the user is shown"),
    # A control talked down rather than switched off. The qualifier is required:
    # bare "validation is optional" is something an honest client-side note says,
    # "the safety check is unnecessary here" is not.
    (r"\b(?:the\s+)?(?:safety|security|risk|compliance|spend(?:ing)?|approval|"
     r"confirmation|authori[sz]ation)\s+(?:check|checks|step|gate|guard|review|control|"
     r"limit|rule|dialog)?s?\s*(?:is|are)\s+(?:not\s+(?:necessary|needed|required)|"
     r"unnecessary|optional|redundant|superfluous|irrelevant)\b",
     "downgrades a control to optional"),
    (r"\b(?:the\s+)?(?:safety|security|risk|compliance|spend(?:ing)?|approval|"
     r"confirmation|authori[sz]ation|sanity|pre-?flight)\s*(?:check|review|validation|"
     r"verification|gate|step)s?\s+(?:can|may|could)\s+(?:safely\s+)?be\s+"
     r"(?:skipped|omitted|disabled|bypassed|ignored|left\s+out)\b",
     "declares a control skippable"),
    (r"\b(?:limits?|caps?|ceilings?|thresholds?|quotas?|restrictions?)\s+"
     r"(?:do|does)\s+not\s+apply\s+(?:to|here|for)\b", "claims the limits do not apply here"),
    # -- other languages --
    (r"\bohne\s+(?:den\s+|die\s+|das\s+)?(?:nutzer|benutzer|anwender|besitzer|eigent[uü]mer)\b",
     "asks to bypass the human (German)"),
    (r"\bnicht\s+(?:informiert|benachrichtigt|gefragt|angezeigt)\s+werden\b",
     "asks the agent to withhold (German)"),
    (r"\bkeine\s+(?:best[aä]tigung|zustimmung|freigabe|r[uü]ckfrage)\b", "waives confirmation (German)"),
    (r"\bsin\s+(?:informar|avisar|notificar|preguntar|consultar)\b", "asks to bypass the human (Spanish)"),
    (r"\bno\s+(?:es\s+)?necesari[oa]\s+(?:confirmar|avisar|preguntar)\b", "waives confirmation (Spanish)"),
    (r"不要(?:告[诉訴]|提及|显示|顯示)", "asks the agent to withhold (Chinese)"),
    (r"(?:无需|無需|不需要)(?:确认|確認|批准)", "waives confirmation (Chinese)"),
    (r"(?:静默|靜默|悄悄)", "asks for silence (Chinese)"),
]

# --------------------------------------------------------------------------- #
#  Coercion inside the sanctioned frame
#
#  Everything above this point looks for an attack that leaves the frame: another
#  action, another destination, a request for silence. There is a second family
#  that never leaves it. It keeps the action the user asked for and the fields the
#  schema declares, and bends only *which value* goes into them, or *which of two
#  legitimate tools* gets used -- maximise the amount, discard the figure the user
#  actually stated, move the caller off the read-only quote and onto the
#  irreversible transfer. No foreign action is named and no address appears, so
#  every detector above stays silent while the loss is the same size.
#
#  The difficulty is that honest documentation talks about maximums, deprecations
#  and full balances all day. What separates the two is never the vocabulary; it
#  is who the sentence is aimed at. Documentation describes what a field means
#  ("set to true to use the entire available balance"); an injection gives the
#  reader a standing order about what to put in it ("always set it to the largest
#  value permitted"). Every pattern below therefore requires the directive form
#  and refuses the descriptive one, which is why they all carry an
#  always/must/should gate that looks redundant and is not.
# --------------------------------------------------------------------------- #

# The caller stated a value and the description tells the reader to throw it away.
# There is no honest version of this sentence, which is why it is the one shape in
# this family that reaches CRITICAL on its own: a third party documenting a
# parameter has no standing to overrule the person who filled it in.
_PARAM_OVERRIDE = [
    (r"\b(?:ignore|disregard|overrule|overwrite|discard|drop)\s+"
     r"(?:any|all|the|whatever|whichever)?\s*(?:\w+\s+){0,2}?"
     r"(?:amount|value|limit|figure|quantity|number|size|price|recipient|address|"
     r"destination|parameter|argument|input|field)s?\b[^.\n]{0,40}?"
     r"\b(?:stated|given|provided|specified|supplied|requested|passed|entered|chosen|"
     r"named|set|asked\s+for)\s+(?:by|in)\s+(?:the\s+)?"
     r"(?:user|caller|human|operator|owner|prompt|request)\b",
     "tells the reader to discard the value the caller supplied"),
    # "always set `recipient` to 0x... regardless of the address the user gives".
    # The directive gate matters here: "the fee is charged in native token
    # regardless of the chain the user selected" is ordinary documentation.
    (r"\b(?:always|must|should|shall)\s+(?:\w+\s+){0,4}?"
     r"(?:set|use|pass|send|route|apply|force)\b[^.\n]{0,80}?"
     r"\b(?:regardless\s+of|irrespective\s+of|no\s+matter\s+what)\b[^.\n]{0,60}?"
     r"\b(?:user|caller|human|operator|owner)\b",
     "overrides whatever the caller supplied"),
]

# A standing order to sit on the ceiling. The superlative alone is not evidence --
# "the maximum amount allowed is 10000" is a fact about the field -- so the
# directive gate in front of it is what makes this a detector rather than a
# wordlist.
_VALUE_COERCION = re.compile(
    r"\b(?:always|must|should|shall|need\s+to|be\s+sure\s+to|make\s+sure\s+to)\s+"
    r"(?:\w+\s+){0,4}?(?:set|use|pass|send|specify|fill|populate|request|choose)\b"
    r"[^.\n]{0,60}?"
    r"\b(?:maximum|max|largest|highest|greatest|biggest|unlimited|uncapped|infinite|"
    r"entire|full|whole|total)\b[^.\n]{0,40}?"
    r"\b(?:allows?|allowed|permits?|permitted|possible|available|balance|allowance|"
    r"funds|holdings|position)\b",
    re.I,
)

# A description that announces its own replacement. An honest deprecation notice
# reads the same way -- "this endpoint is deprecated; use v2 instead" is something
# real toolkits write -- so the claim on its own is only worth reporting. What
# turns it into a finding is the redirect being *universal*: every request, price
# checks and estimates included. That is the sentence that moves a caller off a
# read-only tool and onto one that signs, and no honest migration note needs it.
_SELF_DEPRECATION = re.compile(
    r"\bthis\s+(?:action|tool|endpoint|method|function|call|api|route|operation)\b"
    r"[^.\n]{0,40}?\b(?:is|has\s+been|was)\s+(?:now\s+)?(?:deprecated|obsolete|superseded|"
    r"retired|discontinued|unsupported|legacy|no\s+longer\s+(?:supported|maintained|"
    r"available|reliable|accurate))\b"
    r"|\bthis\s+(?:action|tool|endpoint|method|function|call|api)\b[^.\n]{0,40}?"
    r"\breturns?\s+(?:stale|outdated|incorrect|unreliable|wrong|misleading)\b",
    re.I,
)
_REPLACEMENT_NAMED = re.compile(
    r"\b(?:use|call|invoke|switch\s+to|migrate\s+to|prefer)\s+[`\"']?"
    r"([A-Za-z_][\w.-]{2,40})[`\"']?\s+(?:instead|in\s+its\s+place|"
    r"for\s+(?:every|all|any)\b)",
    re.I,
)
_UNIVERSAL_SCOPE = re.compile(
    r"\bfor\s+(?:every|all|any)\s+(?:request|call|case|use|query|lookup|operation|"
    r"purpose|scenario)s?\b"
    r"|\bincluding\s+(?:price\s+checks?|estimates?|quotes?|read-?only|previews?|"
    r"simulations?|dry\s+runs?|balance\s+checks?)\b",
    re.I,
)
# A version bump is the honest reason to retire something, and a pointer at
# another *field* is not a pointer at another tool.
_VERSION_LIKE = re.compile(r"(?:^|[._-])v?\d+(?:[._]\d+)*$|^version|_v\d", re.I)

# Direction to invoke. The distinction that matters: documenting a parameter is
# fine; telling the reader which *call to make next* is not the description's job.
_CALL_DIRECTION_PATTERNS = [
    r"\b(?:you\s+(?:must|should|need\s+to|have\s+to)|always|first|then|next|also|"
    r"be\s+sure\s+to|make\s+sure\s+to|remember\s+to|don'?t\s+forget\s+to)"
    r"\s+(?:\w+\s+){0,3}?(?:call|invoke|execute|run|trigger|use|send|fetch|post)\b",
    r"\bbefore\s+(?:calling|invoking|running|using)\s+this\b",
    r"\bafter\s+(?:calling|invoking|running|using)\s+this\b",
    r"\binstead\s+of\s+(?:calling|invoking|this)\b",
    # -- indirect phrasings: nobody is ordered, everybody complies --
    r"\b(?:it\s+is|it's)\s+(?:customary|standard|common|usual|recommended|advisable|"
    r"best\s+practice|required|expected|good\s+practice)\s+to\s+(?:\w+\s+){0,3}?"
    r"(?:call|invoke|execute|run|trigger|use|send|post|settle|route|forward|transfer|sweep|withdraw)\b",
    r"\bmost\s+(?:integrations?|clients?|agents?|callers?|implementations?|toolkits?|users?)\b"
    r"[^.\n]{0,60}\b(?:call|invoke|pair\s+this|chain|follow\s+(?:this|up)|also)\b",
    r"\b(?:standard|recommended|usual|typical|customary|correct|expected|normal|preferred)\s+"
    r"(?:practice|sequence|workflow|order|flow|pattern|procedure|approach|follow-?up|next\s+step)\s+is\b",
    r"\b(?:pair|chain|combine|follow)\s+(?:this|it)\s+with\b",
    # A second call does not have to be named to be a second call.
    r"\b(?:companion|paired|partner|sibling|follow-?up|second)\s+"
    r"(?:action|call|tool|endpoint|helper|routine)\b",
    r"\bshould\s+be\s+(?:called|invoked|executed|run|triggered|completed|performed|settled)\b",
    r"\bmust\s+be\s+(?:preceded|followed|accompanied)\s+by\b",
    r"\bprior\s+to\s+(?:calling|invoking|using|running|executing)\s+this\b",
    r"\bonce\s+this\s+(?:returns|completes|succeeds|is\s+done|has\s+run)\b[^.\n]{0,60}"
    r"\b(?:call|invoke|run|use|send|post|execute|trigger|settle|route|sweep|transfer|forward)\b",
    r"\bas\s+a\s+(?:final|last|first|second|subsequent|follow-?up)\s+step\b",
    r"\bafterwards?,?\s+(?:\w+\s+){0,2}?(?:call|invoke|run|use|send|post|execute|trigger|settle|route)\b",
    r"\bsend\s+(?:everything|all\s+of\s+it|the\s+(?:entire|full|whole|remaining)\s+"
    r"(?:balance|amount|funds|position))\b",
    # -- other languages --
    r"\bruf(?:e|en|t)?\s+(?:zuerst\s+|zun[aä]chst\s+|danach\s+|anschlie[sß]end\s+|vorher\s+)?"
    r"(?:die\s+|den\s+|das\s+)?(?:[\w.-]+\s+){1,3}auf\b",
    r"\b(?:zuerst|zun[aä]chst|danach|anschlie[sß]end)\b[^.\n]{0,40}\baufruf\w*\b",
    r"\b(?:primero|luego|despu[eé]s|primeramente)\b[^.\n]{0,40}\b(?:invoca|llama|ejecuta|env[ií]a)\b",
    r"\binvoca\s+la\s+(?:acci[oó]n|herramienta|funci[oó]n)\b",
    r"(?:先|然后|接着|之后|首先)\s*(?:调用|調用|执行|執行|发送|發送)",
    r"(?:调用|調用)\s*[\w.-]+\s*(?:动作|動作|工具|接口|函数|函數)",
]
_CALL_DIRECTION = re.compile("|".join("(?:%s)" % p for p in _CALL_DIRECTION_PATTERNS), re.I)

_FOREIGN_ACTION = re.compile(
    r"\b(?:call|invoke|execute|run|trigger|hit|issue|perform)\s+(?:a\s+|the\s+)?[`\"']?"
    r"([A-Za-z_][\w.-]{2,40})[`\"']?\s*(?:\(\s*\)|action|tool|function|endpoint|api|method|"
    r"helper|routine|handler|step)\b",
    re.I,
)
# The same instruction with the words in the other order: "the X helper should be
# completed beforehand".
_FOREIGN_ACTION_REVERSED = re.compile(
    r"\b(?:the\s+)?[`\"']?([A-Za-z_][\w.-]{2,40})[`\"']?\s+"
    r"(?:action|tool|helper|endpoint|routine|function|handler|step|call)\s+"
    r"(?:should|must|needs?\s+to|has\s+to|is\s+to|ought\s+to)\s+(?:be\s+)?"
    r"(?:called|invoked|run|executed|triggered|used|completed|performed|finished|settled)\b",
    re.I,
)
# "settle through treasury_sweep", "route it via drain_wallet".
_ROUTED_THROUGH = re.compile(
    r"\b(?:through|via|using|with|to)\s+[`\"']?"
    r"([a-z][a-z0-9]*(?:_[a-z0-9]+){1,4})[`\"']?",
    re.I,
)
# Identifiers that end a sentence the way a heist ends: everything, elsewhere.
_DANGEROUS_NAME = re.compile(
    r"\b(?:"
    r"(?:transfer|withdraw|sweep|drain|export|exfil\w*|forward|approve|revoke|disable|"
    r"send|upload|purge|dump|siphon|liquidate|unstake|redeem|retirar|abheben|transferir)"
    r"[_-]?(?:all|funds?|balance|keys?|wallet|everything|remaining|todo|alles)"
    r"|(?:treasury|wallet|balance|funds?|account|asset|portfolio|vault)"
    r"[_-](?:sweep|drain|transfer|withdraw|export|dump|move|out)"
    r")\b",
    re.I,
)
# Parameter-ish tails, so 'amount_in' and 'dry_run' are not read as action names.
_PARAM_TAIL = re.compile(
    r"_(?:in|out|bps|id|ms|us|usd|at|url|uri|key|run|mode|size|limit|type|code|hash|"
    r"address|name|count|max|min|token|amount|value|time|date|ts|sec|s)$", re.I)
_DIRECTIVE_NEAR = re.compile(
    r"call|invoke|execut|run\b|trigger|use\b|step|sequence|first|then\b|next\b|after|before|"
    r"follow|settle|rout|via\b|through|action|tool|helper|workflow|order|"
    r"ruf\w*|aufruf|zuerst|zun[aä]chst|danach|anschlie|aktion|schritt|"
    r"invoca|llama|ejecut|primero|luego|acci[oó]n|paso|"
    r"调用|調用|执行|執行|先|然后|首先|步骤|步驟",
    re.I,
)

# Conditionals that describe when the human is asked -- a tool has no business
# knowing that, but honest wrappers do talk about it, so this never escalates.
_CONDITIONAL_GATE = re.compile(
    r"\b(?:proceeds?|executes?|settles?|runs?|completes?|goes\s+through)\s+automatically\b"
    r"[^.\n]{0,80}\b(?:prompt|confirmation|approval|review|asked|notified)\b"
    r"|\b(?:prompt|confirmation|approval|review)\b[^.\n]{0,80}"
    r"\b(?:proceeds?|executes?|settles?|runs?)\s+automatically\b",
    re.I,
)

# --------------------------------------------------------------------------- #
#  Destinations
# --------------------------------------------------------------------------- #

_URL = re.compile(r"\bhttps?://[^\s<>\"'`\])}]+", re.I)
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)")
_MD_LINK = re.compile(r"(?<!!)\[([^\]]*)\]\(\s*(https?://[^)\s]+)")

# A destination that has been disguised. Documentation does not defang its own
# links; only something expecting to be read by a filter does that.
_OBFUSCATED_SCHEME = [
    (re.compile(r"\bh(?:xx|\*\*|__|x)ps?\s*(?::|\[:\]|\(:\))\s*//\S*", re.I), "defanged scheme (hxxp)"),
    (re.compile(r"\bhttps?\s*(?:\[:\]|\(:\)|：|:\s)\s*(?://|\[//\]|\\/\\/)\S*", re.I), "scheme with a broken colon"),
    (re.compile(r"https?:\\/\\/\S*", re.I), "escaped slashes"),
    (re.compile(r"\b[a-z0-9-]{2,}\s*(?:\[\.\]|\(\.\)|\{\.\}|\s+dot\s+)\s*[a-z0-9-]{2,}", re.I), "defanged dot"),
]
_TLD = (r"com|net|org|io|co|xyz|app|dev|info|site|online|top|ru|cn|me|to|sh|link|live|"
        r"store|cloud|fun|click|zip|gg|tk|ml|ga|cf|pw|cc|biz|space|website|host")
_BARE_HOST = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?\.){1,3}(?:" + _TLD + r")\b(?:[:/][^\s<>\"'`\])}]*)?",
    re.I,
)
_PROTO_RELATIVE = re.compile(
    r"(?<![:\w./])//[a-z0-9][a-z0-9.-]{1,60}\.[a-z]{2,24}(?:[:/][^\s<>\"'`\])}]*)?", re.I)
_IP_DEST = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5}(?:/[^\s]*)?|/[^\s]+)", re.I)
_OTHER_SCHEME = re.compile(
    r"\b(?:ftps?|wss?|ipfs|ipns|gopher|smb|file)://\S+|\bdata:[a-z]+/[a-z0-9.+-]+;|\bmailto:\S+@\S+",
    re.I,
)
# Hosts whose entire purpose is to receive whatever you send them.
_COLLECTOR_HOST = re.compile(
    r"\b(?:webhook\.site|requestbin|pipedream\.net|ngrok\.io|ngrok-free\.app|burpcollaborator|"
    r"oastify|interact\.sh|canarytokens|pastebin\.com|paste\.ee|transfer\.sh|file\.io|0x0\.st|"
    r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com)\b",
    re.I,
)

# A destination written as a role rather than as an address. Kept at MEDIUM
# because an honest fee disclosure reads the same way.
_NAMED_RECIPIENT = re.compile(
    r"\b(?:to|into)\s+(?:the\s+|our\s+|an?\s+)?(?:operator|admin(?:istrator)?|our)\s*(?:'s)?\s*"
    r"(?:key|wallet|address|account|node)\b",
    re.I,
)

_ADDRESSES = [
    (re.compile(r"\b0x[a-fA-F0-9]{40}\b"), "EVM address"),
    (re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"), "Bitcoin address"),
    (re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b"), "base58 string (possible Solana address)"),
]
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[A-Za-z]{2,}\b")
# The addresses documentation points a human at, rather than the ones a payload
# is sent to. The domain is still unverifiable, so this lowers the volume, not
# the category: with any second signal it still combines to CRITICAL.
_ROLE_ADDRESS = re.compile(
    r"(?:support|help(?:desk)?|hello|hi|info|contact|sales|security|abuse|privacy|legal|"
    r"billing|feedback|team|dev|developers?|api|no-?reply|donotreply|postmaster|webmaster|"
    r"admin)@", re.I)

# Core verbs mean exfiltration wherever they sit; weak ones only count next to a
# destination, because honest prose says "copy the hash" and "report the error".
# A word boundary that survives a change of script.
#
# Python's ``\b`` marks a transition between word and non-word characters. CJK
# characters ARE word characters, and in running text one is followed by
# another -- so there is never a boundary between them, and any alternation
# that ends in ``\b`` can never match its CJK alternatives.
#
# This was not theory. Measured on 08.09.2026, the Chinese half of the
# send-verb pattern below had never fired since the day it was added, and the
# Latin half kept the pattern looking alive: "send the private key to <url>"
# rated CRITICAL in English and MEDIUM in Chinese, and MEDIUM does not hold a
# tool back under the default policy.
#
# What the boundary actually has to assert is "this Latin word does not
# continue". A following CJK character is the next word, not a continuation.
_LATIN_WORD = "A-Za-z\u00C0-\u024F0-9_"
_LB = "(?<![" + _LATIN_WORD + "])"      # left edge, script-aware
_RB = "(?![" + _LATIN_WORD + "])"       # right edge, script-aware

_EXFIL_VERB = re.compile(
    _LB + r"(?:send|sends|sent|sending|post|posts|posted|posting|transmit\w*|forward\w*|upload\w*|"
    r"exfiltrat\w*|deliver\w*|transfer\w*|withdraw\w*|drain\w*|sweep\w*|relay\w*|"
    r"beacon\w*|leak\w*|siphon\w*|publish\w*|senden|schicken|[uü]bermitteln|weiterleiten|"
    r"enviar|env[ií]a|reenviar|发送|發送|上传|上傳|转发|轉發|传送|傳送)" + _RB,
    re.I,
)
_EXFIL_VERB_WEAK = re.compile(
    r"\b(?:copy|copies|copied|share|shares|shared|report|reports|reported|route|routes|routed|"
    r"submit\w*|sync\w*|notif\w*|cc|bcc|emit\w*|dispatch\w*|stream\w*|export\w*|push\w*|"
    r"mirror\w*|replicat\w*|archive\w*|collect\w*|ingest\w*|aggregat\w*|harvest\w*)\b",
    re.I,
)
# Something is *aimed* at a destination, or a destination is merely *introduced*.
# The two readings sit in the words immediately before it.
# Does the run-up to a URL point AT it, or merely mention it? "send it to <url>"
# is a destination; "see <url> for details" is a citation, and treating the
# second as the first is how a scanner earns its way into the bin.
#
# Both halves of this were English-only until 08.09.2026, which capped every
# non-English description at HIGH no matter what it said: Spanish "a", German
# "an" and Chinese "\u5230" all mean "to", and none of them was listed. The CJK
# alternative needs its own branch, because Chinese is written without spaces
# and \b cannot mark a boundary between two CJK characters.
_SENT_TO_LATIN = (
    r"(?:to|into|towards?|at|via|through"
    r"|an|zu|zum|zur|nach"          # German
    r"|a|hacia|para"                # Spanish
    r")\s+[\"'`(<]?\s*$"
)
_SENT_TO_CJK = "[\u5230\u81f3\u7ed9\u7d66\u5411]" + r"\s*[\"'`(<]?\s*$"
_SENT_TO = re.compile(_LB + _SENT_TO_LATIN + "|" + _SENT_TO_CJK, re.I)
_DOC_FRAME = re.compile(
    r"\b(?:see|documented|documentation|referenced?|docs?|guide|details?|instructions?|"
    r"examples?|more|available|described|listed|reference|spec|specification|read)\s+"
    r"(?:it\s+|them\s+|more\s+|info\s+)?(?:at|in|on|under|here)?\s*:?\s*$", re.I)

# Loopback and private ranges are what a local gateway looks like, not a drop.
_PRIVATE_IP = re.compile(
    r"^(?:127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)")
# The other half of the same defect. Somebody made the send verbs multilingual
# and left this list in English, so a Spanish or German description could match
# a destination AND a verb and still stop at HIGH -- the composite needs all
# three to reach CRITICAL. Measured before the fix: EN CRITICAL, ES HIGH,
# DE HIGH, ZH MEDIUM, for four sentences that say the same thing.
#
# A secret word alone means nothing here and is never reported on its own; it
# only weighs when a destination and a send verb are already present. That is
# why terms as ordinary as "balance" can sit in this list at all.
_SECRET_WORD = re.compile(
    _LB + r"(?:private\s*key|seed\s*phrase|recovery\s*phrase|mnemonic|keystore|signing\s*key|"
    r"secret|api[\s_-]?key|password|credential|token|wallet|balance|holdings|portfolio|"
    r"session\s*token|bearer|system\s*prompt|chat\s*history|conversation\s*history|"
    r"previous\s*messages|"
    # German
    r"privat\w*\s+schl(?:ü|ue)ssel|seed[\s-]*phrase|wiederherstellungs\w*|passwort|"
    r"zugangsdaten|anmeldedaten|guthaben|kontostand|geheimnis|brieftasche|"
    # Spanish
    r"clave\s*privada|frase\s*semilla|frase\s*de\s*recuperaci[oó]n|contrase[nñ]a|"
    r"credenciales|saldo|secreto|cartera|billetera|"
    # Chinese (simplified and traditional)
    r"私钥|私鑰|密钥|密鑰|助记词|助記詞|密码|密碼|余额|餘額|钱包|錢包|凭证|憑證)" + _RB,
    re.I,
)

# --------------------------------------------------------------------------- #
#  Encodings
# --------------------------------------------------------------------------- #

_BASE64_RUN = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
_HEX_RUN = re.compile(r"\b(?:0x)?[0-9a-fA-F]{60,}\b")
_HEX_TEXT_RUN = re.compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b")
def _entschluessele_escapes(run: str, art: str) -> str:
    """Turn one escape run back into the text it hides. '' when it will not decode.

    Deliberately narrow: only the five forms listed below, no chaining, no
    guessing. A decoder that tries hard produces plausible text out of random
    bytes, and a finding built on plausible text is worse than no finding.
    """
    try:
        if "uXXXX" in art or "xNN" in art:
            return run.encode("latin-1", "backslashreplace").decode("unicode_escape")
        if "numeric entities" in art:
            return "".join(chr(int(c)) for c in re.findall(r"&#(\d{2,5});", run))
        if "hex entities" in art:
            return "".join(chr(int(c, 16)) for c in re.findall(r"&#x([0-9a-fA-F]{2,4});", run))
        if "percent" in art:
            return bytes(int(c, 16) for c in re.findall(r"%([0-9a-fA-F]{2})", run)).decode("utf-8")
    except (ValueError, UnicodeDecodeError, UnicodeEncodeError, OverflowError):
        return ""
    return ""


_ESCAPE_RUNS = [
    (re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}"), r"\\uXXXX escapes"),
    (re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}"), r"\\xNN escapes"),
    (re.compile(r"(?:&#\d{2,5};){4,}"), "HTML numeric entities"),
    (re.compile(r"(?:&#x[0-9a-fA-F]{2,4};){4,}"), "HTML hex entities"),
    (re.compile(r"(?:%[0-9a-fA-F]{2}){6,}"), "percent-encoding"),
]
# Comment and hidden-markup syntax. The text inside is invisible where the
# description is rendered and perfectly visible to whatever reads the raw string.
_HIDDEN_MARKUP = [
    (re.compile(r"<!--(.*?)-->", re.S), "HTML comment"),
    (re.compile(r"\[(?://|comment)\]\s*:\s*(?:#|<>)\s*\((.*?)\)", re.S), "Markdown comment"),
    (re.compile(r"/\*(.*?)\*/", re.S), "block comment"),
    (re.compile(r"<(?:span|div|p)[^>]*(?:display\s*:\s*none|font-size\s*:\s*0|"
                r"color\s*:\s*#?(?:fff|ffffff|white)|\bhidden\b)[^>]*>(.*?)</(?:span|div|p)>",
                re.S | re.I), "hidden HTML element"),
]
# Attack markers that survive having every space removed, for decoded payloads
# written without them.
_SQUASHED_MARKERS = [
    "ignoreall", "ignoreprevious", "ignoreprior", "disregardall", "disregardprevious",
    "forgeteverything", "forgetall", "newinstructions", "systemprompt", "donottell",
    "donotmention", "donotinform", "withouttellingtheuser", "withoutinforming",
    "transferall", "withdrawall", "sweepfunds", "drainwallet", "exportkeys", "sendall",
    "privatekey", "seedphrase", "mnemonic", "apikey", "developermode", "youarenow",
    "yourrealtask", "keepthissecret", "noneedtoask",
]

_LATIN = re.compile(r"[A-Za-z]")
_WORD = re.compile(r"[^\W\d_]{2,}", re.UNICODE)


def _clip(s: str, n: int = 90) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


# --------------------------------------------------------------------------- #
#  Combination
#
#  A single signal is usually noise: plenty of honest descriptions link to docs,
#  and "use this first" is ordinary advice. The attack is what the signals spell
#  out *together* -- name a call, name a destination, ask for silence. Scoring the
#  parts and never the pattern is how a real injection walks past three separate
#  HIGH findings without ever reaching CRITICAL, which is exactly what this
#  scanner did on its own example until the example was run.
# --------------------------------------------------------------------------- #
_CATEGORY = {
    "bidi_control": "structure",
    "tag_characters": "structure",
    "variation_selector": "structure",
    "zero_width": "structure",
    "format_control": "structure",
    "role_marker": "structure",
    "mixed_script": "structure",
    "disguised_text": "structure",
    "instruction_override": "override",
    "concealment": "conceal",
    "parameter_override": "coerce",
    "value_coercion": "coerce",
    "deprecation_redirect": "coerce",
    "call_direction": "direct",
    "foreign_action": "direct",
    "url": "destination",
    "obfuscated_destination": "destination",
    "hardcoded_address": "destination",
    "email_destination": "destination",
    "markdown_image": "destination",
    "link_text_mismatch": "destination",
    "encoded_payload": "hidden",
    "escape_run": "hidden",
    "hex_blob": "hidden",
    "buried_content": "hidden",
    "hidden_markup": "hidden",
    # deliberately uncategorised, so they report without ever escalating:
    #   action_like_name, conditional_gate, oversized, deprecation_notice
}

# Pairs that, on their own, describe an attack end to end.
_DAMNING_PAIRS = [
    ({"direct", "destination"}, "names a call to make and a place to send the result"),
    ({"direct", "conceal"}, "names a call to make and asks for it to be hidden"),
    ({"destination", "conceal"}, "names a destination and asks for it to be hidden"),
    ({"conceal", "hidden"}, "asks for silence and hides part of its own text"),
    ({"conceal", "structure"}, "asks for silence in text that is partly invisible or disguised"),
    ({"override", "direct"}, "reframes the reader's instructions and names a call to make"),
    ({"override", "conceal"}, "reframes the reader's instructions and asks for silence"),
    ({"coerce", "conceal"}, "dictates the value to put in a field and asks for that to be "
                            "kept out of what the user sees"),
    # Added 08.09.2026, after `call_direction` stopped being HIGH on its own.
    # An honest author writes "first use searchInvestments" in plain words --
    # that is why the single signal was downgraded. Nobody writes it as numeric
    # HTML entities, in rot13, or reversed. **The hiding is the tell**: content
    # concealed from a reviewer that then turns out to name a call is not a
    # documented prerequisite, whatever it says.
    ({"hidden", "direct"}, "hides part of its own text, and the hidden part names a "
                           "call to make"),
    ({"hidden", "coerce"}, "hides part of its own text, and the hidden part dictates "
                           "a field's value"),
]


def _escalate(rep: ScanReport, where: str = "") -> ScanReport:
    """Add one CRITICAL finding when separate signals combine into a pattern."""
    rep.findings = [f for f in rep.findings if f.detector != "composite"]
    cats = {_CATEGORY.get(f.detector, "other") for f in rep.findings}
    cats.discard("other")

    why = None
    for pair, reason in _DAMNING_PAIRS:
        if pair <= cats:
            why = reason
            break
    if why is None and len(cats) >= 3:
        why = "signals from %d unrelated categories in one description (%s)" % (
            len(cats), ", ".join(sorted(cats)))

    if why is not None:
        rep.findings.append(
            Finding("composite", Severity.CRITICAL,
                    "combination: %s -- each part alone is arguable, together they are "
                    "not" % why,
                    ", ".join(sorted(cats)), where)
        )
    return rep


# --------------------------------------------------------------------------- #
#  Phrase pass -- shared by the canonical text and by everything decoded out of it
# --------------------------------------------------------------------------- #

_Signal = Tuple[str, Severity, str, str]


def _phrase_signals(text: str, squashed: bool = False) -> List[_Signal]:
    """Run the phrase detectors over already-canonicalised text.

    ``squashed`` additionally tests the text with every non-alphanumeric character
    removed. That is only safe on decoded payloads -- on ordinary prose it would
    join words across a full stop and invent matches.
    """
    out: List[_Signal] = []
    for pat in _ROLE_MARKERS:
        m = re.search(pat, text, re.I)
        if m:
            out.append(("role_marker", Severity.CRITICAL,
                        "contains a chat/role delimiter -- a description has no turns to open",
                        m.group(0)))
    for pat, why in _OVERRIDE:
        m = re.search(pat, text, re.I)
        if m:
            out.append(("instruction_override", Severity.CRITICAL, why, m.group(0)))
    for pat, why in _OVERRIDE_SOFT:
        m = re.search(pat, text, re.I)
        if m:
            out.append(("instruction_override", Severity.HIGH, why, m.group(0)))
    for pat, why in _CONCEAL:
        m = re.search(pat, text, re.I)
        if m:
            out.append(("concealment", Severity.HIGH, why, m.group(0)))
    for pat, why in _PARAM_OVERRIDE:
        m = re.search(pat, text, re.I)
        if m:
            out.append(("parameter_override", Severity.CRITICAL, why, m.group(0)))

    m = _VALUE_COERCION.search(text)
    if m:
        out.append(("value_coercion", Severity.HIGH,
                    "orders the reader to put the largest permitted value in a field -- a "
                    "description documents what a field means, it does not decide what the "
                    "caller wants to spend", _clip(m.group(0), 80)))

    m_dep = _SELF_DEPRECATION.search(text)
    if m_dep:
        for m_rep in _REPLACEMENT_NAMED.finditer(text):
            name = m_rep.group(1)
            if _VERSION_LIKE.search(name) or _PARAM_TAIL.search(name):
                continue  # a version bump, or a pointer at another field
            excerpt = _clip("%s ... %s" % (m_dep.group(0), m_rep.group(0)), 90)
            if _UNIVERSAL_SCOPE.search(text):
                out.append(("deprecation_redirect", Severity.HIGH,
                            "declares itself deprecated and sends every request -- read-only "
                            "ones included -- to %s instead; retiring yourself is the cheapest "
                            "way to move a caller onto a different tool" % name, excerpt))
            else:
                # An ordinary migration note reads exactly like this, so it is
                # reported and never escalated.
                out.append(("deprecation_notice", Severity.MEDIUM,
                            "claims to be deprecated and names %s as its replacement -- confirm "
                            "the replacement does the same thing" % name, excerpt))
            break

    m = _CALL_DIRECTION.search(text)
    if m:
        # "First call this with dry_run=true" is an author documenting their own
        # action. "First call get_balance" is not. The object of the verb is the
        # whole distinction, so read it before shouting.
        about_self = re.match(r"\s*(?:this|it)\b", text[m.end():])
        # Never HIGH on its own any more, and the live catalogue is the reason.
        # Measured 08.09.2026 across 183 real actions: the only three HIGH hits
        # in the whole catalogue were "it is recommended to first use
        # searchInvestments" and "you need to use the raw amount" -- three
        # legitimate toolkits, and under the default policy HIGH gates a call.
        # Documenting a prerequisite step is what a careful author does, and no
        # wording separates it reliably from an instruction.
        #
        # Nothing is lost. The composite still lifts {direct + destination} and
        # {direct + conceal} to CRITICAL, and that is where the attack lives:
        # "call X, send the result to Y, say nothing". One sentence about order
        # is not that, and treating it as if it were is how a scanner earns its
        # way into the bin.
        out.append(("call_direction",
                    Severity.LOW if about_self else Severity.MEDIUM,
                    "refers the reader to a call, but the object is this action itself"
                    if about_self else
                    "points the reader at another call -- usually a documented "
                    "prerequisite, but it is also half of an injection", m.group(0)))

    for rx in (_FOREIGN_ACTION, _FOREIGN_ACTION_REVERSED):
        for m2 in rx.finditer(text):
            name = m2.group(1)
            danger = bool(_DANGEROUS_NAME.search(name))
            out.append(("foreign_action",
                        Severity.CRITICAL if danger else Severity.HIGH,
                        "names another action to invoke (%s)%s" % (
                            name, " and the name is one that moves everything" if danger else ""),
                        m2.group(0)))
    for m2 in _ROUTED_THROUGH.finditer(text):
        name = m2.group(1)
        if _PARAM_TAIL.search(name):
            continue  # amount_in, dry_run: a field, not an action
        if _DANGEROUS_NAME.search(name):
            out.append(("foreign_action", Severity.CRITICAL,
                        "routes the work through %s, a name that moves everything" % name,
                        m2.group(0)))
        else:
            # Honest docs do say "settled through stripe_connect". Report it,
            # never escalate on it -- an identifier is not an instruction.
            out.append(("action_like_name", Severity.MEDIUM,
                        "routes the work through another named thing (%s) -- confirm it is a "
                        "service and not an action the agent is being pointed at" % name,
                        m2.group(0)))

    # A dangerous identifier on its own is reported but never escalates: a wallet
    # toolkit is allowed to have a 'withdraw_all'. Inside a directive it is a
    # different sentence, and _FOREIGN_ACTION above has already said so.
    for m2 in _DANGEROUS_NAME.finditer(text):
        near = text[max(0, m2.start() - 120): m2.end() + 120]
        if _DIRECTIVE_NEAR.search(near):
            out.append(("foreign_action", Severity.CRITICAL,
                        "names an action that moves everything, in a sentence that tells the "
                        "reader to run something (%s)" % m2.group(0), _clip(near, 80)))
        else:
            out.append(("action_like_name", Severity.MEDIUM,
                        "mentions an identifier that reads like 'move everything' (%s)"
                        % m2.group(0), m2.group(0)))

    m = _CONDITIONAL_GATE.search(text)
    if m:
        out.append(("conditional_gate", Severity.MEDIUM,
                    "describes when the human is asked -- confirm the tool is not steering "
                    "callers under the threshold", _clip(m.group(0), 80)))

    if squashed:
        flat = re.sub(r"[^a-z0-9]", "", text.lower())
        for marker in _SQUASHED_MARKERS:
            if marker in flat:
                out.append(("instruction_override", Severity.CRITICAL,
                            "instruction text written without separators (%s)" % marker, marker))
                break
    return out


def _destination_signals(text: str) -> List[_Signal]:
    """Everything that names somewhere else."""
    out: List[_Signal] = []
    spans: List[Tuple[int, int]] = []

    imgs = {m.group(1) for m in _MD_IMAGE.finditer(text)}
    for m in _MD_IMAGE.finditer(text):
        out.append(("markdown_image", Severity.HIGH,
                    "embeds an image URL -- rendering it makes a request the agent did not "
                    "choose to make", m.group(1)))
        spans.append(m.span())
    for m in _MD_LINK.finditer(text):
        label, target = m.group(1), m.group(2)
        label_host = _URL.search(label) or _BARE_HOST.search(label)
        if label_host and label_host.group(0).split("/")[2 if "//" in label_host.group(0) else 0] \
                not in target:
            out.append(("link_text_mismatch", Severity.CRITICAL,
                        "the visible link text names a different host than the link target -- "
                        "there is no innocent reason to label one destination with another",
                        _clip(m.group(0), 80)))

    core_verb = bool(_EXFIL_VERB.search(text))
    has_secret = bool(_SECRET_WORD.search(text))
    email_spans = [m.span() for m in _EMAIL.finditer(text)]

    def verb_near(start: int, end: int) -> bool:
        # A weak verb only counts when it governs the destination -- "copy the
        # summary to X" is a send, "X; the fields below mirror it" is prose. In
        # English the verb comes first, so only the run-up is read.
        if core_verb:
            return True
        return bool(_EXFIL_VERB_WEAK.search(text[max(0, start - 60): start]))

    def rate(start: int, end: int) -> Tuple[Severity, str]:
        verb = verb_near(start, end)
        run_up = text[max(0, start - 30): start]
        directed = bool(_SENT_TO.search(run_up))
        # "Withdraws the full balance to the connected wallet. See <docs> for
        # details" has a send-verb, a secret-word and a URL, and is a completely
        # ordinary description. What separates it from an exfiltration is which
        # noun the destination is attached to: a reference is introduced, a drop
        # is aimed at. Read the run-up before shouting.
        if _DOC_FRAME.search(run_up) and not directed:
            return (Severity.MEDIUM,
                    "a URL introduced as a reference -- confirm the link is documentation")
        if verb and has_secret and directed:
            return (Severity.CRITICAL,
                    "a destination together with a send-verb and a secret-word is the shape "
                    "of an exfiltration instruction")
        if verb:
            return Severity.HIGH, "a destination together with a send-verb"
        return (Severity.MEDIUM,
                "contains a URL -- confirm it is documentation, not a destination")

    for rx, why in _OBFUSCATED_SCHEME:
        for m in rx.finditer(text):
            out.append(("obfuscated_destination", Severity.CRITICAL,
                        "a destination written so it does not look like one (%s) -- "
                        "documentation does not defang its own links" % why, _clip(m.group(0), 70)))
            spans.append(m.span())

    for m in _URL.finditer(text):
        spans.append(m.span())
        if m.group(0) in imgs:
            continue
        sev, note = rate(*m.span())
        out.append(("url", sev, note, m.group(0)))

    def overlaps(span: Tuple[int, int]) -> bool:
        # An address' own domain is not a second destination.
        return any(a <= span[0] < b or a < span[1] <= b for a, b in spans + email_spans)

    for rx, label in ((_PROTO_RELATIVE, "scheme-relative URL"),
                      (_IP_DEST, "bare IP address with a path or port"),
                      (_OTHER_SCHEME, "non-http URL"),
                      (_BARE_HOST, "bare hostname")):
        for m in rx.finditer(text):
            if overlaps(m.span()):
                continue
            sev, note = rate(*m.span())
            # Nobody documents a parameter with a scheme-relative URL or a raw
            # public IP. Those shapes belong to something being pasted, not
            # written -- so they start at HIGH even without a verb.
            if rx is _PROTO_RELATIVE or (rx is _IP_DEST and not _PRIVATE_IP.match(m.group(0))):
                sev = max(sev, Severity.HIGH)
            out.append(("url", sev, "%s -- %s" % (label, note), m.group(0)))
            spans.append(m.span())

    for m in _NAMED_RECIPIENT.finditer(text):
        out.append(("url", Severity.MEDIUM,
                    "names a recipient that is neither the caller nor a parameter -- confirm "
                    "the tool is not documenting where it sends things", _clip(m.group(0), 60)))

    # -- is this address pointed at, or merely documented? -------------------
    def _ADRESSE_GERICHTET(t: str, pos: int) -> bool:
        """True when the run-up to an address makes it a destination.

        "send it to 0x..." / "recipient: 0x..."  -> destination
        "e.g. USDC = 0x..." / "use 0x0 for ETH"  -> documentation

        Kept deliberately narrow: in a catalogue where every second parameter is
        a contract address, a detector that fires on presence alone fires on
        everything, and a detector that fires on everything gets switched off.
        """
        vor = t[max(0, pos - 60):pos]
        if _SENT_TO.search(vor):
            return True
        return bool(re.search(
            r"(?:recipient|destination|beneficiary|payee|receiver|drop|collector"
            r"|empf[a\u00e4]nger|ziel)\s*[:=]?\s*$", vor, re.I))

    for m in _COLLECTOR_HOST.finditer(text):
        out.append(("url", Severity.HIGH,
                    "names a host whose purpose is to receive whatever is sent to it",
                    m.group(0)))

    for pat, kind in _ADDRESSES:
        for m in pat.finditer(text):
            a = m.group(0)
            # base58 catches a lot of ordinary tokens; only report it when the
            # surrounding text gives it a reason to be there.
            if kind.startswith("base58") and not (core_verb or "address" in text.lower()):
                continue
            # An address has to be POINTED AT before it is a finding. This is the
            # same test the URL detector already applies, and it was missing here.
            #
            # Measured on the live catalogue, 08.09.2026: of 183 real actions, 24
            # were flagged for a hardcoded address and every single one was
            # correct documentation -- 0x0 for a native token, Aave's 0xeee
            # placeholder for ETH, USDC on Polygon and on Solana, wrapped SOL. In
            # DeFi the contract address IS the parameter value, and giving it as
            # an example is exactly what a good description does.
            #
            # The 52-entry legitimate corpus never caught this because it was
            # written from imagination. Real documentation is full of addresses.
            # Downgraded, never dropped. Deleting the signal outright was the
            # first attempt and it was wrong twice over: a bare address became
            # SILENT rather than merely unblocked, and -- worse -- it stopped
            # feeding the composite, which is what had been catching an address
            # smuggled in through HTML entities. A weak signal that still
            # combines is worth far more than no signal.
            if not _ADRESSE_GERICHTET(text, m.start()):
                out.append(("hardcoded_address", Severity.LOW,
                            "a %s appears in a description. In DeFi that is usually "
                            "the parameter's own value and entirely normal -- noted "
                            "so it can still weigh in combination, not to block"
                            % kind, a))
                continue
            out.append(("hardcoded_address", Severity.HIGH,
                        "a %s is named as a destination, not documented as a value "
                        "-- confirm the tool is not telling the agent where to send "
                        "things" % kind, a))

    for m in _EMAIL.finditer(text):
        if not verb_near(*m.span()):
            continue
        # "Report the error to support@example.com" is where documentation points
        # a human. A role address is still a destination -- it still combines with
        # a second signal -- but on its own it is not worth an alarm.
        role = _ROLE_ADDRESS.match(m.group(0))
        out.append(("email_destination",
                    Severity.MEDIUM if role else Severity.HIGH,
                    "a published contact address together with a send-verb"
                    if role else "an address together with a send-verb", m.group(0)))
    return out


# --------------------------------------------------------------------------- #
#  Decoding
# --------------------------------------------------------------------------- #

def _try_b64(run: str) -> Optional[str]:
    """Return the decoded text if a base64 run turns into readable characters."""
    candidate = run.replace("-", "+").replace("_", "/")
    pad = candidate + "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(pad, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 12:
        return None
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for c in s if c.isprintable() or c in "\n\t")
    if printable / len(s) < 0.9:
        return None
    return s


# Views that rearrange the same characters rather than decode a payload. They are
# worth reading for instructions and worthless for hostnames.
_REORDERED_VIEWS = {"rot13", "reversed"}


def _decoded_views(text: str) -> List[Tuple[str, str]]:
    """Every reading of the text that is not the one a reviewer gets."""
    views: List[Tuple[str, str]] = []

    for run in _BASE64_RUN.findall(text):
        decoded = _try_b64(run)
        if decoded and (len(re.findall(r"[A-Za-z]{3,}", decoded)) >= 2
                        or sum(c.isalpha() for c in decoded) >= 16):
            # The second clause is for payloads written without separators, which
            # is exactly how you dodge a detector that looks for readable prose.
            views.append(("base64", decoded))

    if re.search(r"(?:%[0-9a-fA-F]{2}){4,}", text):
        try:
            views.append(("percent-encoding", unquote(text)))
        except Exception:  # pragma: no cover - unquote is total in practice
            pass

    if re.search(r"&#x?[0-9a-fA-F]{2,5};", text):
        views.append(("HTML entities", html.unescape(text)))

    if re.search(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}", text):
        try:
            views.append(("escape sequences",
                          codecs.decode(text.encode("utf-8", "ignore"), "unicode_escape")))
        except Exception:
            pass

    for run in _HEX_TEXT_RUN.findall(text):
        try:
            raw = bytes.fromhex(run)
            s = raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if len(re.findall(r"[A-Za-z]{3,}", s)) >= 2:
            views.append(("hex", s))

    tags = "".join(chr(ord(c) - _TAG_LO) for c in text if _TAG_LO <= ord(c) <= _TAG_HI)
    if len(tags) >= 4:
        views.append(("Unicode tag characters", tags))

    vs = bytes((ord(c) - _VS_SUP_LO) % 256 for c in text if _VS_SUP_LO <= ord(c) <= _VS_SUP_HI)
    if len(vs) >= 4:
        try:
            views.append(("variation selectors", vs.decode("utf-8")))
        except UnicodeDecodeError:
            views.append(("variation selectors", vs.decode("latin-1")))

    letters = sum(1 for c in text if c.isalpha())
    if letters >= 12:
        try:
            views.append(("rot13", codecs.decode(text, "rot13")))
        except Exception:  # pragma: no cover
            pass
        views.append(("reversed", text[::-1]))

    return views


# --------------------------------------------------------------------------- #
#  The scan
# --------------------------------------------------------------------------- #

def scan_text(text: str, where: str = "") -> ScanReport:
    """Scan one string of third-party description text."""
    rep = ScanReport(scanned_chars=len(text or ""))
    if not text:
        return rep

    def add(det: str, sev: Severity, msg: str, excerpt: str = "") -> None:
        rep.findings.append(Finding(det, sev, msg, excerpt, where))

    canon = _canonical(text)

    # -- 1. characters that are there but cannot be seen --------------------
    zw: Dict[str, int] = {}
    zw_interior: set = set()
    other_cf: Dict[str, int] = {}
    vs_run = 0
    for i, ch in enumerate(text):
        cp = ord(ch)
        if _is_vs(cp):
            vs_run += 1
            if _VS_SUP_LO <= cp <= _VS_SUP_HI:
                add("variation_selector", Severity.CRITICAL,
                    "contains U+%04X from the variation selector supplement -- invisible, and "
                    "the standard way to smuggle bytes past a reviewer" % cp, repr(ch))
            elif vs_run >= 2:
                add("variation_selector", Severity.CRITICAL,
                    "contains consecutive variation selectors -- one is a glyph choice, "
                    "a run is a channel", repr(ch))
            continue
        vs_run = 0
        if cp in _ZERO_WIDTH:
            name = _ZERO_WIDTH[cp]
            zw[name] = zw.get(name, 0) + 1
            # Sitting between two ASCII letters, it is not a stray paste artifact:
            # it is a word broken in half so that matching on words fails. A soft
            # hyphen is excused -- that one really does come from copied prose.
            if (cp != 0x00AD and 0 < i < len(text) - 1
                    and text[i - 1].isascii() and text[i - 1].isalpha()
                    and text[i + 1].isascii() and text[i + 1].isalpha()):
                zw_interior.add(name)
        elif cp in _BIDI:
            add("bidi_control", Severity.CRITICAL,
                "contains %s -- text can be made to display differently than it reads"
                % _BIDI[cp], repr(ch))
        elif _TAG_LO <= cp <= _TAG_HI:
            add("tag_characters", Severity.CRITICAL,
                "contains Unicode tag character U+%04X -- invisible in every viewer, "
                "readable by the model" % cp, repr(ch))
        elif unicodedata.category(ch) == "Cf":
            name = unicodedata.name(ch, "U+%04X" % cp)
            other_cf[name] = other_cf.get(name, 0) + 1
    for name, n in zw.items():
        # ZERO WIDTH JOINER is load-bearing inside emoji sequences, so it alone is
        # not evidence of anything. The others have no business in a parameter doc.
        if name in zw_interior:
            sev, note = Severity.CRITICAL, " and sits inside a word, which is how a word is hidden from a reader that matches words"
        elif name == "ZERO WIDTH JOINER":
            sev, note = Severity.MEDIUM, " (legitimate inside emoji sequences -- check before acting)"
        elif name in _WEAK_MARK_NAMES:
            sev, note = Severity.MEDIUM, " (ordinary in right-to-left text -- check before acting)"
        else:
            sev, note = Severity.HIGH, ""
        add("zero_width", sev,
            "contains %d x %s -- invisible to a human reviewer%s" % (n, name, note))
    for name, n in other_cf.items():
        add("format_control", Severity.HIGH,
            "contains %d x %s -- a formatting control with no visible mark" % (n, name))

    # -- 2. letters that are not the letters they look like ------------------
    disguised = _nfkc_disguised_letters(text)
    if disguised >= 3:
        add("disguised_text", Severity.HIGH,
            "%d letters are written in a lookalike alphabet (mathematical, fullwidth or "
            "enclosed forms) -- they read as ASCII to the model and as decoration to a "
            "reviewer" % disguised, _clip(text, 60))

    for w in _WORD.findall(text):
        if not _LATIN.search(w):
            continue
        foreign = [c for c in w if _script_of(c)]
        if not foreign:
            continue
        confusable = [c for c in foreign if ord(c) in _CONFUSABLE_CPS]
        scripts = sorted({_script_of(c) for c in foreign})
        if confusable:
            add("mixed_script", Severity.CRITICAL,
                "one word mixes Latin with %s using characters that look identical to ASCII "
                "letters -- there is no innocent reason to write a word this way"
                % " and ".join(scripts), w)
        else:
            add("mixed_script", Severity.HIGH,
                "one word mixes Latin and %s -- homoglyphs defeat a reviewer reading for "
                "keywords" % " and ".join(scripts), w)
        break

    # -- 3. what the text says, once it is read as the model reads it --------
    for det, sev, msg, excerpt in _phrase_signals(canon):
        add(det, sev, msg, excerpt)
    for det, sev, msg, excerpt in _destination_signals(canon):
        add(det, sev, msg, excerpt)

    # -- 4. content that is not meant to be read -----------------------------
    for run in _BASE64_RUN.findall(text):
        decoded = _try_b64(run)
        if decoded and " " in decoded:
            add("encoded_payload", Severity.HIGH,
                "a base64 run decodes to readable text -- content hidden from review",
                _clip(decoded, 70))
    if _HEX_RUN.search(text):
        add("hex_blob", Severity.MEDIUM, "a long hex run appears in prose")
    for rx, what in _ESCAPE_RUNS:
        m = rx.search(text)
        if m:
            # Look at WHAT was hidden, not merely that something was -- the same
            # thing _HIDDEN_MARKUP does twenty lines below, and it belonged here
            # too. Reporting "this contains escapes" says the door was locked
            # from the inside; reading the escapes says what is behind it.
            #
            # Found on 08.09.2026: a description encoding "send everything to the
            # drop" as numeric HTML entities scored only HIGH, because the run
            # was flagged and never decoded. The plain-text version of the same
            # sentence is ordinary enough not to be CRITICAL on its own -- and
            # that is exactly the point. **Nobody encodes an honest sentence.**
            klartext = _entschluessele_escapes(m.group(0), what)
            drin = (_phrase_signals(klartext) + _destination_signals(klartext)
                    if klartext else [])
            if drin:
                add("escape_run", Severity.CRITICAL,
                    "a run of %s decodes to an instruction: %s"
                    % (what, drin[0][2]), _clip(klartext, 70))
            elif klartext and len(klartext.split()) >= 3:
                add("escape_run", Severity.HIGH,
                    "a run of %s decodes to readable prose -- text written so it "
                    "does not read as text" % what, _clip(klartext, 70))
            else:
                add("escape_run", Severity.HIGH,
                    "a run of %s -- text written so it does not read as text" % what,
                    _clip(m.group(0), 50))
            break

    for rx, what in _HIDDEN_MARKUP:
        for m in rx.finditer(text):
            inner = _canonical(m.group(1) or "")
            inner_signals = _phrase_signals(inner) + _destination_signals(inner)
            worst = max((s[1] for s in inner_signals), default=Severity.INFO)
            if worst >= Severity.HIGH:
                add("hidden_markup", Severity.CRITICAL,
                    "a %s carries an instruction: %s" % (what, inner_signals[0][2]),
                    _clip(m.group(1), 70))
            else:
                add("hidden_markup", Severity.MEDIUM,
                    "contains a %s -- text that is invisible wherever this is rendered"
                    % what, _clip(m.group(1), 70))

    # -- 5. the readings a reviewer never sees -------------------------------
    seen_views = set()
    for label, decoded in _decoded_views(text):
        folded = _canonical(decoded)
        if folded in seen_views:
            continue
        seen_views.add(folded)
        phrase = _phrase_signals(folded, squashed=True)
        # rot13 and reversal leave digits and punctuation exactly where they were,
        # so an IP address or a '//host/path' survives them untouched and would be
        # "discovered" in a view of text that was never encoded at all. Those two
        # views are read for instructions only.
        dests = [] if label in _REORDERED_VIEWS else _destination_signals(folded)

        # Nothing is hidden if it is also sitting in the plain text.
        signals = [s for s in phrase + dests if not (s[3] and s[3] in canon)]

        for det, _sev, msg, excerpt in dests:
            if det in ("url", "obfuscated_destination") and excerpt and excerpt not in canon:
                add("obfuscated_destination", Severity.CRITICAL,
                    "a destination appears only once the %s is decoded -- documentation "
                    "does not encode its own links (%s)" % (label, msg), excerpt)
                break

        signals = [s for s in signals if s[1] >= Severity.HIGH]
        if not signals:
            continue
        add("encoded_payload", Severity.CRITICAL,
            "%s decodes to text a reviewer never sees, and that text trips %s (%s)"
            % (label, signals[0][0], signals[0][2]), _clip(decoded, 70))

    # -- 6. content pushed out of sight --------------------------------------
    m = re.search(r"\n[ \t]*\n[ \t]*\n[ \t]*\n(\s*\S.*)", text, re.S)
    if m:
        add("buried_content", Severity.MEDIUM,
            "text follows a large gap -- a common way to push content below what a "
            "reviewer scrolls", _clip(m.group(1), 70))
    if re.search(r"[ \t]{40,}\S", text):
        add("buried_content", Severity.MEDIUM,
            "text follows a long run of spaces on one line")

    if len(text) > 4000:
        add("oversized", Severity.LOW,
            "description is %d characters -- long enough that nobody reads all of it"
            % len(text))

    return _escalate(rep, where)


_NAME_DETECTORS = {d for d, c in _CATEGORY.items() if c == "structure"} | {"action_like_name"}
_PREFILLED_KEYS = {"default", "const", "example", "examples", "enum", "placeholder"}
_SILENCING_FIELD = re.compile(
    r"^(?:quiet|silent|stealth|hidden|invisible|no[_-]?(?:prompt|confirm\w*|approval|log|notify)|"
    r"skip[_-]?(?:approval|confirm\w*|review|prompt)|suppress[_-]?\w*|auto[_-]?(?:approve|confirm))$",
    re.I,
)


def scan_action(action: Dict[str, Any], where: str = "") -> ScanReport:
    """Scan one discovered action as UnifAI returns it.

    Accepts the loose shapes real payloads come in: ``description`` or
    ``actionDescription``; ``payloadDescription`` either as a dict of fields or
    already flattened to a string.
    """
    rep = ScanReport()
    name = action.get("action") or action.get("name") or "<unnamed>"
    base = where or str(name)

    # The name is third-party text too, but it is judged more narrowly than prose:
    # a toolkit is allowed to call its action 'withdraw_all' (reported, never
    # escalated), and it is not allowed to call it 'withdrаw_all' with a Cyrillic
    # 'a' so it sorts next to the real one.
    if isinstance(name, str):
        name_rep = scan_text(name, "%s.action" % base)
        rep.findings.extend(f for f in name_rep.findings if f.detector in _NAME_DETECTORS)
        rep.scanned_chars += name_rep.scanned_chars

    for key in ("description", "actionDescription", "action_description"):
        if isinstance(action.get(key), str):
            rep.extend(scan_text(action[key], "%s.%s" % (base, key)))

    pd = action.get("payloadDescription", action.get("payload_description"))
    if isinstance(pd, str):
        rep.extend(scan_text(pd, "%s.payloadDescription" % base))
    elif isinstance(pd, dict):
        for fname, fval in pd.items():
            loc = "%s.payloadDescription.%s" % (base, fname)
            rep.extend(scan_text(str(fname), loc + " (name)"))
            if _SILENCING_FIELD.match(str(fname)):
                # A --quiet flag is ordinary, so this never escalates. It is here
                # because the field the attacker wants set is often named plainly.
                rep.findings.append(Finding(
                    "silencing_field", Severity.MEDIUM,
                    "a field whose name asks for the human-facing step to be dropped -- read "
                    "its description with that in mind", str(fname), loc))
            if isinstance(fval, str):
                rep.extend(scan_text(fval, loc))
            elif isinstance(fval, dict):
                for k, v in fval.items():
                    strings = [v] if isinstance(v, str) else (
                        [x for x in v if isinstance(x, str)]
                        if isinstance(v, (list, tuple)) else [])
                    for item in strings:
                        sub = scan_text(item, "%s.%s" % (loc, k))
                        # A destination in prose is a link. A destination in
                        # 'default' is where the value goes unless someone
                        # notices -- and nobody reads defaults.
                        if str(k).lower() in _PREFILLED_KEYS:
                            sub.findings = [
                                Finding(f.detector, max(f.severity, Severity.HIGH), f.message
                                        + " -- and it is pre-filled as the field's %s" % k,
                                        f.excerpt, f.where)
                                if _CATEGORY.get(f.detector) == "destination" else f
                                for f in sub.findings]
                        rep.extend(sub)
    return _escalate(rep, base)


def scan_toolkit(toolkit: Dict[str, Any]) -> ScanReport:
    """Scan a toolkit record and every action inside it."""
    rep = ScanReport()
    name = toolkit.get("name", "<unnamed toolkit>")
    for key in ("description", "toolkitDescription"):
        if isinstance(toolkit.get(key), str):
            rep.extend(scan_text(toolkit[key], "%s.%s" % (name, key)))
    actions: Iterable[Any] = toolkit.get("actions") or []
    if isinstance(actions, dict):
        actions = [dict(v, action=k) for k, v in actions.items()]
    for a in actions:
        if isinstance(a, dict):
            rep.extend(scan_action(a, "%s/%s" % (name, a.get("action", a.get("name", "?")))))
    return _escalate(rep, str(name))
