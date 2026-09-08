# -*- coding: utf-8 -*-
"""Where the call stops and a human is asked.

Two rules carry most of the weight here, and both are about what happens when the
guard is *unsure*:

1. **An unknown action is not a safe action.** If nobody registered it, the guard
   does not know whether it sends an email or empties a wallet. The default is to
   ask, not to allow.
2. **An amount the guard cannot read is treated as large.** If an action is marked
   irreversible and no magnitude can be found in the payload, that is a reason to
   stop, not a reason to shrug. A gate that opens when it cannot measure is a
   decoration.

Both defaults are annoying on purpose. They can be turned off in one line each,
by someone who has decided to -- which is the point: the decision is written down
somewhere, instead of being the accident of a missing check.
"""
from __future__ import annotations

import enum
import fnmatch
import re
from dataclasses import dataclass, field as _dc_field
from typing import Any, Dict, List, Optional, Tuple

from .scanner import ScanReport, Severity

__all__ = ["Decision", "Verdict", "Policy", "estimate_magnitude"]


class Decision(enum.Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"

    def __str__(self) -> str:  # pragma: no cover - display only
        return self.value


@dataclass
class Verdict:
    decision: Decision
    reason: str
    action: str = ""
    magnitude: Optional[float] = None
    magnitude_source: str = ""
    scan: Optional[ScanReport] = None
    violations: List[str] = _dc_field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    @property
    def needs_human(self) -> bool:
        return self.decision is Decision.REQUIRE_APPROVAL

    def __str__(self) -> str:  # pragma: no cover - display only
        mag = "" if self.magnitude is None else " (magnitude %s via %s)" % (
            self.magnitude, self.magnitude_source)
        return "%s: %s%s" % (self.decision.value.upper(), self.reason, mag)


# Field names that carry a quantity in practically every DeFi payload seen in the
# wild. This list is a convenience for actions nobody bothered to register -- a
# registered schema marks its own monetary fields and does not need guessing.
_MONEY_NAMES = re.compile(
    r"^(?:amount|amount_?in|amount_?out|amountIn|amountOut|value|qty|quantity|size|"
    r"notional|principal|collateral|stake|deposit|withdraw|repay|borrow|"
    r"lamports|wei|gwei|sats|satoshis|units|total|sum|max_?spend|budget)$",
    re.I,
)

_DECIMAL = re.compile(r"^\s*-?\d+(?:\.\d+)?\s*$")


def estimate_magnitude(
    payload: Any,
    monetary_fields: Optional[List[str]] = None,
    _depth: int = 0,
) -> Tuple[Optional[float], str]:
    """Best guess at "how much does this call move", and where the guess came from.

    Returns ``(None, "")`` when nothing usable was found -- which callers must
    treat as *unknown*, never as *zero*. The two are opposite in consequence.
    """
    if _depth > 6 or not isinstance(payload, dict):
        return None, ""

    best: Optional[float] = None
    source = ""

    # A declared monetary field always beats a guessed one.
    for name in monetary_fields or []:
        if name in payload:
            v = _as_number(payload[name])
            if v is not None and (best is None or v > best):
                best, source = v, "declared field %r" % name
    if best is not None:
        return best, source

    for key, val in payload.items():
        if isinstance(val, dict):
            sub, sub_src = estimate_magnitude(val, None, _depth + 1)
            if sub is not None and (best is None or sub > best):
                best, source = sub, "%s.%s" % (key, sub_src) if sub_src else key
        elif isinstance(val, (list, tuple)):
            for i, item in enumerate(val):
                if isinstance(item, dict):
                    sub, sub_src = estimate_magnitude(item, None, _depth + 1)
                    if sub is not None and (best is None or sub > best):
                        best, source = sub, "%s[%d].%s" % (key, i, sub_src)
        elif _MONEY_NAMES.match(str(key)):
            v = _as_number(val)
            if v is not None and (best is None or v > best):
                best, source = v, "field name %r" % key

    return best, source


def _as_number(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str) and _DECIMAL.match(v):
        try:
            return float(v.strip())
        except ValueError:
            return None
    return None


@dataclass
class Policy:
    """What the guard does, written where anyone can read it.

    ``approval_over`` is in whatever unit the payload uses. The guard does not
    convert currencies and does not pretend to: a threshold of 100 against a
    payload denominated in wei is a threshold nobody meant. Set it per toolkit,
    or mark the field with ``unit=`` and read it back in the audit log.
    """

    # -- scanning ------------------------------------------------------------
    deny_scan_at: Severity = Severity.CRITICAL
    approve_scan_at: Severity = Severity.HIGH

    # -- spending ------------------------------------------------------------
    approval_over: Optional[float] = None
    deny_over: Optional[float] = None

    # -- irreversibility -----------------------------------------------------
    irreversible: List[str] = _dc_field(default_factory=list)
    always_approve: List[str] = _dc_field(default_factory=list)
    always_deny: List[str] = _dc_field(default_factory=list)

    # -- the two fail-closed defaults ---------------------------------------
    unknown_action: Decision = Decision.REQUIRE_APPROVAL
    unmeasurable_irreversible: Decision = Decision.REQUIRE_APPROVAL

    # -- validation ----------------------------------------------------------
    deny_on_validation_error: bool = True

    def matches(self, patterns: List[str], action: str) -> bool:
        return any(fnmatch.fnmatch(action, p) for p in patterns)

    @classmethod
    def permissive(cls) -> "Policy":
        """Everything allowed except what the scanner calls critical.

        For reading, searching, quoting -- actions that cost a request and
        nothing else.
        """
        return cls(
            deny_scan_at=Severity.CRITICAL,
            approve_scan_at=Severity.CRITICAL,
            unknown_action=Decision.ALLOW,
            unmeasurable_irreversible=Decision.ALLOW,
            deny_on_validation_error=True,
        )

    @classmethod
    def strict(cls, approval_over: float = 0.0) -> "Policy":
        """Nothing unregistered, nothing unmeasured, nothing high-severity.

        The default ``approval_over=0`` means every call that moves any value at
        all gets a human. Raise it when you know what you are willing to lose.
        """
        return cls(
            deny_scan_at=Severity.HIGH,
            approve_scan_at=Severity.MEDIUM,
            approval_over=approval_over,
            unknown_action=Decision.DENY,
            unmeasurable_irreversible=Decision.REQUIRE_APPROVAL,
            deny_on_validation_error=True,
        )


def decide(
    policy: Policy,
    action: str,
    payload: Dict[str, Any],
    *,
    known: bool,
    irreversible: bool,
    monetary_fields: Optional[List[str]] = None,
    scan: Optional[ScanReport] = None,
    violations: Optional[List[str]] = None,
) -> Verdict:
    """Apply the policy. Deny wins over approve wins over allow."""
    violations = list(violations or [])
    magnitude, source = estimate_magnitude(payload, monetary_fields)
    base = dict(action=action, magnitude=magnitude, magnitude_source=source,
                scan=scan, violations=violations)

    # -- hard stops ----------------------------------------------------------
    if policy.matches(policy.always_deny, action):
        return Verdict(Decision.DENY, "action matches always_deny", **base)

    if violations and policy.deny_on_validation_error:
        return Verdict(Decision.DENY,
                       "payload failed validation: %s" % "; ".join(violations[:3]), **base)

    if scan is not None and scan.blocks_at(policy.deny_scan_at):
        worst = scan.at_or_above(policy.deny_scan_at)[0]
        return Verdict(Decision.DENY,
                       "description scan: %s (%s)" % (worst.message, worst.detector), **base)

    if policy.deny_over is not None and magnitude is not None and magnitude > policy.deny_over:
        return Verdict(Decision.DENY,
                       "magnitude %s is over the hard limit %s" % (magnitude, policy.deny_over),
                       **base)

    if not known:
        if policy.unknown_action is Decision.DENY:
            return Verdict(Decision.DENY,
                           "action is not registered -- an unknown action is not a safe "
                           "action", **base)
        if policy.unknown_action is Decision.REQUIRE_APPROVAL:
            return Verdict(Decision.REQUIRE_APPROVAL,
                           "action is not registered -- the guard cannot tell what it does",
                           **base)

    # -- ask a human ---------------------------------------------------------
    if policy.matches(policy.always_approve, action):
        return Verdict(Decision.REQUIRE_APPROVAL, "action matches always_approve", **base)

    if scan is not None and scan.blocks_at(policy.approve_scan_at):
        worst = scan.at_or_above(policy.approve_scan_at)[0]
        return Verdict(Decision.REQUIRE_APPROVAL,
                       "description scan: %s (%s)" % (worst.message, worst.detector), **base)

    if irreversible:
        if magnitude is None:
            if policy.unmeasurable_irreversible is Decision.DENY:
                return Verdict(Decision.DENY,
                               "irreversible action and no magnitude could be read from "
                               "the payload", **base)
            if policy.unmeasurable_irreversible is Decision.REQUIRE_APPROVAL:
                return Verdict(Decision.REQUIRE_APPROVAL,
                               "irreversible action and no magnitude could be read -- "
                               "unknown is not zero", **base)
        elif policy.approval_over is not None and magnitude > policy.approval_over:
            return Verdict(Decision.REQUIRE_APPROVAL,
                           "irreversible action of magnitude %s, over the limit %s"
                           % (magnitude, policy.approval_over), **base)

    if (policy.approval_over is not None and magnitude is not None
            and magnitude > policy.approval_over):
        return Verdict(Decision.REQUIRE_APPROVAL,
                       "magnitude %s is over the approval limit %s"
                       % (magnitude, policy.approval_over), **base)

    return Verdict(Decision.ALLOW, "within policy", **base)
