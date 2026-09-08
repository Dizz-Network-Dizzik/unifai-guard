# -*- coding: utf-8 -*-
"""unifai-guard -- a governance layer for agents that call tools they discovered.

Unofficial. Built by a community member, not affiliated with UnifAI Network.

Four pieces, each usable on its own:

* :mod:`~unifai_guard.schema`  -- declare a payload once, get both the
  natural-language ``payloadDescription`` and the validation.
* :mod:`~unifai_guard.scanner` -- read a discovered tool's description as the
  untrusted input it is.
* :mod:`~unifai_guard.gates`   -- stop before the irreversible thing; fail closed
  when unsure.
* :mod:`~unifai_guard.ledger`  -- an append-only record that notices edits, and
  says out loud what it cannot prove.

Nothing here needs a network, an API key, or a model. Standard library only.
"""
from .gates import Decision, Policy, Verdict, decide, estimate_magnitude
from .guard import BlockedError, Guard, Registration, always_approve, console_approver
from .ledger import ChainBreak, Ledger, LedgerEntry
from .scanner import (
    Finding,
    ScanReport,
    Severity,
    scan_action,
    scan_text,
    scan_toolkit,
)
from .schema import Field, Schema, ValidationError, Violation

__version__ = "0.1.0"

__all__ = [
    "Decision", "Policy", "Verdict", "decide", "estimate_magnitude",
    "BlockedError", "Guard", "Registration", "always_approve", "console_approver",
    "ChainBreak", "Ledger", "LedgerEntry",
    "Finding", "ScanReport", "Severity", "scan_action", "scan_text", "scan_toolkit",
    "Field", "Schema", "ValidationError", "Violation",
    "__version__",
]
