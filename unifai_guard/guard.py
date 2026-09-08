# -*- coding: utf-8 -*-
"""The piece that ties the other four together.

Register what an action is, and the guard will: generate the natural-language
``payloadDescription`` from that same declaration, validate every payload against
it, scan the descriptions of tools it discovers, apply the policy, ask a human
when the policy says to, and write down what happened.

The default approver refuses. A guard whose "ask a human" path silently answers
yes is decoration, and decoration is worse than nothing here, because it is
mistaken for a control. Pass a real approver, or accept that anything needing
approval stops.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .gates import Decision, Policy, Verdict, decide
from .ledger import Ledger
from .scanner import ScanReport, Severity, scan_action, scan_text
from .schema import Schema, ValidationError

__all__ = ["Guard", "Registration", "BlockedError", "console_approver", "always_approve"]


class BlockedError(RuntimeError):
    """Raised when a call was stopped. Carries the verdict that stopped it."""

    def __init__(self, verdict: Verdict) -> None:
        self.verdict = verdict
        super().__init__(str(verdict))


@dataclass
class Registration:
    action: str
    schema: Optional[Schema] = None
    irreversible: bool = False
    note: str = ""


Approver = Callable[[Verdict], bool]


def console_approver(verdict: Verdict) -> bool:  # pragma: no cover - interactive
    """Ask on stdin. For a person sitting in front of the process."""
    print("")
    print("  APPROVAL NEEDED")
    print("    action    : %s" % verdict.action)
    print("    reason    : %s" % verdict.reason)
    if verdict.magnitude is not None:
        print("    magnitude : %s  (%s)" % (verdict.magnitude, verdict.magnitude_source))
    if verdict.scan and verdict.scan.findings:
        print("    scan      : %s" % verdict.scan.summary())
        for f in verdict.scan.at_or_above(Severity.MEDIUM)[:5]:
            print("                %s" % f)
    answer = input("    allow this call? [y/N] ").strip().lower()
    return answer in ("y", "yes")


def always_approve(verdict: Verdict) -> bool:
    """For tests and dry runs. Naming it this way makes it grep-able in review."""
    return True


class Guard:
    """One guard per toolkit or per agent. Not thread-shared across processes."""

    def __init__(
        self,
        policy: Optional[Policy] = None,
        ledger: Optional[Ledger] = None,
        approver: Optional[Approver] = None,
        scan_payloads: bool = False,
    ) -> None:
        self.policy = policy or Policy.strict()
        self.ledger = ledger if ledger is not None else Ledger()
        self.approver = approver
        self.scan_payloads = scan_payloads
        self._registry: Dict[str, Registration] = {}
        self._tool_scans: Dict[str, ScanReport] = {}

    # -- declaring -----------------------------------------------------------
    def register(
        self,
        action: str,
        schema: Optional[Schema] = None,
        irreversible: bool = False,
        note: str = "",
    ) -> Registration:
        reg = Registration(action=action, schema=schema, irreversible=irreversible, note=note)
        self._registry[action] = reg
        self.ledger.append(
            "register", action, "registered", note or "",
            meta={"irreversible": irreversible, "has_schema": schema is not None},
        )
        return reg

    def describe(self, action: str) -> Dict[str, Dict[str, str]]:
        """The ``payloadDescription`` for a registered action.

        Generated from the same declaration that validates it, so the sentence
        the agent reads and the rule the code enforces cannot disagree.
        """
        reg = self._registry.get(action)
        if reg is None or reg.schema is None:
            raise KeyError("%r is not registered with a schema" % action)
        return reg.schema.to_payload_description()

    @property
    def registered(self) -> List[str]:
        return sorted(self._registry)

    # -- inspecting what was discovered --------------------------------------
    def inspect(self, tool: Dict[str, Any]) -> ScanReport:
        """Scan a discovered tool before letting an agent read its description.

        Call this on everything that came back from tool discovery, not just on
        tools you are about to use: the cost of scanning is microseconds and the
        finding you want is the one on the tool you decided against.
        """
        rep = scan_action(tool)
        name = str(tool.get("action") or tool.get("name") or "<unnamed>")
        self._tool_scans[name] = rep
        if rep.findings:
            self.ledger.append(
                "inspect", name, "flagged", rep.summary(),
                findings=[str(f) for f in rep.at_or_above(Severity.MEDIUM)],
            )
        return rep

    def inspect_all(self, tools: List[Dict[str, Any]]) -> Dict[str, ScanReport]:
        return {str(t.get("action") or t.get("name") or i): self.inspect(t)
                for i, t in enumerate(tools)}

    def usable(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """The subset of discovered tools whose descriptions do not trip the policy.

        This is the practical entry point: hand it what discovery returned, give
        the agent back what survived, and read the ledger for what did not.
        """
        out = []
        for t in tools:
            rep = self.inspect(t)
            if not rep.blocks_at(self.policy.deny_scan_at):
                out.append(t)
        return out

    # -- deciding ------------------------------------------------------------
    def check(self, action: str, payload: Dict[str, Any]) -> Verdict:
        """Decide without calling anything. Always writes to the ledger."""
        reg = self._registry.get(action)
        violations: List[str] = []
        monetary: List[str] = []

        if reg is not None and reg.schema is not None:
            violations = [str(v) for v in reg.schema.validate(payload)]
            monetary = reg.schema.monetary_fields()

        scan = self._tool_scans.get(action)
        if self.scan_payloads:
            payload_scan = ScanReport()
            for k, v in (payload or {}).items():
                if isinstance(v, str):
                    payload_scan.extend(scan_text(v, "payload.%s" % k))
            if scan is None:
                scan = payload_scan
            else:
                merged = ScanReport(list(scan.findings), scan.scanned_chars)
                scan = merged.extend(payload_scan)

        verdict = decide(
            self.policy, action, payload or {},
            known=reg is not None,
            irreversible=bool(reg and reg.irreversible),
            monetary_fields=monetary,
            scan=scan,
            violations=violations,
        )

        redacted_digest = None
        if reg is not None and reg.schema is not None and isinstance(payload, dict):
            from .ledger import _digest  # local: keeps the redaction next to its use
            redacted_digest = _digest(reg.schema.redact(payload))

        self.ledger.append(
            "check", action, verdict.decision.value, verdict.reason,
            payload=None if redacted_digest else payload,
            payload_digest=redacted_digest,
            findings=violations[:10],
            meta={"magnitude": verdict.magnitude, "source": verdict.magnitude_source},
        )
        return verdict

    def call(
        self,
        action: str,
        fn: Callable[..., Any],
        payload: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Check, ask if needed, then run ``fn(payload)``.

        Raises :class:`BlockedError` when the call does not survive the policy or
        the approver. Raising is deliberate: a guard that returns ``None`` on a
        blocked call gets mistaken for a guard that ran it.
        """
        payload = dict(payload or {})
        payload.update(kwargs)
        verdict = self.check(action, payload)

        if verdict.decision is Decision.DENY:
            raise BlockedError(verdict)

        if verdict.decision is Decision.REQUIRE_APPROVAL:
            approved = False
            if self.approver is not None:
                approved = bool(self.approver(verdict))
            self.ledger.append(
                "approval", action, "granted" if approved else "refused",
                "approver present" if self.approver else
                "no approver configured -- the default is to refuse",
            )
            if not approved:
                raise BlockedError(verdict)

        reg = self._registry.get(action)
        if reg is not None and reg.schema is not None:
            try:
                payload = reg.schema.validate_or_raise(payload)
            except ValidationError as exc:  # pragma: no cover - decide() catches this first
                self.ledger.append("execute", action, "error", str(exc))
                raise

        try:
            result = fn(payload)
        except Exception as exc:
            self.ledger.append("execute", action, "raised", "%s: %s"
                               % (type(exc).__name__, exc))
            raise
        self.ledger.append("execute", action, "ran", "")
        return result

    # -- wrapping a toolkit action ------------------------------------------
    def protect(
        self,
        action: str,
        schema: Optional[Schema] = None,
        irreversible: bool = False,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator for a toolkit handler.

        ::

            @guard.protect("swap", SWAP, irreversible=True)
            async def swap(ctx, payload):
                ...
        """
        self.register(action, schema=schema, irreversible=irreversible)

        def wrap(fn: Callable[..., Any]) -> Callable[..., Any]:
            import functools
            import inspect

            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def awrapper(ctx: Any, payload: Dict[str, Any]) -> Any:
                    verdict = self.check(action, payload)
                    if verdict.decision is Decision.DENY:
                        raise BlockedError(verdict)
                    if verdict.decision is Decision.REQUIRE_APPROVAL:
                        if not (self.approver and self.approver(verdict)):
                            raise BlockedError(verdict)
                    result = await fn(ctx, payload)
                    self.ledger.append("execute", action, "ran", "")
                    return result

                return awrapper

            @functools.wraps(fn)
            def wrapper(ctx: Any, payload: Dict[str, Any]) -> Any:
                verdict = self.check(action, payload)
                if verdict.decision is Decision.DENY:
                    raise BlockedError(verdict)
                if verdict.decision is Decision.REQUIRE_APPROVAL:
                    if not (self.approver and self.approver(verdict)):
                        raise BlockedError(verdict)
                result = fn(ctx, payload)
                self.ledger.append("execute", action, "ran", "")
                return result

            return wrapper

        return wrap

    # -- looking back --------------------------------------------------------
    def audit(self) -> str:
        break_ = self.ledger.verify()
        head = "ledger: %d entries, head %s" % (len(self.ledger), self.ledger.head[:12])
        if break_ is not None:
            return "%s\nCHAIN BROKEN -- %s" % (head, break_)
        return "%s\nchain holds (note: tail truncation is not detectable locally -- " \
               "publish the head)" % head
