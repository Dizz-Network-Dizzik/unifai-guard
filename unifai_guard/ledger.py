# -*- coding: utf-8 -*-
"""An append-only record that notices when it has been edited.

Every decision the guard makes is written here as one JSON line whose digest
covers the line before it. Change any earlier entry, or remove one from the
middle, and every digest after it stops matching.

What this does and does not prove
---------------------------------
It detects **modification** and **deletion from the middle**. It does not detect
**truncation of the tail**: an attacker who deletes the last N lines leaves a
chain that is internally consistent. That is a property of hash chains, not an
oversight, and no amount of local cleverness fixes it -- the fix is to publish
:meth:`Ledger.head` somewhere you do not control, at intervals. A timestamped
comment, a commit, an OpenTimestamps anchor: anything that makes "the log ended
here" a claim someone else can check.

Saying this out loud matters more than the code. A log that quietly implies more
than it proves is worse than no log, because people stop looking.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional

__all__ = ["Ledger", "LedgerEntry", "ChainBreak", "GENESIS"]

GENESIS = "0" * 64


def _digest(obj: Any) -> str:
    """Stable digest: sorted keys, no whitespace, explicit UTF-8."""
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class LedgerEntry:
    seq: int
    ts: str
    prev: str
    kind: str
    action: str
    decision: str
    reason: str
    payload_digest: str
    findings: List[str]
    meta: Dict[str, Any]
    digest: str

    def body(self) -> Dict[str, Any]:
        """Everything the digest covers."""
        return {
            "seq": self.seq,
            "ts": self.ts,
            "prev": self.prev,
            "kind": self.kind,
            "action": self.action,
            "decision": self.decision,
            "reason": self.reason,
            "payload_digest": self.payload_digest,
            "findings": self.findings,
            "meta": self.meta,
        }

    def recompute(self) -> str:
        return _digest(self.body())

    def to_json(self) -> str:
        d = self.body()
        d["digest"] = self.digest
        return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class ChainBreak:
    seq: Optional[int]
    kind: str
    detail: str

    def __str__(self) -> str:  # pragma: no cover - display only
        at = "entry %d" % self.seq if self.seq is not None else "file"
        return "%s: %s (%s)" % (at, self.detail, self.kind)


class Ledger:
    """Append-only, hash-chained, one JSON object per line.

    Thread-safe for appends within one process. Across processes, point each at
    its own file -- interleaved writers would produce a chain that forks, and a
    forked chain that still verifies is exactly the kind of quiet lie this class
    is supposed to prevent.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._memory: List[LedgerEntry] = []
        self._head = GENESIS
        self._seq = 0
        if path and os.path.exists(path):
            self._resume()

    # -- reading -------------------------------------------------------------
    def _resume(self) -> None:
        last = None
        n = 0
        for entry in self.entries():
            last = entry
            n += 1
        if last is not None:
            self._head = last.digest
            self._seq = last.seq + 1
        elif n == 0:
            self._head = GENESIS
            self._seq = 0

    def entries(self) -> Iterator[LedgerEntry]:
        if self.path:
            if not os.path.exists(self.path):
                return
            with open(self.path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    yield _entry_from_json(line)
        else:
            for e in self._memory:
                yield e

    def __len__(self) -> int:
        return sum(1 for _ in self.entries())

    @property
    def head(self) -> str:
        """Digest of the newest entry. Publish this to close the truncation gap."""
        return self._head

    # -- writing -------------------------------------------------------------
    def append(
        self,
        kind: str,
        action: str,
        decision: str,
        reason: str = "",
        payload: Any = None,
        payload_digest: Optional[str] = None,
        findings: Optional[List[str]] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> LedgerEntry:
        """Record one decision.

        The payload is digested, never stored: the log should prove *what was
        decided*, and it should not become a second copy of everything that
        passed through. Pass ``payload_digest`` directly if you have already
        redacted and hashed it yourself.
        """
        with self._lock:
            if payload_digest is None:
                payload_digest = _digest(payload) if payload is not None else ""
            body = {
                "seq": self._seq,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "prev": self._head,
                "kind": kind,
                "action": action,
                "decision": decision,
                "reason": reason,
                "payload_digest": payload_digest,
                "findings": list(findings or []),
                "meta": dict(meta or {}),
            }
            entry = LedgerEntry(digest=_digest(body), **body)

            if self.path:
                d = os.path.dirname(os.path.abspath(self.path))
                if d:
                    os.makedirs(d, exist_ok=True)
                with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
                    fh.write(entry.to_json() + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            else:
                self._memory.append(entry)

            self._head = entry.digest
            self._seq += 1
            return entry

    # -- checking ------------------------------------------------------------
    def verify(self) -> Optional[ChainBreak]:
        """Walk the chain. Return the first break, or ``None`` if it holds."""
        prev = GENESIS
        expect_seq = 0
        seen = 0
        try:
            for entry in self.entries():
                seen += 1
                if entry.seq != expect_seq:
                    return ChainBreak(entry.seq, "sequence",
                                      "expected seq %d, found %d" % (expect_seq, entry.seq))
                if entry.prev != prev:
                    return ChainBreak(entry.seq, "link",
                                      "prev does not match the previous entry's digest "
                                      "-- an entry was changed or removed before this one")
                if entry.recompute() != entry.digest:
                    return ChainBreak(entry.seq, "digest",
                                      "contents do not match the recorded digest "
                                      "-- this entry was edited")
                prev = entry.digest
                expect_seq += 1
        except (ValueError, KeyError, TypeError) as exc:
            return ChainBreak(expect_seq, "malformed", "line could not be read: %s" % exc)

        if seen and prev != self._head:
            return ChainBreak(None, "head",
                              "file ends at a different digest than this Ledger expects "
                              "-- entries were removed from the end")
        return None

    def holds(self) -> bool:
        return self.verify() is None

    def tail(self, n: int = 20) -> List[LedgerEntry]:
        out = list(self.entries())
        return out[-n:]


def _entry_from_json(line: str) -> LedgerEntry:
    d = json.loads(line)
    return LedgerEntry(
        seq=d["seq"], ts=d["ts"], prev=d["prev"], kind=d["kind"], action=d["action"],
        decision=d["decision"], reason=d.get("reason", ""),
        payload_digest=d.get("payload_digest", ""), findings=d.get("findings", []),
        meta=d.get("meta", {}), digest=d["digest"],
    )
