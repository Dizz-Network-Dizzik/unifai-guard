# -*- coding: utf-8 -*-
"""One declaration, two outputs.

UnifAI's ``payloadDescription`` is free-form natural language: the agent reads it
and decides what to send. That is what makes a toolkit fifteen lines long, and it
should stay that way.

The gap is that there is no path from loose to strict when a toolkit starts moving
value. Today you write the sentence for the agent *and* the validation in code, by
hand, twice -- and the two drift apart the first time anyone edits one of them.

This module removes the second copy. Declare the shape once::

    SWAP = Schema(
        token_in=Field.string("Symbol of the token to sell, e.g. USDC.",
                              pattern=r"^[A-Z0-9]{2,10}$"),
        amount=Field.number("How much of token_in to sell.",
                            minimum=0, exclusive_minimum=True,
                            maximum=10_000, monetary=True, unit="token_in"),
        slippage_bps=Field.integer("Maximum acceptable slippage in basis points.",
                                   minimum=0, maximum=1000, required=False,
                                   default=50),
    )

and you get both:

* ``SWAP.to_payload_description()`` -- the natural-language dict UnifAI wants,
  with every constraint spelled out in the sentence the agent actually reads.
* ``SWAP.validate(payload)`` -- the same constraints, enforced.

They cannot drift, because there is only one of them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field as _dc_field
from typing import Any, Dict, List, Optional, Sequence

__all__ = ["Field", "Schema", "Violation", "ValidationError"]

_TYPES = ("string", "number", "integer", "boolean", "array", "object")


@dataclass(frozen=True)
class Violation:
    """One reason a payload was rejected.

    ``path`` uses dotted/indexed notation (``order.items[2].amount``) so a caller
    can point at the offending value without guessing.
    """

    path: str
    code: str
    message: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return "%s: %s" % (self.path or "<payload>", self.message)


class ValidationError(ValueError):
    """Raised by :meth:`Schema.validate_or_raise`."""

    def __init__(self, violations: Sequence[Violation]) -> None:
        self.violations = list(violations)
        super().__init__(
            "%d validation problem(s): %s"
            % (len(self.violations), "; ".join(str(v) for v in self.violations))
        )


@dataclass
class Field:
    """One parameter: what it is, what it may contain, and what it means.

    ``sensitive`` marks a value that must never reach a log in clear text.
    ``monetary`` marks a value that participates in spend gates -- see
    :mod:`unifai_guard.gates`. Both are metadata the description does not carry
    on its own, and both are the reason this is a dataclass and not a bare dict.
    """

    type: str
    description: str
    required: bool = True
    default: Any = None
    enum: Optional[List[Any]] = None
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    exclusive_minimum: bool = False
    exclusive_maximum: bool = False
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    items: Optional["Field"] = None
    properties: Optional[Dict[str, "Field"]] = None
    additional_properties: bool = False
    sensitive: bool = False
    monetary: bool = False
    unit: Optional[str] = None
    examples: List[Any] = _dc_field(default_factory=list)

    def __post_init__(self) -> None:
        if self.type not in _TYPES:
            raise ValueError(
                "unknown type %r -- expected one of %s" % (self.type, ", ".join(_TYPES))
            )
        if self.type == "array" and self.items is None:
            raise ValueError("array fields need items=Field(...)")
        if self.type == "object" and self.properties is None:
            raise ValueError("object fields need properties={...}")
        if self.monetary and self.type not in ("number", "integer", "string"):
            raise ValueError("monetary only makes sense on number, integer or string")
        if self.pattern is not None:
            re.compile(self.pattern)  # fail at declaration, not at first call

    # -- constructors that read like the thing they build --------------------
    @classmethod
    def string(cls, description: str, **kw: Any) -> "Field":
        return cls(type="string", description=description, **kw)

    @classmethod
    def number(cls, description: str, **kw: Any) -> "Field":
        return cls(type="number", description=description, **kw)

    @classmethod
    def integer(cls, description: str, **kw: Any) -> "Field":
        return cls(type="integer", description=description, **kw)

    @classmethod
    def boolean(cls, description: str, **kw: Any) -> "Field":
        return cls(type="boolean", description=description, **kw)

    @classmethod
    def array(cls, description: str, items: "Field", **kw: Any) -> "Field":
        return cls(type="array", description=description, items=items, **kw)

    @classmethod
    def object(cls, description: str, properties: Dict[str, "Field"], **kw: Any) -> "Field":
        return cls(type="object", description=description, properties=properties, **kw)

    # -- what the agent reads ------------------------------------------------
    def sentence(self) -> str:
        """The description plus every constraint, in words.

        The point is not prettiness. An agent that is told ``amount`` must be
        between 0 and 10000 will usually send something in that range; an agent
        told only "the amount" will sometimes not. Stating the constraint is
        cheaper than rejecting the call afterwards.
        """
        parts = [self.description.strip().rstrip(".") + "."]

        if not self.required:
            if self.default is not None:
                parts.append("Optional; defaults to %s." % _lit(self.default))
            else:
                parts.append("Optional.")
        else:
            parts.append("Required.")

        if self.enum:
            parts.append("Must be one of: %s." % ", ".join(_lit(v) for v in self.enum))

        rng = _range_phrase(self)
        if rng:
            parts.append(rng)

        if self.type == "string":
            if self.min_length is not None and self.max_length is not None:
                if self.min_length == self.max_length:
                    parts.append("Exactly %d characters." % self.min_length)
                else:
                    parts.append(
                        "Between %d and %d characters." % (self.min_length, self.max_length)
                    )
            elif self.min_length is not None:
                parts.append("At least %d characters." % self.min_length)
            elif self.max_length is not None:
                parts.append("At most %d characters." % self.max_length)
            if self.pattern:
                parts.append("Must match the regular expression %s." % self.pattern)

        if self.type == "array":
            if self.min_length is not None and self.max_length is not None:
                parts.append("Between %d and %d items." % (self.min_length, self.max_length))
            elif self.min_length is not None:
                parts.append("At least %d item(s)." % self.min_length)
            elif self.max_length is not None:
                parts.append("At most %d item(s)." % self.max_length)
            parts.append("Each item: %s" % self.items.sentence())  # type: ignore[union-attr]

        if self.type == "object" and self.properties:
            inner = "; ".join(
                "%s -- %s" % (n, f.sentence()) for n, f in self.properties.items()
            )
            parts.append("Fields: %s" % inner)
            if not self.additional_properties:
                parts.append("No other fields are accepted.")

        if self.unit:
            parts.append("Unit: %s." % self.unit)

        if self.monetary:
            parts.append(
                "This field moves value; calls above the configured limit need "
                "human approval."
            )

        if self.sensitive:
            parts.append("Sensitive: never echoed back and never written to logs.")

        if self.examples:
            parts.append("Example: %s." % ", ".join(_lit(e) for e in self.examples))

        return " ".join(p for p in parts if p)

    # -- what other machines read -------------------------------------------
    def to_json_schema(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"type": self.type, "description": self.description}
        if self.enum:
            out["enum"] = list(self.enum)
        if self.minimum is not None:
            out["exclusiveMinimum" if self.exclusive_minimum else "minimum"] = self.minimum
        if self.maximum is not None:
            out["exclusiveMaximum" if self.exclusive_maximum else "maximum"] = self.maximum
        if self.type == "string":
            if self.min_length is not None:
                out["minLength"] = self.min_length
            if self.max_length is not None:
                out["maxLength"] = self.max_length
            if self.pattern:
                out["pattern"] = self.pattern
        if self.type == "array":
            out["items"] = self.items.to_json_schema()  # type: ignore[union-attr]
            if self.min_length is not None:
                out["minItems"] = self.min_length
            if self.max_length is not None:
                out["maxItems"] = self.max_length
        if self.type == "object" and self.properties:
            out["properties"] = {n: f.to_json_schema() for n, f in self.properties.items()}
            req = [n for n, f in self.properties.items() if f.required]
            if req:
                out["required"] = req
            out["additionalProperties"] = self.additional_properties
        if self.default is not None:
            out["default"] = self.default
        if self.examples:
            out["examples"] = list(self.examples)
        return out


def _lit(v: Any) -> str:
    return '"%s"' % v if isinstance(v, str) else str(v)


def _range_phrase(f: Field) -> str:
    if f.type not in ("number", "integer"):
        return ""
    lo, hi = f.minimum, f.maximum
    if lo is None and hi is None:
        return ""
    lo_w = "greater than" if f.exclusive_minimum else "at least"
    hi_w = "less than" if f.exclusive_maximum else "at most"
    if lo is not None and hi is not None:
        return "Must be %s %s and %s %s." % (lo_w, _num(lo), hi_w, _num(hi))
    if lo is not None:
        return "Must be %s %s." % (lo_w, _num(lo))
    return "Must be %s %s." % (hi_w, _num(hi))


def _num(v: float) -> str:
    return str(int(v)) if float(v).is_integer() else str(v)


class Schema:
    """A named set of :class:`Field` s -- the payload of one action."""

    def __init__(self, **fields: Field) -> None:
        if not fields:
            raise ValueError("a schema with no fields validates nothing")
        for name, f in fields.items():
            if not isinstance(f, Field):
                raise TypeError("%s must be a Field, got %r" % (name, type(f).__name__))
        self.fields: Dict[str, Field] = dict(fields)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "Schema(%s)" % ", ".join(self.fields)

    # -- the two outputs -----------------------------------------------------
    def to_payload_description(self) -> Dict[str, Dict[str, str]]:
        """Exactly the shape UnifAI expects, with the constraints written out."""
        return {
            name: {"type": f.type, "description": f.sentence()}
            for name, f in self.fields.items()
        }

    def to_json_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {n: f.to_json_schema() for n, f in self.fields.items()},
            "required": [n for n, f in self.fields.items() if f.required],
            "additionalProperties": False,
        }

    # -- enforcement ---------------------------------------------------------
    def validate(self, payload: Any) -> List[Violation]:
        """Return every problem, not just the first.

        An agent that gets all four mistakes back in one response can fix all
        four in one retry. One-at-a-time costs a round trip per field.
        """
        if not isinstance(payload, dict):
            return [
                Violation("", "not_an_object", "payload must be an object, got %s"
                          % type(payload).__name__)
            ]

        out: List[Violation] = []
        for name, f in self.fields.items():
            if name not in payload or payload[name] is None:
                if f.required:
                    out.append(Violation(name, "missing", "required field is missing"))
                continue
            out.extend(_check(payload[name], f, name))

        for name in payload:
            if name not in self.fields:
                out.append(
                    Violation(
                        name,
                        "unknown_field",
                        "not a field of this action -- a hallucinated parameter is a "
                        "signal, not a nuisance",
                    )
                )
        return out

    def validate_or_raise(self, payload: Any) -> Dict[str, Any]:
        """Validate, fill in declared defaults, and return the clean payload."""
        problems = self.validate(payload)
        if problems:
            raise ValidationError(problems)
        clean = dict(payload)
        for name, f in self.fields.items():
            if name not in clean and f.default is not None:
                clean[name] = f.default
        return clean

    def is_valid(self, payload: Any) -> bool:
        return not self.validate(payload)

    # -- helpers other modules need -----------------------------------------
    def monetary_fields(self) -> List[str]:
        return [n for n, f in self.fields.items() if f.monetary]

    def sensitive_fields(self) -> List[str]:
        return [n for n, f in self.fields.items() if f.sensitive]

    def redact(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """A copy safe to write down: sensitive values replaced, shape kept."""
        out = {}
        for k, v in payload.items():
            f = self.fields.get(k)
            out[k] = "<redacted>" if (f is not None and f.sensitive) else v
        return out


def _check(value: Any, f: Field, path: str) -> List[Violation]:
    out: List[Violation] = []

    # bool is a subclass of int in Python; for a payload they are not the same
    # thing, and letting True through as an amount is exactly the kind of quiet
    # mistake this module exists to stop.
    if f.type == "boolean":
        if not isinstance(value, bool):
            return [Violation(path, "type", "expected boolean, got %s" % _tname(value))]
    elif f.type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            return [Violation(path, "type", "expected integer, got %s" % _tname(value))]
    elif f.type == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return [Violation(path, "type", "expected number, got %s" % _tname(value))]
    elif f.type == "string":
        if not isinstance(value, str):
            return [Violation(path, "type", "expected string, got %s" % _tname(value))]
    elif f.type == "array":
        if not isinstance(value, (list, tuple)):
            return [Violation(path, "type", "expected array, got %s" % _tname(value))]
    elif f.type == "object":
        if not isinstance(value, dict):
            return [Violation(path, "type", "expected object, got %s" % _tname(value))]

    if f.enum is not None and value not in f.enum:
        out.append(
            Violation(path, "enum", "must be one of %s"
                      % ", ".join(_lit(v) for v in f.enum))
        )

    if f.type in ("number", "integer"):
        if f.minimum is not None:
            if f.exclusive_minimum and value <= f.minimum:
                out.append(Violation(path, "minimum",
                                     "must be greater than %s" % _num(f.minimum)))
            elif not f.exclusive_minimum and value < f.minimum:
                out.append(Violation(path, "minimum",
                                     "must be at least %s" % _num(f.minimum)))
        if f.maximum is not None:
            if f.exclusive_maximum and value >= f.maximum:
                out.append(Violation(path, "maximum",
                                     "must be less than %s" % _num(f.maximum)))
            elif not f.exclusive_maximum and value > f.maximum:
                out.append(Violation(path, "maximum",
                                     "must be at most %s" % _num(f.maximum)))

    if f.type == "string":
        if f.min_length is not None and len(value) < f.min_length:
            out.append(Violation(path, "min_length",
                                 "must be at least %d characters" % f.min_length))
        if f.max_length is not None and len(value) > f.max_length:
            out.append(Violation(path, "max_length",
                                 "must be at most %d characters" % f.max_length))
        if f.pattern and not re.search(f.pattern, value):
            out.append(Violation(path, "pattern",
                                 "must match %s" % f.pattern))

    if f.type == "array":
        if f.min_length is not None and len(value) < f.min_length:
            out.append(Violation(path, "min_items",
                                 "must have at least %d item(s)" % f.min_length))
        if f.max_length is not None and len(value) > f.max_length:
            out.append(Violation(path, "max_items",
                                 "must have at most %d item(s)" % f.max_length))
        for i, item in enumerate(value):
            out.extend(_check(item, f.items, "%s[%d]" % (path, i)))  # type: ignore[arg-type]

    if f.type == "object" and f.properties is not None:
        for n, sub in f.properties.items():
            if n not in value or value[n] is None:
                if sub.required:
                    out.append(Violation("%s.%s" % (path, n), "missing",
                                         "required field is missing"))
                continue
            out.extend(_check(value[n], sub, "%s.%s" % (path, n)))
        if not f.additional_properties:
            for n in value:
                if n not in f.properties:
                    out.append(Violation("%s.%s" % (path, n), "unknown_field",
                                         "not a field of this object"))

    return out


def _tname(v: Any) -> str:
    return {bool: "boolean", int: "integer", float: "number", str: "string",
            list: "array", tuple: "array", dict: "object",
            type(None): "null"}.get(type(v), type(v).__name__)
