# -*- coding: utf-8 -*-
import unittest

from unifai_guard import Field, Schema, ValidationError


SWAP = Schema(
    token_in=Field.string("Symbol of the token to sell.", pattern=r"^[A-Z0-9]{2,10}$"),
    token_out=Field.string("Symbol of the token to buy.", pattern=r"^[A-Z0-9]{2,10}$"),
    amount=Field.number("How much of token_in to sell.", minimum=0,
                        exclusive_minimum=True, maximum=10000, monetary=True,
                        unit="token_in"),
    slippage_bps=Field.integer("Maximum acceptable slippage, in basis points.",
                               minimum=0, maximum=1000, required=False, default=50),
    dry_run=Field.boolean("Simulate without broadcasting.", required=False, default=False),
)


class TestDescription(unittest.TestCase):
    def test_payload_description_has_unifai_shape(self):
        pd = SWAP.to_payload_description()
        self.assertEqual(set(pd), set(SWAP.fields))
        for name, entry in pd.items():
            self.assertEqual(set(entry), {"type", "description"})
            self.assertIsInstance(entry["description"], str)

    def test_constraints_reach_the_agent(self):
        """The whole point: the limit is in the sentence, not only in the code."""
        d = SWAP.to_payload_description()["amount"]["description"]
        self.assertIn("greater than 0", d)
        self.assertIn("at most 10000", d)
        self.assertIn("Required", d)
        self.assertIn("moves value", d)
        self.assertIn("token_in", d)

    def test_optional_states_its_default(self):
        d = SWAP.to_payload_description()["slippage_bps"]["description"]
        self.assertIn("Optional", d)
        self.assertIn("50", d)

    def test_pattern_is_stated(self):
        d = SWAP.to_payload_description()["token_in"]["description"]
        self.assertIn("^[A-Z0-9]{2,10}$", d)

    def test_enum_is_listed(self):
        s = Schema(side=Field.string("Order side.", enum=["buy", "sell"]))
        self.assertIn('"buy", "sell"', s.to_payload_description()["side"]["description"])

    def test_json_schema_round_trip(self):
        js = SWAP.to_json_schema()
        self.assertEqual(js["type"], "object")
        self.assertEqual(js["additionalProperties"], False)
        self.assertIn("amount", js["properties"])
        self.assertEqual(js["properties"]["amount"]["exclusiveMinimum"], 0)
        self.assertEqual(js["properties"]["amount"]["maximum"], 10000)
        self.assertCountEqual(js["required"], ["token_in", "token_out", "amount"])

    def test_sensitive_is_announced(self):
        s = Schema(key=Field.string("The signing key.", sensitive=True))
        self.assertIn("never written to logs", s.to_payload_description()["key"]["description"])


class TestValidation(unittest.TestCase):
    def good(self):
        return {"token_in": "USDC", "token_out": "SOL", "amount": 100.0}

    def test_good_payload_passes(self):
        self.assertEqual(SWAP.validate(self.good()), [])
        self.assertTrue(SWAP.is_valid(self.good()))

    def test_defaults_are_filled_in(self):
        clean = SWAP.validate_or_raise(self.good())
        self.assertEqual(clean["slippage_bps"], 50)
        self.assertEqual(clean["dry_run"], False)

    def test_missing_required(self):
        p = self.good()
        del p["amount"]
        codes = [v.code for v in SWAP.validate(p)]
        self.assertIn("missing", codes)

    def test_every_problem_is_returned_not_just_the_first(self):
        p = {"token_in": "usdc", "amount": -5}
        problems = SWAP.validate(p)
        codes = {v.code for v in problems}
        self.assertIn("pattern", codes)    # lowercase symbol
        self.assertIn("minimum", codes)    # negative amount
        self.assertIn("missing", codes)    # token_out absent
        self.assertGreaterEqual(len(problems), 3)

    def test_exclusive_minimum_rejects_zero(self):
        p = self.good()
        p["amount"] = 0
        self.assertIn("minimum", [v.code for v in SWAP.validate(p)])

    def test_maximum(self):
        p = self.good()
        p["amount"] = 10000.01
        self.assertIn("maximum", [v.code for v in SWAP.validate(p)])

    def test_boolean_is_not_an_integer(self):
        """True == 1 in Python. It is not an amount, and it must not pass as one."""
        p = self.good()
        p["amount"] = True
        self.assertIn("type", [v.code for v in SWAP.validate(p)])

    def test_integer_field_rejects_float(self):
        p = self.good()
        p["slippage_bps"] = 12.5
        self.assertIn("type", [v.code for v in SWAP.validate(p)])

    def test_unknown_field_is_a_signal(self):
        p = self.good()
        p["recipient"] = "0x" + "a" * 40
        problems = SWAP.validate(p)
        self.assertEqual([v.code for v in problems], ["unknown_field"])

    def test_non_dict_payload(self):
        self.assertEqual(SWAP.validate(["USDC"])[0].code, "not_an_object")

    def test_raises_with_all_violations(self):
        with self.assertRaises(ValidationError) as ctx:
            SWAP.validate_or_raise({"token_in": "usdc"})
        self.assertGreaterEqual(len(ctx.exception.violations), 2)


class TestNested(unittest.TestCase):
    BATCH = Schema(
        orders=Field.array(
            "Orders to submit together.",
            items=Field.object(
                "One order.",
                properties={
                    "symbol": Field.string("Market symbol."),
                    "qty": Field.number("Quantity.", minimum=0, exclusive_minimum=True,
                                        monetary=True),
                },
            ),
            min_length=1,
            max_length=5,
        ),
    )

    def test_nested_paths_point_at_the_problem(self):
        p = {"orders": [{"symbol": "SOL", "qty": 1},
                        {"symbol": "ETH", "qty": -3}]}
        problems = self.BATCH.validate(p)
        self.assertEqual(len(problems), 1)
        self.assertEqual(problems[0].path, "orders[1].qty")

    def test_nested_unknown_field(self):
        p = {"orders": [{"symbol": "SOL", "qty": 1, "to": "0xdead"}]}
        paths = [v.path for v in self.BATCH.validate(p)]
        self.assertIn("orders[0].to", paths)

    def test_too_many_items(self):
        p = {"orders": [{"symbol": "S", "qty": 1}] * 6}
        self.assertIn("max_items", [v.code for v in self.BATCH.validate(p)])

    def test_item_description_is_nested_in_the_sentence(self):
        d = self.BATCH.to_payload_description()["orders"]["description"]
        self.assertIn("Each item", d)
        self.assertIn("symbol", d)


class TestRedaction(unittest.TestCase):
    S = Schema(
        who=Field.string("Recipient."),
        secret=Field.string("Signing key.", sensitive=True),
    )

    def test_sensitive_values_are_replaced_shape_is_kept(self):
        out = self.S.redact({"who": "alice", "secret": "hunter2"})
        self.assertEqual(out["who"], "alice")
        self.assertEqual(out["secret"], "<redacted>")

    def test_monetary_and_sensitive_lists(self):
        self.assertEqual(SWAP.monetary_fields(), ["amount"])
        self.assertEqual(self.S.sensitive_fields(), ["secret"])


class TestDeclarationErrors(unittest.TestCase):
    def test_bad_type_fails_at_declaration(self):
        with self.assertRaises(ValueError):
            Field(type="decimal", description="x")

    def test_array_needs_items(self):
        with self.assertRaises(ValueError):
            Field(type="array", description="x")

    def test_bad_pattern_fails_at_declaration_not_at_first_call(self):
        with self.assertRaises(Exception):
            Field.string("x", pattern="[unclosed")

    def test_empty_schema_is_refused(self):
        with self.assertRaises(ValueError):
            Schema()


if __name__ == "__main__":
    unittest.main()
