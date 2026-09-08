# -*- coding: utf-8 -*-
"""A pattern that cannot fire looks exactly like one that can.

This is the permanent form of a defect found on 08.09.2026: the send-verb
pattern's Chinese alternatives had never once matched, because `\b` cannot mark
a boundary between two CJK characters. The Latin half kept matching all day, so
the suite stayed green and the pattern looked alive.

No assertion about a verdict can catch that. A test says "this text is
CRITICAL", the pattern delivers CRITICAL through *some* branch, and nobody
learns which branch carried it. The working half is the alibi of the broken
half.

So this file does not test the scanner. It tests that every alternative in
every single-alternation pattern is reachable at all.
"""
import os
import sys
import unittest

HIER = os.path.dirname(os.path.abspath(__file__))
WURZEL = os.path.dirname(HIER)
sys.path.insert(0, WURZEL)
sys.path.insert(0, os.path.join(WURZEL, "tools"))

import re  # noqa: E402

from boundary_check import pruefe, selbsttest  # noqa: E402
from alternative_coverage import patterns_of_module, sammle_korpus  # noqa: E402

import unifai_guard.scanner as sc  # noqa: E402


class TestNoBranchIsLockedOutByItsBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.korpus = sammle_korpus()

    def test_the_checker_catches_the_defect_it_was_written_for(self):
        """A green checker proves nothing until it has been seen failing.

        This rebuilds the pattern as it stood before the fix and asserts the
        check fires on it. If this test ever passes while the next one is
        vacuous, the suite is lying to itself.
        """
        self.assertTrue(selbsttest(self.korpus),
                        "the boundary checker no longer detects its own origin case")

    def test_no_alternative_is_unreachable_through_its_boundary(self):
        schuldig = []
        for name, pat in patterns_of_module(sc):
            aus, _nie, ok = pruefe(pat, self.korpus)
            if ok and aus:
                schuldig.append("%s: %s" % (name, ", ".join(aus)))
        self.assertEqual(schuldig, [],
                         "branches whose text is reachable but whose word "
                         "boundary blocks the match:\n  " + "\n  ".join(schuldig))

    def test_the_chinese_send_verbs_actually_fire(self):
        """The specific regression, named, so it cannot come back quietly."""
        for verb in ("发送", "上传", "转发"):
            text = "将余额" + verb + "到该地址"
            self.assertIsNotNone(sc._EXFIL_VERB.search(text),
                                 "send verb %s does not match in running Chinese" % verb)

    def test_the_boundary_still_blocks_partial_latin_words(self):
        """What \b was there for must survive its replacement."""
        self.assertIsNotNone(sc._EXFIL_VERB.search("please enviar el saldo"))
        self.assertIsNone(sc._EXFIL_VERB.search("para reenviarlo pronto"))


if __name__ == "__main__":
    unittest.main()
