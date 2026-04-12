# SPDX-License-Identifier: MIT
# (c) Hanno Böck
#
# Part of badkeys: https://badkeys.info/

import os
import pathlib
import unittest

import badkeys

TDPATH = os.path.join(os.path.dirname(__file__), "data")


class TestRSABias(unittest.TestCase):

    def test_rsabias(self):

        key = pathlib.Path(f"{TDPATH}/rsa-vanity.key").read_text()
        r = badkeys.detectandcheck(key, checks=["rsabias"])
        self.assertTrue("rsabias" in r["results"])
        self.assertTrue(r["results"]["rsabias"]["subtest"] == "vanity")

        key = pathlib.Path(f"{TDPATH}/rsa-ok.key").read_text()
        r = badkeys.detectandcheck(key, checks=["rsabias"])
        self.assertFalse("rsapoly" in r["results"])


if __name__ == "__main__":
    unittest.main()
