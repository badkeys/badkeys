# SPDX-License-Identifier: MIT
# (c) Hanno Böck
#
# Part of badkeys: https://badkeys.info/

import os
import pathlib
import unittest

import badkeys

TDPATH = os.path.join(os.path.dirname(__file__), "data")


class TestRSAPoly(unittest.TestCase):

    def test_rsapoly(self):

        key = pathlib.Path(f"{TDPATH}/rsapoly128.key").read_text()
        r = badkeys.detectandcheck(key, checks=["rsapoly"])
        self.assertTrue("rsapoly" in r["results"])
        self.assertTrue(r["results"]["rsapoly"]["subtest"] == "nautilus")

        key = pathlib.Path(f"{TDPATH}/rsapoly32.key").read_text()
        r = badkeys.detectandcheck(key, checks=["rsapoly"])
        self.assertTrue("rsapoly" in r["results"])
        self.assertTrue(r["results"]["rsapoly"]["subtest"] == "centipede")

        key = pathlib.Path(f"{TDPATH}/rsa-ok.key").read_text()
        r = badkeys.detectandcheck(key, checks=["rsapoly"])
        self.assertFalse("rsapoly" in r["results"])


if __name__ == "__main__":
    unittest.main()
