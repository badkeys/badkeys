# SPDX-License-Identifier: MIT
# (c) Hanno Böck
#
# Part of badkeys: https://badkeys.info/

import os
import pathlib
import unittest

import badkeys

TDPATH = os.path.join(os.path.dirname(__file__), "data")


class TestSmalld(unittest.TestCase):

    def test_smalld(self):

        # Use all checks except blocklist to make sure they have no
        # issues with large d RSA values
        mychecks = list(badkeys.allchecks.keys())
        mychecks.remove("blocklist")

        # key with mixed-up d/e values (d=65537)
        key = pathlib.Path(f"{TDPATH}/rsa-small-d.key").read_text()
        r = badkeys.detectandcheck(key, checks=mychecks)
        self.assertTrue("smalld" in r["results"])
        self.assertTrue("rsawarnings" in r["results"])
        self.assertTrue(r["results"]["rsawarnings"]["subtest"] == "exponent_not_65537")

        # key with large e, but otherwise correct (FIPS test vector)
        key = pathlib.Path(f"{TDPATH}/rsa-large-e.key").read_text()
        r = badkeys.detectandcheck(key, checks=mychecks)
        self.assertFalse("smalld" in r["results"])
        self.assertTrue("rsawarnings" in r["results"])
        self.assertTrue(r["results"]["rsawarnings"]["subtest"] == "exponent_not_65537")


if __name__ == "__main__":
    unittest.main()
