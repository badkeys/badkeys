import unittest
import os

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestSmallprimes(unittest.TestCase):
    def test_smallprimes(self):
        with open(f"{TDPATH}rsa-e1.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["rsainvalid"])
        self.assertTrue("rsainvalid" in r["results"])
        self.assertEqual("invalid_e", r["results"]["rsainvalid"]["subtest"])

        with open(f"{TDPATH}rsa-nprime.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["rsainvalid"])
        self.assertTrue("rsainvalid" in r["results"])
        self.assertEqual("prime_n", r["results"]["rsainvalid"]["subtest"])

        with open(f"{TDPATH}rsa-ok.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["rsainvalid"])
        self.assertFalse(r["results"])


if __name__ == "__main__":
    unittest.main()
