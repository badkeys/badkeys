import os
import pathlib
import unittest

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestSmallprimes(unittest.TestCase):
    def test_smallprimes_valid(self):
        key = pathlib.Path(f"{TDPATH}rsa-smallfactors-valid.key").read_text()
        r = badkeys.checkpubkey(key, checks=["smallfactors"])
        self.assertTrue("smallfactors" in r["results"])
        self.assertEqual(r["results"]["smallfactors"]["subtest"], "valid")

    def test_smallprimes_corrupt(self):
        key = pathlib.Path(f"{TDPATH}rsa-smallfactors-corrupt.key").read_text()
        r = badkeys.checkpubkey(key, checks=["smallfactors"])
        self.assertTrue("smallfactors" in r["results"])
        self.assertEqual(r["results"]["smallfactors"]["subtest"], "corrupt")

    def test_smallprimes_nofinding(self):
        key = pathlib.Path(f"{TDPATH}rsa-ok.key").read_text()
        r = badkeys.checkpubkey(key, checks=["smallfactors"])
        self.assertFalse(r["results"])


if __name__ == "__main__":
    unittest.main()
