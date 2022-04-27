import unittest
import os

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestPattern(unittest.TestCase):
    def test_roca(self):
        with open(f"{TDPATH}rsa-pattern.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["pattern"])
        self.assertTrue("pattern" in r["results"])
        with open(f"{TDPATH}rsa-ok.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["pattern"])
        self.assertFalse(r["results"])


if __name__ == "__main__":
    unittest.main()
