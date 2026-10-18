import os
import pathlib
import unittest

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestPattern(unittest.TestCase):
    def test_roca(self):
        key = pathlib.Path(f"{TDPATH}rsa-pattern.key").read_text()
        r = badkeys.checkpubkey(key, checks=["pattern"])
        self.assertTrue("pattern" in r["results"])
        key = pathlib.Path(f"{TDPATH}rsa-ok.key").read_text()
        r = badkeys.checkpubkey(key, checks=["pattern"])
        self.assertFalse(r["results"])


if __name__ == "__main__":
    unittest.main()
