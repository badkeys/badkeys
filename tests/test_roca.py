import os
import pathlib
import unittest

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestRoca(unittest.TestCase):
    def test_roca(self):
        key = pathlib.Path(f"{TDPATH}rsa-roca.key").read_text()
        r = badkeys.checkpubkey(key, checks=["roca"])
        self.assertTrue("roca" in r["results"])
        self.assertTrue(r["bits"] == 2048)
        key = pathlib.Path(f"{TDPATH}rsa-ok.key").read_text()
        r = badkeys.checkpubkey(key, checks=["roca"])
        self.assertFalse(r["results"])
        self.assertTrue(r["bits"] == 2048)


if __name__ == "__main__":
    unittest.main()
