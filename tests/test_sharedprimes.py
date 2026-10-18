import os
import pathlib
import unittest

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestSharedprimes(unittest.TestCase):
    def test_sharedprimes(self):
        key = pathlib.Path(f"{TDPATH}rsa-sharedprimes.key").read_text()
        r = badkeys.checkpubkey(key, checks=["sharedprimes"])
        self.assertTrue("sharedprimes" in r["results"])
        self.assertTrue(r["bits"] == 2048)
        key = pathlib.Path(f"{TDPATH}rsa-ok.key").read_text()
        r = badkeys.checkpubkey(key, checks=["sharedprimes"])
        self.assertFalse(r["results"])
        self.assertTrue(r["bits"] == 2048)


if __name__ == "__main__":
    unittest.main()
