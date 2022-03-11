import unittest
import os

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestRsabl(unittest.TestCase):

    def test_rsabl(self):
        with open(f"{TDPATH}rsa-debianweak.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["rsabl"])
        self.assertTrue("rsabl" in r["results"])
        with open(f"{TDPATH}rsa-ok.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["rsabl"])
        self.assertFalse(r["results"])


if __name__ == '__main__':
    unittest.main()
