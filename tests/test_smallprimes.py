import unittest
import os

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestSmallprimes(unittest.TestCase):

    def test_smallprimes(self):
        with open(f"{TDPATH}rsa-smallfactors.key") as f:
            key = f.read()
        r = badkeys.checkpkey(key, ["smallfactors"])
        self.assertTrue("smallfactors" in r)
        with open(f"{TDPATH}rsa-ok.key") as f:
            key = f.read()
        r = badkeys.checkpkey(key, ["smallfactors"])
        self.assertFalse(r)


if __name__ == '__main__':
    unittest.main()
