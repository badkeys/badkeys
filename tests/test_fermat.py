import unittest
import os

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestFermat(unittest.TestCase):

    def test_fermat(self):
        # For this test only we are testing several
        # input formats. Also the test keys differ in
        # the distance of the "close" primes to test
        # different rounds of the fermat check.

        with open(f"{TDPATH}rsa-fermat.crt") as f:
            inp = f.read()
        r = badkeys.checkcrt(inp, ["fermat"])
        self.assertTrue("fermat" in r)
        r = badkeys.detectandcheck(inp, ["fermat"])
        self.assertTrue("fermat" in r)

        with open(f"{TDPATH}rsa-fermat.csr") as f:
            inp = f.read()
        r = badkeys.checkcsr(inp, ["fermat"])
        self.assertTrue("fermat" in r)
        r = badkeys.detectandcheck(inp, ["fermat"])
        self.assertTrue("fermat" in r)

        with open(f"{TDPATH}rsa-fermat-pkcs1.key") as f:
            inp = f.read()
        r = badkeys.checkpkey(inp, ["fermat"])
        self.assertTrue("fermat" in r)
        r = badkeys.detectandcheck(inp, ["fermat"])
        self.assertTrue("fermat" in r)

        with open(f"{TDPATH}rsa-fermat-pkcs8.key") as f:
            inp = f.read()
        r = badkeys.checkpkey(inp, ["fermat"])
        self.assertTrue("fermat" in r)
        r = badkeys.detectandcheck(inp, ["fermat"])
        self.assertTrue("fermat" in r)

        with open(f"{TDPATH}rsa-fermat-hexmodulus.txt") as f:
            inp = f.read()
        n = int(inp, 16)
        r = badkeys.checkrsa(["fermat"], n=n)
        self.assertTrue("fermat" in r)
        # check that Fermat factorization works
        p = r['fermat']['p']
        q = r['fermat']['q']
        self.assertEqual(p * q, n)

        with open(f"{TDPATH}rsa-ok.key") as f:
            key = f.read()
        r = badkeys.checkpkey(key, ["fermat"])
        self.assertFalse(r)


if __name__ == '__main__':
    unittest.main()
