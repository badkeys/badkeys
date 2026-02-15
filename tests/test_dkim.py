# SPDX-License-Identifier: MIT
# (c) Hanno Böck

import os
import pathlib
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from badkeys.checks import _checkkey, allchecks
from badkeys.dkim import parsedkim

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestDkim(unittest.TestCase):

    def test_dkimparser(self):
        # Defect inputs should not return anything, but also should not cause
        # unexpected exceptions
        for dkimbroken in ["dkim-broken-char.txt", "dkim-broken-length.txt"]:
            dkey = pathlib.Path(f"{TDPATH}dkim/{dkimbroken}").read_text(errors="ignore")
            self.assertTrue(isinstance(parsedkim(dkey), str))
        # Valid inputs should return PEM public key
        for dkimvalid in ["dkim-valid-gmail.txt", "dkim-insecure-rfc8463.txt",
                          "dkim-escaped-quote.txt", "dkim-comment-quotes.txt"]:
            dkey = pathlib.Path(f"{TDPATH}dkim/{dkimvalid}").read_text()
            parsedkey = parsedkim(dkey)
            self.assertTrue(isinstance(parsedkey, (ed25519.Ed25519PublicKey, rsa.RSAPublicKey)))

    @unittest.skipUnless(os.environ.get("RUN_ONLINETESTS"), "Skipping blocklist tests")
    def test_dkimscan(self):
        dkey = pathlib.Path(f"{TDPATH}dkim/dkim-valid-gmail.txt").read_text()
        ret = _checkkey(parsedkim(dkey), checks=allchecks)
        self.assertFalse(ret["results"])

        for dkimbl in ["dkim-insecure-rfc8463.txt", "dkim-escaped-quote.txt",
                       "dkim-comment-quotes.txt"]:
            dkey = pathlib.Path(f"{TDPATH}dkim/{dkimbl}").read_text()
            ret = _checkkey(parsedkim(dkey), checks=allchecks)
            self.assertTrue("blocklist" in ret["results"])


if __name__ == "__main__":
    unittest.main()
