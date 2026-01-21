# SPDX-License-Identifier: MIT
# (c) Hanno Böck

import os
import pathlib
import unittest

from badkeys.checks import checkpubkey
from badkeys.dkim import PUBPRE, parsedkim

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestDkim(unittest.TestCase):

    def test_dkimparser(self):
        # Defect inputs should not return anything, but also should not cause
        # unexpected exceptions
        for dkimbroken in ["dkim-broken-char.txt", "dkim-broken-length.txt"]:
            dkey = pathlib.Path(f"{TDPATH}dkim/{dkimbroken}").read_text(errors="ignore")
            self.assertFalse(parsedkim(dkey))
        # Valid inputs should return PEM public key
        for dkimvalid in ["dkim-valid-gmail.txt", "dkim-insecure-rfc8463.txt",
                          "dkim-escaped-quote.txt"]:
            dkey = pathlib.Path(f"{TDPATH}dkim/{dkimvalid}").read_text()
            self.assertTrue(parsedkim(dkey).startswith(PUBPRE))

    @unittest.skipUnless(os.environ.get("RUN_ONLINETESTS"), "Skipping blocklist tests")
    def test_dkimscan(self):
        dkey = pathlib.Path(f"{TDPATH}dkim/dkim-valid-gmail.txt").read_text()
        ret = checkpubkey(parsedkim(dkey))
        self.assertFalse(ret["results"])

        dkey = pathlib.Path(f"{TDPATH}dkim/dkim-insecure-rfc8463.txt").read_text()
        ret = checkpubkey(parsedkim(dkey))
        self.assertTrue("blocklist" in ret["results"])

        dkey = pathlib.Path(f"{TDPATH}dkim/dkim-escaped-quote.txt").read_text()
        ret = checkpubkey(parsedkim(dkey))
        self.assertTrue("blocklist" in ret["results"])


if __name__ == "__main__":
    unittest.main()
