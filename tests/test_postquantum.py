# SPDX-License-Identifier: MIT
# (c) Hanno Böck
#
# Part of badkeys: https://badkeys.info/

import os
import pathlib
import unittest

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestBlocklist(unittest.TestCase):

    # Test keys in post-quantum formats (ML-DSA/ML-KEM),
    # only parsing, no checks enabled.
    def test_postquantum(self):
        key = pathlib.Path(f"{TDPATH}mldsa44.key").read_text()
        r = badkeys.detectandcheck(key, checks=[])
        self.assertTrue(r["type"] == "mldsa44")
        key = pathlib.Path(f"{TDPATH}mlkem768-private.key").read_text()
        r = badkeys.detectandcheck(key, checks=[])
        self.assertTrue(r["type"] == "mlkem768")
        key = pathlib.Path(f"{TDPATH}mldsa65-cert.crt").read_text()
        r = badkeys.detectandcheck(key, checks=[])
        self.assertTrue(r["type"] == "mldsa65")


if __name__ == "__main__":
    unittest.main()
