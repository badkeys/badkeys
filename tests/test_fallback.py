# SPDX-License-Identifier: MIT
# (c) Hanno Böck
#
# Part of badkeys: https://badkeys.info/

import os
import pathlib
import unittest

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestFallback(unittest.TestCase):
    def test_invalidver(self):
        crt = pathlib.Path(f"{TDPATH}fallback/invalidver.crt").read_text()
        ret = badkeys.checkcrt(crt, checks=["roca", "rsabias", "sharedprimes", "fermat"])
        self.assertEqual(ret["type"], "ec")

    def test_ecdsaparam(self):
        # ECDSA signature with an invalid NULL parameter
        crt = pathlib.Path(f"{TDPATH}fallback/rsa-fido.crt").read_text()
        ret = badkeys.checkcrt(crt, checks=["roca", "rsabias", "sharedprimes", "fermat"])
        self.assertEqual(ret["type"], "ec")

    def test_pubex(self):
        # Python cryptography is able to load this cert, but fails
        # extracting the public key
        crt = pathlib.Path(f"{TDPATH}fallback/rootagency.crt").read_text()
        ret = badkeys.checkcrt(crt, checks=["roca", "rsabias", "sharedprimes", "fermat"])
        self.assertEqual(ret["type"], "rsa")


if __name__ == "__main__":
    unittest.main()
