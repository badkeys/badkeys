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

    @unittest.skipUnless(os.environ.get("RUN_ONLINETESTS"), "Skipping blocklist tests")
    def test_rsabl(self):
        key = pathlib.Path(f"{TDPATH}rsa-debianweak.key").read_text()
        r = badkeys.checkpubkey(key, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        self.assertTrue(r["bits"] == 2048)
        key = pathlib.Path(f"{TDPATH}rsa-ok.key").read_text()
        r = badkeys.checkpubkey(key, checks=["blocklist"])
        self.assertFalse(r["results"])
        self.assertTrue(r["bits"] == 2048)

    @unittest.skipUnless(os.environ.get("RUN_ONLINETESTS"), "Skipping blocklist tests")
    def test_ecbl(self):
        key = pathlib.Path(f"{TDPATH}ec-p256-rfc-example.key").read_text()
        r = badkeys.checkpubkey(key, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        self.assertTrue(r["curve"] == "p256")
        key = pathlib.Path(f"{TDPATH}ed25519-rfc-example.key").read_text()
        r = badkeys.checkpubkey(key, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        self.assertTrue(r["curve"] == "ed25519")
        key = pathlib.Path(f"{TDPATH}x448-ok.key").read_text()
        r = badkeys.checkpubkey(key, checks=["blocklist"])
        self.assertFalse(r["results"])
        self.assertTrue(r["curve"] == "x448")
        # RFC example ECDSA key with explicit curve encoding
        key = pathlib.Path(f"{TDPATH}ecdsa-explicit-pub.key").read_text()
        r = badkeys.checkpubkey(key, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        self.assertTrue(r["results"]["blocklist"]["subtest"] == "rfc")
        self.assertTrue(r["curve"] == "p256")

    # Testing key in SSH DSA pubkey format.
    # Python cryptography plans to deprecate this format,
    # we will need to find a solution.
    @unittest.skipUnless(os.environ.get("RUN_ONLINETESTS"), "Skipping blocklist tests")
    def test_dsabl(self):
        key = pathlib.Path(f"{TDPATH}dsa-sshpub-ietf-example.key").read_text()
        r = badkeys.checksshpubkey(key, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        self.assertTrue(r["bits"] == 1024)

    # Test keys in post-quantum formats (ML-DSA/ML-KEM)
    @unittest.skipUnless(os.environ.get("RUN_ONLINETESTS"), "Skipping blocklist tests")
    def test_postquantumbl(self):
        key = pathlib.Path(f"{TDPATH}mldsa44.key").read_text()
        r = badkeys.checkpubkey(key, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        self.assertTrue(r["results"]["blocklist"]["subtest"] == "rfc")
        self.assertTrue(r["type"] == "mldsa44")
        key = pathlib.Path(f"{TDPATH}mlkem768-private.key").read_text()
        r = badkeys.checkprivkey(key, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        self.assertTrue(r["results"]["blocklist"]["subtest"] == "rfc")
        self.assertTrue(r["type"] == "mlkem768")
        key = pathlib.Path(f"{TDPATH}mldsa65-cert.crt").read_text()
        r = badkeys.checkcrt(key, checks=["blocklist"])
        self.assertTrue("blocklist" not in r["results"])
        self.assertTrue(r["type"] == "mldsa65")


if __name__ == "__main__":
    unittest.main()
