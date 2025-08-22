import os
import pathlib
import unittest

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestDnssec(unittest.TestCase):

    @unittest.skipUnless(os.environ.get("RUN_ONLINETESTS"), "Skipping blocklist tests")
    def test_dnssecbl(self):
        key = pathlib.Path(f"{TDPATH}dnssec-p256-rfc6605.dnskey").read_text()
        r = badkeys.checkdnskey(key, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        self.assertTrue(r["type"] == "ec")
        self.assertTrue(r["curve"] == "p256")

        key = pathlib.Path(f"{TDPATH}dnssec-root-rsa.dnskey").read_text()
        r = badkeys.checkdnskey(key, checks=["blocklist"])
        self.assertFalse("blocklist" in r["results"])
        self.assertTrue(r["type"] == "rsa")
        self.assertTrue(r["bits"] == 2048)

    def test_dnssec(self):
        key = pathlib.Path(f"{TDPATH}dnssec-p256-rfc6605.dnskey").read_text()
        r = badkeys.checkdnskey(key, checks=["roca", "pattern", "sharedprimes", "fermat"])
        self.assertFalse(r["results"])
        self.assertTrue(r["type"] == "ec")
        self.assertTrue(r["curve"] == "p256")

        key = pathlib.Path(f"{TDPATH}dnssec-root-rsa.dnskey").read_text()
        r = badkeys.checkdnskey(key, checks=["roca", "pattern", "sharedprimes", "fermat"])
        self.assertFalse(r["results"])
        self.assertTrue(r["type"] == "rsa")
        self.assertTrue(r["bits"] == 2048)


if __name__ == "__main__":
    unittest.main()
