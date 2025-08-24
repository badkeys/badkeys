import json
import os
import pathlib
import unittest

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestJwk(unittest.TestCase):

    @unittest.skipUnless(os.environ.get("RUN_ONLINETESTS"), "Skipping blocklist tests")
    def test_jwkbl(self):
        jkey = json.loads(pathlib.Path(f"{TDPATH}jwk-ecp256-rfc7517.json").read_text())
        r = badkeys.checkjwk(jkey, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        self.assertTrue(r["type"] == "ec")
        self.assertTrue(r["curve"] == "p256")

        jkey = json.loads(pathlib.Path(f"{TDPATH}jwk-rsa-rfc7517.json").read_text())
        r = badkeys.checkjwk(jkey, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        self.assertTrue(r["type"] == "rsa")
        self.assertTrue(r["bits"] == 2048)

        jkey = json.loads(pathlib.Path(f"{TDPATH}jwk-ed25519-rfc8037.json").read_text())
        r = badkeys.checkjwk(jkey, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        self.assertTrue(r["type"] == "ec")
        self.assertTrue(r["curve"] == "ed25519")

    def test_jwk(self):
        jkey = json.loads(pathlib.Path(f"{TDPATH}jwk-rsa-ok.json").read_text())
        r = badkeys.checkjwk(jkey, checks=["roca", "pattern", "sharedprimes", "fermat"])
        self.assertFalse(r["results"])
        self.assertTrue(r["type"] == "rsa")
        self.assertTrue(r["bits"] == 2048)


if __name__ == "__main__":
    unittest.main()
