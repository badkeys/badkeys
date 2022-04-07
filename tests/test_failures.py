import unittest
import os

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestFailures(unittest.TestCase):
    def test_brokencrt(self):
        brokencrt = "-----BEGIN CERTIFICATE-----\nMII"
        r = badkeys.detectandcheck(brokencrt)
        self.assertEqual(r["type"], "unparseable")

    def test_empty(self):
        r = badkeys.detectandcheck("")
        self.assertEqual(r["type"], "notfound")

    def test_unsupportedssh(self):
        r = badkeys.detectandcheck("ssh-invalid invalid")
        self.assertEqual(r["type"], "unsupported")


if __name__ == "__main__":
    unittest.main()
