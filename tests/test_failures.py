import os
import pathlib
import unittest

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestFailures(unittest.TestCase):
    def test_brokencrt(self):
        brokencrt = "-----BEGIN CERTIFICATE-----\nMII"
        r = badkeys.detectandcheck(brokencrt)
        self.assertEqual(r["type"], "unparseable")

    def test_brokencsr(self):
        brokencsr = "-----BEGIN CERTIFICATE REQUEST-----\nMII"
        r = badkeys.detectandcheck(brokencsr)
        self.assertEqual(r["type"], "unparseable")

    def test_empty(self):
        r = badkeys.detectandcheck("")
        self.assertEqual(r["type"], "notfound")

    def test_unsupportedssh(self):
        r = badkeys.detectandcheck("ssh-invalid invalid")
        self.assertEqual(r["type"], "unsupported")

    def test_defect(self):
        indir = os.path.join(TDPATH, "defect")
        for fn in os.listdir(indir):
            indata = pathlib.Path(os.path.join(indir, fn)).read_text()
            r = badkeys.detectandcheck(indata)
            self.assertEqual(r["type"], "unparseable")

    def test_unsupported(self):
        indir = os.path.join(TDPATH, "unsupported")
        for fn in os.listdir(indir):
            indata = pathlib.Path(os.path.join(indir, fn)).read_text()
            r = badkeys.detectandcheck(indata)
            # some "unsupported" inputs return "unparseable" due to
            # cryptography's API behavior
            self.assertIn(r["type"], ["unparseable", "unsupported"])


if __name__ == "__main__":
    unittest.main()
