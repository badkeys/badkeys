# SPDX-License-Identifier: MIT
# (c) Hanno Böck

import os
import pathlib
import unittest

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestRSAInvalid(unittest.TestCase):
    def test_rsainvalid(self):
        key = pathlib.Path(f"{TDPATH}rsa-e1.key").read_text()
        r = badkeys.checkpubkey(key, checks=["rsainvalid"])
        self.assertEqual(r["type"], "unparseable")

        key = pathlib.Path(f"{TDPATH}rsa-e-larger-n.key").read_text()
        r = badkeys.checkpubkey(key, checks=["rsainvalid"])
        self.assertEqual(r["type"], "unparseable")

        key = pathlib.Path(f"{TDPATH}rsa-ok.key").read_text()
        r = badkeys.checkpubkey(key, checks=["rsainvalid"])
        self.assertFalse(r["results"])


if __name__ == "__main__":
    unittest.main()
