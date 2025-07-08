# Tests for bugs in past versions of badkeys

import os
import pathlib
import unittest

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestRegressions(unittest.TestCase):
    def test_rsanzero(self):
        # Regression test for https://github.com/badkeys/badkeys/issues/31
        key = pathlib.Path(f"{TDPATH}rsazerozero.key").read_text()
        r = badkeys.checkpubkey(key, checks=["xzbackdoor"])
        self.assertFalse(r["results"])
        key = pathlib.Path(f"{TDPATH}rsanzero.key").read_text()
        r = badkeys.checkpubkey(key, checks=["xzbackdoor"])
        self.assertFalse(r["results"])


if __name__ == "__main__":
    unittest.main()
