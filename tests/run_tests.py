#!/usr/bin/env python3
"""Discover and run Sentry's unit test suite.

    python3 tests/run_tests.py            # normal
    python3 run_tests.py -q         # quiet
    python3 run_tests.py -k pattern # only tests whose name matches

Exits non-zero if anything fails or errors. Unexpected successes (a test
marked @unittest.expectedFailure that starts passing) also fail the run, so a
bug fix cannot silently leave a stale marker behind.
"""
from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path

# This runner lives in tests/, so the project root is one level up.
TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-q", "--quiet", action="store_true",
                       help="one character per test instead of one line")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="one line per test (the default)")
    parser.add_argument("-k", "--pattern", action="append", default=[],
                       metavar="SUBSTRING",
                       help="only run tests whose full name contains this")
    parser.add_argument("-f", "--failfast", action="store_true",
                       help="stop at the first failure")
    args = parser.parse_args(argv)

    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    if not TESTS.is_dir():
        print(f"no tests directory at {TESTS}", file=sys.stderr)
        return 2

    loader = unittest.TestLoader()
    if args.pattern:
        loader.testNamePatterns = [p if "*" in p else f"*{p}*"
                                   for p in args.pattern]
    suite = loader.discover(start_dir=str(TESTS), top_level_dir=str(ROOT))

    if loader.errors:
        for err in loader.errors:
            print(err, file=sys.stderr)
        return 2

    verbosity = 1 if args.quiet else 2
    runner = unittest.TextTestRunner(verbosity=verbosity,
                                     failfast=args.failfast,
                                     buffer=False)
    result = runner.run(suite)

    total = result.testsRun
    failed = len(result.failures)
    errored = len(result.errors)
    skipped = len(result.skipped)
    xfail = len(result.expectedFailures)
    xpass = len(result.unexpectedSuccesses)

    print()
    print(f"  {total} tests: {total - failed - errored - skipped - xfail - xpass}"
          f" passed, {failed} failed, {errored} errors,"
          f" {skipped} skipped, {xfail} known bugs (expected failures),"
          f" {xpass} unexpected successes")
    if xfail:
        print("\n  Known bugs still reproducing (expected failures):")
        for test, _tb in result.expectedFailures:
            print(f"    - {test.id()}")
    if xpass:
        print("\n  These are marked as known bugs but PASSED -- if the bug was"
              "\n  fixed, remove the @unittest.expectedFailure marker:")
        for test in result.unexpectedSuccesses:
            print(f"    - {test.id()}")

    return 0 if result.wasSuccessful() and not xpass else 1


if __name__ == "__main__":
    raise SystemExit(main())
