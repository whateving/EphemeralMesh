"""Run the regression suite without consuming real invitations or printing credentials."""
from pathlib import Path
import unittest

if __name__ == '__main__':
    # Tests create isolated temporary profiles and databases, leaving user data untouched.
    suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent / 'tests'))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
