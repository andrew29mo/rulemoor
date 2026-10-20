import sys
import time
import unittest
from tools.process import run
from rulemoor.cli import request


class ProcessTests(unittest.TestCase):
    def test_nonzero_is_failure(self):
        result = run([sys.executable, '-c', 'raise SystemExit(7)'], timeout=2)
        self.assertFalse(result['passed'])
        self.assertEqual(result['exit_code'], 7)
    def test_timeout_is_failure(self):
        began = time.monotonic()
        result = run([sys.executable, '-c', 'import time; time.sleep(20)'], timeout=.1)
        self.assertTrue(result['timed_out'])
        self.assertFalse(result['passed'])
        self.assertLess(time.monotonic() - began, 3)
    def test_success(self):
        self.assertTrue(run([sys.executable, '-c', 'print(1)'], timeout=2)['passed'])
    def test_cli_refuses_plaintext(self):
        with self.assertRaises(ValueError): request('http://localhost', 'unused', 'unused', '/status')
