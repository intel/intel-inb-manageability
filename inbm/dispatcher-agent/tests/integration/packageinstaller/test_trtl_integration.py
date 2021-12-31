import unittest
from unittest import TestCase

from inbm_common_lib.shell_runner import PseudoShellRunner


class TestTrtlIntegration(TestCase):

    def test_no_shell_runner_return_code_integration(self):
        (out, err, code) = PseudoShellRunner().run("false")
        self.assertEqual(1, code)


if __name__ == '__main__':
    unittest.main()
