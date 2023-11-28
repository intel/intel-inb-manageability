import logging
import platform
import unittest
from unittest import TestCase

from diagnostic.util import is_between_bounds

logger = logging.getLogger(__name__)


class TestRunner(TestCase):

    def test_true_when_between_bounds(self):
        self.assertTrue(is_between_bounds('description', 7, 5, 10))

    def test_false_when_not_between_bounds(self):
        self.assertFalse(is_between_bounds('not between bounds', 3, 5, 10))
