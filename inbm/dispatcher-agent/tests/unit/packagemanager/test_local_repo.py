import unittest
from unittest import TestCase

from dispatcher.packagemanager.memory_repo import MemoryRepo


class TestLocalRepo(TestCase):

    def test_hash_finder(self) -> None:
        repo = MemoryRepo("test_hash_finder")
        contents = b"0123456789"
        repo.add("test.rpm", contents)
        self.assertEqual(contents, repo.get("test.rpm"))
        repo.add("test2.rpm", b"13531")
        self.assertEqual(["test.rpm", "test2.rpm"], repo.list())

        repo.delete("test.rpm")
        self.assertFalse("test.rpm" in repo.list())
        repo.delete("test2.rpm")
        self.assertTrue(repo.list() == [])

        # delete a non-existing file should not raise an exception
        repo.delete("test1.rpm")


if __name__ == '__main__':
    unittest.main()
