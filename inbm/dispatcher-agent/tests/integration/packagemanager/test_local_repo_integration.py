import os
import tempfile
import unittest
from unittest import TestCase

from dispatcher.packagemanager.local_repo import DirectoryRepo


class TestLocalRepo(TestCase):

    def test_filesystem_repo_add_integration(self):
        directory = tempfile.mkdtemp()
        repo = DirectoryRepo(directory)

        repo.add("hello.txt", b"hello world")

        with open(os.path.join(directory, "hello.txt"), "rb") as hello:
            text = hello.read()
        self.assertEquals(b"hello world", text)

    def test_filesystem_repo_get_integration(self):
        directory = tempfile.mkdtemp()
        repo = DirectoryRepo(directory)

        repo.add("hello.txt", b"hello world")

        self.assertEquals(b"hello world", repo.get("hello.txt"))

    def test_filesystem_repo_list_integration(self):
        directory = tempfile.mkdtemp()
        repo = DirectoryRepo(directory)

        repo.add("hello.txt", b"hello world")
        repo.add("hello2.txt", b"hello world 2")
        repo2 = DirectoryRepo(directory)

        self.assertEquals({"hello.txt", "hello2.txt"}, set(repo2.list()))

    def test_filesystem_repo_exists_integration(self):
        directory = tempfile.mkdtemp()
        repo = DirectoryRepo(directory)
        self.assertTrue(repo.exists())
        os.rmdir(directory)
        self.assertFalse(repo.exists())
        self.assertEqual(directory, repo.name())


if __name__ == '__main__':
    unittest.main()
