import unittest
from unittest import TestCase

from dispatcher.packagemanager.memory_repo import MemoryRepo


class TestMemoryRepo(TestCase):

    def test_blank_repo(self):
        repo = MemoryRepo("test")

        self.assertEqual(0, len(repo.list()))

    def test_get_blank_repo(self):
        repo = MemoryRepo("test")

        with self.assertRaises(KeyError):
            repo.get("anything")

    def test_add_one_item(self):
        repo = MemoryRepo("test")

        repo.add("foo", b"contents")

        self.assertEqual(1, len(repo.list()))

    def test_add_retrieve_one_item(self):
        repo = MemoryRepo("test")
        contents = b"contents2"
        name = "foo2"

        repo.add(name, contents)

        self.assertEqual(contents, repo.get(name))

    def test_add_two_items(self):
        repo = MemoryRepo("test")

        repo.add("foo3", b"contents3")
        repo.add("foo4", b"contents4")

        self.assertEqual(2, len(repo.list()))

    def test_retrieve_with_two_items(self):
        repo = MemoryRepo("test")
        contents = b"contents3"
        name = "foo3"

        repo.add(name, contents)
        repo.add("foo4", b"contents4")

        self.assertEqual(contents, repo.get(name))

    def test_exists(self):
        repo = MemoryRepo("test")
        self.assertTrue(repo.exists())

    def test_id(self):
        repo = MemoryRepo("bar")
        self.assertEqual("bar", repo.name())

        repo2 = MemoryRepo("test")
        self.assertEqual("test", repo2.name())


if __name__ == '__main__':
    unittest.main()
