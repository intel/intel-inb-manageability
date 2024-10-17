import os
import unittest
import hashlib
import tempfile
import shutil

from dispatcher.packagemanager.local_repo import DirectoryRepo
from dispatcher.sota.update_tool_util import update_tool_write_command
from dispatcher.sota.constants import TIBER_UPDATE_TOOL_PATH


class TestDownloader(unittest.TestCase):

    def test_update_tool_write_command_return_file_path(self) -> None:

        directory = tempfile.mkdtemp()
        try:
            repo = DirectoryRepo(directory)
            repo.add("test", b"This is a test file.")

            # Calculate the SHA256 checksum
            sha256_hash = hashlib.sha256()
            file_path = os.path.join(directory, "test")
            with open(file_path, 'rb') as file:
                for chunk in iter(lambda: file.read(4096), b''):
                    sha256_hash.update(chunk)
            checksum = sha256_hash.hexdigest()

            expected_cmd = f'{TIBER_UPDATE_TOOL_PATH} -w -u {os.path.join(repo.get_repo_path(), "test")}'
            cmd = update_tool_write_command(signature=checksum, file_path=file_path)
            self.assertEqual(cmd, expected_cmd)
        finally:
            shutil.rmtree(directory)
