import datetime
from mock import patch
from unittest import TestCase

from inbm_vision_lib.utility import get_file_path_from_manifest, build_file_path_list, \
    move_flashless_files, create_date


MANIFEST_XML = '<?xml version="1.0" encoding="utf-8"?> <manifest><type>ota</type>     ' \
    '<ota><header><id>sampleId</id><name>Sample FOTA</name>       ' \
    '<description>Sample FOTA manifest file</description><type>fota</type><repo>local</repo></header>' \
    '<type><fota name="sample"><targetType>node</targetType><targets><target>123ABC</target></targets>' \
    '<biosversion>5.12</biosversion><vendor>American Megatrends Inc.</vendor><manufacturer>' \
    'Default string</manufacturer><product>Default string</product><releasedate>2018-03-30</releasedate>'\
    '<path>/var/cache/manageability/X041_BIOS.tar</path></fota></type></ota> </manifest>'


class TestUtility(TestCase):

    def test_get_file_path_from_manifest(self):
        self.assertEqual('/var/cache/manageability/X041_BIOS.tar',
                         get_file_path_from_manifest(MANIFEST_XML))

    def test_build_file_path_list_with_one(self):
        parsed_params = ({'repo': 'local',
                          'ota': 'fota',
                          'path': '/var/cache/manageability/X041_BIOS.tar',
                          'biosversion': '5.12',
                          'vendor': 'Intel',
                          'manufacturer': 'Intel',
                          'product': 'KMB',
                          'releasedate': '2020-10-21',
                          'release_date': '2020-10-21',
                          'cmd': 'update',
                          'logtofile': 'y',
                          'signature': 'Default string'})

        file_paths = build_file_path_list(parsed_params)
        self.assertEqual(len(file_paths), 1)
        self.assertEqual(file_paths[0], '/var/cache/manageability/X041_BIOS.tar')

    def test_build_file_path_list_with_two(self):
        parsed_params = ({'repo': 'local',
                          'ota': 'fota',
                          'fota_path': '/var/cache/manageability/X041_BIOS.tar',
                          'sota_path': '/var/cache/manageability/file.mender',
                          'biosversion': '5.12',
                          'vendor': 'Intel',
                          'manufacturer': 'Intel',
                          'product': 'KMB',
                          'releasedate': '2020-10-21',
                          'release_date': '2020-10-21',
                          'cmd': 'update',
                          'logtofile': 'y',
                          'signature': 'Default string'})
        file_paths = build_file_path_list(parsed_params)
        self.assertEqual(len(file_paths), 2)
        self.assertEqual(file_paths[0], '/var/cache/manageability/X041_BIOS.tar')
        self.assertEqual(file_paths[1], '/var/cache/manageability/file.mender')

    def test_build_file_path_raises_missing_pota_file(self):
        parsed_params = ({'repo': 'local',
                          'ota': 'fota',
                          'fota_path': '/var/cache/manageability/X041_BIOS.tar',
                          'biosversion': '5.12',
                          'vendor': 'Intel',
                          'manufacturer': 'Intel',
                          'product': 'KMB',
                          'releasedate': '2020-10-21',
                          'release_date': '2020-10-21',
                          'cmd': 'update',
                          'logtofile': 'y',
                          'signature': 'Default string'})
        self.assertRaises(FileNotFoundError, build_file_path_list, parsed_params)

    @patch('glob.glob', return_value=["core-image-ese-initramfs-base-thunderbay-20201213181419.cpio.gz.u-boot"])
    @patch('os.rename')
    @patch('os.path.exists', return_value=True)
    @patch("pathlib.Path.unlink", return_value=True)
    @patch("tarfile.open")
    @patch("pathlib.Path.is_file", return_value=True)
    def test_move_flashless_files(self, is_file, mock_open, unlink, mock_exists, mock_rename, glob):
        move_flashless_files('/var/cache/manageability/X041_BIOS.tar', '/lib/firmware')
        is_file.assert_called()
        mock_open.assert_called()
        mock_rename.assert_called()
        glob.assert_called()

    @patch("inbm_vision_lib.utility.remove_file")
    @patch('os.path.exists', return_value=True)
    @patch("pathlib.Path.unlink", return_value=True)
    @patch("tarfile.open")
    @patch("pathlib.Path.is_file", return_value=True)
    def test_move_flashless_files_raise_error_no_rootfs_file(self, is_file, mock_open, unlink, mock_exists, remove):
        with self.assertRaises(FileNotFoundError):
            move_flashless_files('/var/cache/manageability/X041_BIOS.tar', '/lib/firmware')
        is_file.assert_called()
        mock_open.assert_called()
        remove.assert_called()

    @patch("inbm_vision_lib.utility.remove_file")
    @patch('os.rename', side_effect=FileNotFoundError())
    @patch('glob.glob', return_value=["core-image-ese-initramfs-base-thunderbay-20201213181419.cpio.gz.u-boot"])
    @patch('os.path.exists', return_value=True)
    @patch("pathlib.Path.unlink", return_value=True)
    @patch("tarfile.open")
    @patch("pathlib.Path.is_file", return_value=True)
    def test_move_flashless_files_raise_error_no_fip_no_img_file(self, is_file, mock_open, unlink, mock_exists, glob, mock_rename, remove):
        with self.assertRaises(FileNotFoundError):
            move_flashless_files('/var/cache/manageability/X041_BIOS.tar', '/lib/firmware')
        is_file.assert_called()
        mock_open.assert_called()
        mock_rename.assert_called()
        remove.assert_called()

    def test_create_date(self):
        self.assertEqual(create_date(datetime.datetime(2020, 12, 30)), "12-30-2020 00:00:00")
