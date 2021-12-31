from unittest import TestCase

from vision.data_handler.command_data_handler import receive_provision_node_request
from vision.manifest_parser import ParsedManifest
from inbm_vision_lib.ota_parser import ParseException

from mock import Mock, patch

RECEIVED_XML = '<manifest><type>cmd</type><cmd>provisionNode</cmd><provisionNode>' \
    '<blobPath>/var/cache/manageability/repository-tool/test.bin</blobPath>' \
               '<certPath>/var/cache/manageability/repository-tool/test.crt</certPath></provisionNode></manifest>'


class TestCommandDataHandler(TestCase):
    @patch('vision.manifest_parser.parse_manifest',
           return_value=ParsedManifest('provisionNode', {'blob_path': 'blob.bin', 'cert_path': 'path.crt'}, []))
    @patch('inbm_vision_lib.utility.move_file')
    def test_move_files_successfully(self, mock_move, mock_parse):
        receive_provision_node_request(RECEIVED_XML, Mock())
        self.assertEqual(mock_move.call_count, 2)

    @patch('vision.manifest_parser.parse_manifest', side_effect=ParseException)
    @patch('inbm_vision_lib.utility.move_file')
    def test_no_move_files_on_failure(self, mock_move, mock_parse):
        receive_provision_node_request(RECEIVED_XML, Mock())
        self.assertEqual(mock_move.call_count, 0)
