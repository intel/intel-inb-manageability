import os
import unittest
from unittest import TestCase

from dispatcher.validators import is_valid_json_structure, _get_schema_location

TEST_JSON_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                         '../../fpm-template/usr/share/dispatcher-agent/'
                                         'config_param_schema.json')

TEST_NODE_UPDATE_JSON_SCHEMA_LOCATION = os.path.join(os.path.dirname(__file__),
                                        '../../fpm-template/usr/share/dispatcher-agent/'
                                        'node_update_schema.json')


class TestValidators(TestCase):

    def test_validate_node_update_json_structure_pass(self) -> None:
        json_params = '{"status":200, "message":"COMMAND SUCCESSFUL", "jobId":"swupd-4b151b70-c121-4245-873b-5324ac7a3f7a"}'
        result = is_valid_json_structure(json_params, TEST_NODE_UPDATE_JSON_SCHEMA_LOCATION)
        self.assertTrue(result is True)
        
    def test_json_parse_one_param_pass(self) -> None:
        config_params = '{"execcmd":"abc"}'
        result = is_valid_json_structure(config_params, TEST_JSON_SCHEMA_LOCATION)
        self.assertTrue(result is True)

    def test_json_parse_two_param_pass(self) -> None:
        config_params = '{"execcmd":"abc", "device":["abcd","def"]}'
        result = is_valid_json_structure(config_params, TEST_JSON_SCHEMA_LOCATION)
        self.assertTrue(result is True)

    def test_json_parse_param_fail(self) -> None:
        config_params = '{"privileged":["yes"]}'
        result = is_valid_json_structure(config_params, TEST_JSON_SCHEMA_LOCATION)
        self.assertTrue(result is False)

    def test_json_parse_no_param_fail(self) -> None:
        config_params = ''
        result = is_valid_json_structure(config_params, TEST_JSON_SCHEMA_LOCATION)
        self.assertTrue(result is False)

    def test_json_wrong_schema_location(self) -> None:
        config_params = ''
        result = is_valid_json_structure(config_params, '')
        self.assertTrue(result is False)

    def test_get_schema_returns_passed_schema(self) -> None:
        self.assertEqual(_get_schema_location(
            'test_schema.json'), 'test_schema.json')

    def test_get_schema_returns_single_schema(self) -> None:
        self.assertEqual(_get_schema_location(),
                         '/usr/share/dispatcher-agent/config_param_schema.json')


if __name__ == '__main__':
    unittest.main()
