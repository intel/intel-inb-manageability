"""
Unit tests for the Publisher class


"""


import unittest
import mock

from cloudadapter.constants import MESSAGE
from cloudadapter.agent.publisher import Publisher


class TestPublisher(unittest.TestCase):

    @mock.patch('cloudadapter.agent.broker.Broker', autospec=True)
    def setUp(self, MockBroker):
        self.MockBroker = MockBroker
        self.publisher = Publisher(self.MockBroker())

        self.AOTA_ARGUMENTS = {
            "cmd": "up",
            "app": "docker",
            "fetch": "3",
            "version": "4",
            "signature": "5",
            "container_tag": "6",
            "username": "7",
            "password": "8",
            "dockerRegistry": "9",
            "dockerUsername": "0",
            "dockerPassword": "00"
        }

        self.AOTA_XML = ('<?xml version="1.0" encoding="utf-8"?>'
                         '<manifest>'
                            '<type>ota</type>'
                            '<ota>'
                                '<header>'
                                    '<type>aota</type>'
                                    '<repo>remote</repo>'
                                '</header>'
                                '<type><aota name="sample-rpm">'
                                    '<cmd>up</cmd>'
                                    '<app>docker</app>'
                                    '<fetch>3</fetch>'
                                    '<version>4</version>'
                                    '<signature>5</signature>'
                                    '<containerTag>6</containerTag>'
                                    '<username>7</username>'
                                    '<password>8</password>'
                                    '<dockerRegistry>9</dockerRegistry>'
                                    '<dockerUsername>0</dockerUsername>'
                                    '<dockerPassword>00</dockerPassword>'
                                '</aota></type>'
                            '</ota>'
                         '</manifest>')  # noqa: E127

        self.FOTA_ARGUMENTS = {
            "signature": "1",
            "fetch": "2",
            "biosversion": "3",
            "vendor": "4",
            "manufacturer": "5",
            "product": "6",
            "release_date": "7",
            "path": "8",
            "tooloptions": "9",
            "username": "0",
            "password": "00"
        }

        self.FOTA_XML = ('<?xml version="1.0" encoding="utf-8"?>'
                         '<manifest>'
                            '<type>ota</type>'
                            '<ota>'
                                '<header>'
                                    '<type>fota</type>'
                                    '<repo>remote</repo>'
                                '</header>'
                                '<type><fota name="sample">'
                                    '<signature>1</signature>'
                                    '<fetch>2</fetch>'
                                    '<biosversion>3</biosversion>'
                                    '<vendor>4</vendor>'
                                    '<manufacturer>5</manufacturer>'
                                    '<product>6</product>'
                                    '<releasedate>7</releasedate>'
                                    '<path>8</path>'
                                    '<tooloptions>9</tooloptions>'
                                    '<username>0</username>'
                                    '<password>00</password>'
                                '</fota></type>'
                            '</ota>'
                         '</manifest>')  # noqa: E127

        self.SOTA_ARGUMENTS = {
            "log_to_file": "N",
            "cmd": "update",
            "fetch": "3",
            "signature": "4",
            "username": "5",
            "password": "6"
        }

        self.SOTA_XML = ('<?xml version="1.0" encoding="utf-8"?>'
                         '<manifest>'
                            '<type>ota</type>'
                            '<ota>'
                                '<header>'
                                    '<type>sota</type>'
                                    '<repo>remote</repo>'
                                '</header>'
                                '<type><sota>'
                                    '<cmd logtofile="N">update</cmd>'
                                    '<fetch>3</fetch>'
                                    '<signature>4</signature>'
                                    '<username>5</username>'
                                    '<password>6</password>'
                                '</sota></type>'
                            '</ota>'
                         '</manifest>'
                         )  # noqa: E127

        self.CONFIG_ARGUMENTS = {
            "cmd": "get",
            "fetch": "2",
            "signature": "3",
            "path": "4"
        }

        self.CONFIG_XML_GET = ('<?xml version="1.0" encoding="UTF-8"?>'
                           '<manifest>'
                                '<type>config</type>'
                                '<config>'
                                    '<cmd>get_element</cmd>'
                                    '<configtype>'
                                        '<get>'
                                            '<path>4</path>'
                                        '</get>'
                                    '</configtype>'
                                '</config>'
                           '</manifest>')  # noqa: E127

        self.CONFIG_XML_SET = ('<?xml version="1.0" encoding="UTF-8"?>'
                           '<manifest>'
                                '<type>config</type>'
                                '<config>'
                                    '<cmd>set_element</cmd>'
                                    '<configtype>'
                                        '<set>'
                                            '<path>4</path>'
                                        '</set>'
                                    '</configtype>'
                                '</config>'
                           '</manifest>')  # noqa: E127

        self.CONFIG_XML_LOAD = ('<?xml version="1.0" encoding="UTF-8"?>'
                                '<manifest>'
                                    '<type>config</type>'
                                    '<config>'
                                        '<cmd>load</cmd>'
                                        '<configtype>'
                                            '<load>'
                                                '<fetch>2</fetch>'
                                                '<signature>3</signature>'
                                            '</load>'
                                        '</configtype>'
                                    '</config>'
                                '</manifest>')  # noqa: E127
        


        self.QUERY_ALL = ('<?xml version="1.0" encoding="UTF-8"?>'
                      '<manifest>'
                        '<type>cmd</type>'
                        '<cmd>query</cmd>'
                        '<query>'
                            '<option>all</option>'
                        '</query>'
                      '</manifest>')  # noqa: E127

        self.QUERY_ARGUMENTS_ALL = {
            "option": "all", 
         }
        self.QUERY_HW = ('<?xml version="1.0" encoding="UTF-8"?>'
                      '<manifest>'
                        '<type>cmd</type>'
                        '<cmd>query</cmd>'
                        '<query>'
                            '<option>hw</option>'
                        '</query>'
                      '</manifest>')  # noqa: E127

        self.QUERY_ARGUMENTS_HW = {
            "option": "hw",
        }
        self.QUERY_FW = ('<?xml version="1.0" encoding="UTF-8"?>'
                      '<manifest>'
                        '<type>cmd</type>'
                        '<cmd>query</cmd>'
                        '<query>'
                            '<option>fw</option>'
                        '</query>'
                      '</manifest>')  # noqa: E127

        self.QUERY_ARGUMENTS_FW = {
            "option": "fw",
        }
        self.QUERY_STATUS_STATUS = ('<?xml version="1.0" encoding="UTF-8"?>'
                      '<manifest>'
                        '<type>cmd</type>'
                        '<cmd>query</cmd>'
                        '<query>'
                            '<option>status</option>'
                        '</query>'
                      '</manifest>')  # noqa: E127

        self.QUERY_ARGUMENTS_STATUS = {
            "option": "status",
        }
        self.QUERY_SECURITY = ('<?xml version="1.0" encoding="UTF-8"?>'
                      '<manifest>'
                        '<type>cmd</type>'
                        '<cmd>query</cmd>'
                        '<query>'
                            '<option>security</option>'
                        '</query>'
                      '</manifest>')  # noqa: E127

        self.QUERY_ARGUMENTS_SECURITY = {
            "option": "security",
        }
        self.QUERY_OS = ('<?xml version="1.0" encoding="UTF-8"?>'
                      '<manifest>'
                        '<type>cmd</type>'
                        '<cmd>query</cmd>'
                        '<query>'
                            '<option>os</option>'
                        '</query>'
                      '</manifest>')  # noqa: E127

        self.QUERY_ARGUMENTS_OS = {
            "option": "os",
        }
        self.QUERY_GUID = ('<?xml version="1.0" encoding="UTF-8"?>'
                      '<manifest>'
                        '<type>cmd</type>'
                        '<cmd>query</cmd>'
                        '<query>'
                            '<option>guid</option>'
                        '</query>'
                      '</manifest>')  # noqa: E127

        self.QUERY_ARGUMENTS_GUID = {
            "option": "guid",
        }
        self.QUERY_VERSION = ('<?xml version="1.0" encoding="UTF-8"?>'
                      '<manifest>'
                        '<type>cmd</type>'
                        '<cmd>query</cmd>'
                        '<query>'
                            '<option>version</option>'
                        '</query>'
                      '</manifest>')  # noqa: E127

        self.QUERY_ARGUMENTS_VERSION = {
            "option": "version",
        }
        self.QUERY_SWBOM = ('<?xml version="1.0" encoding="UTF-8"?>'
                      '<manifest>'
                        '<type>cmd</type>'
                        '<cmd>query</cmd>'
                        '<query>'
                            '<option>swbom</option>'
                        '</query>'
                      '</manifest>')  # noqa: E127

        self.QUERY_ARGUMENTS_SWBOM = {
            "option": "swbom",
        }

    def test_publish_manifest_succeed(self):
        manifest = "<manifest></mainfest>"

        message = self.publisher.publish_manifest(manifest)

        assert message == MESSAGE.MANIFEST
        mocked = self.MockBroker.return_value
        mocked.publish_install.assert_called_once_with(manifest)

    def test_publish_manifest_whitespace_fail(self):
        self.assertRaises(ValueError, self.publisher.publish_manifest, "    ")

    def test_publish_manifest_empty_fail(self):
        self.assertRaises(ValueError, self.publisher.publish_manifest, "")

    def test_publish_aota_with_container_tag_succeed(self):
        arguments = self.AOTA_ARGUMENTS

        message = self.publisher.publish_aota(**arguments)

        assert message == MESSAGE.AOTA
        mocked = self.MockBroker.return_value
        mocked.publish_install.assert_called_once_with(self.AOTA_XML)

    def test_publish_aota_with_containerTag_succeed(self):
        arguments = self.AOTA_ARGUMENTS.copy()
        arguments.update(containerTag=arguments.pop("container_tag"))

        message = self.publisher.publish_aota(**arguments)

        assert message == MESSAGE.AOTA
        mocked = self.MockBroker.return_value
        mocked.publish_install.assert_called_once_with(self.AOTA_XML)

    def test_publish_aota_with_invalid_app_fail(self):
        arguments = self.AOTA_ARGUMENTS.copy()
        arguments.update(app="invalid")

        self.assertRaises(ValueError, self.publisher.publish_aota, **arguments)

    def test_publish_aota_with_no_app_fail(self):
        arguments = self.AOTA_ARGUMENTS.copy()
        arguments.update(app="")

        self.assertRaises(ValueError, self.publisher.publish_aota, **arguments)

    def test_publish_aota_with_invalid_cmd_fail(self):
        arguments = self.AOTA_ARGUMENTS.copy()
        arguments.update(cmd="invalid")

        self.assertRaises(ValueError, self.publisher.publish_aota, **arguments)

    def test_publish_aota_with_no_cmd_fail(self):
        arguments = self.AOTA_ARGUMENTS.copy()
        arguments.update(cmd="")

        self.assertRaises(ValueError, self.publisher.publish_aota, **arguments)

    def test_publish_fota_with_release_date_succeed(self):
        arguments = self.FOTA_ARGUMENTS

        message = self.publisher.publish_fota(**arguments)

        assert message == MESSAGE.FOTA
        mocked = self.MockBroker.return_value
        mocked.publish_install.assert_called_once_with(self.FOTA_XML)

    def test_publish_fota_with_releasedate_succeed(self):
        arguments = self.FOTA_ARGUMENTS.copy()
        arguments.update(releasedate=arguments.pop("release_date"))

        message = self.publisher.publish_fota(**arguments)

        assert message == MESSAGE.FOTA
        mocked = self.MockBroker.return_value
        mocked.publish_install.assert_called_once_with(self.FOTA_XML)

    def test_publish_fota_without_arguments_fail(self):
        failed = False
        try:
            self.publisher.publish_fota()
        except ValueError:
            failed = True
        assert failed

    def test_publish_sota_with_invalid_cmd_fail(self):
        arguments = self.AOTA_ARGUMENTS.copy()
        arguments.update(cmd="invalid")

        self.assertRaises(ValueError, self.publisher.publish_sota, **arguments)

    def test_publish_sota_with_no_cmd_fail(self):
        arguments = self.AOTA_ARGUMENTS.copy()
        arguments.update(cmd="")

        self.assertRaises(ValueError, self.publisher.publish_sota, **arguments)

    def test_publish_sota_with_invalid_log_to_file_fail(self):
        arguments = self.AOTA_ARGUMENTS.copy()
        arguments.update(log_to_file="invalid")

        self.assertRaises(ValueError, self.publisher.publish_sota, **arguments)

    def test_publish_sota_with_no_log_to_file_fail(self):
        arguments = self.AOTA_ARGUMENTS.copy()
        arguments.update(log_to_file="")

        self.assertRaises(ValueError, self.publisher.publish_sota, **arguments)

    def test_publish_sota_succeed(self):
        arguments = self.SOTA_ARGUMENTS

        message = self.publisher.publish_sota(**arguments)

        assert message == MESSAGE.SOTA
        mocked = self.MockBroker.return_value
        mocked.publish_install.assert_called_once_with(self.SOTA_XML)

    def test_publish_config_succeed(self):
        arguments = self.CONFIG_ARGUMENTS

        message = self.publisher.publish_config(**arguments)

        assert message == MESSAGE.CONFIG
        mocked = self.MockBroker.return_value
        mocked.publish_install.assert_called_once_with(self.CONFIG_XML_GET)

    def test_publish_config_set_succeed(self):
        arguments = self.CONFIG_ARGUMENTS
        arguments.update(cmd="set")

        message = self.publisher.publish_config(**arguments)

        assert message == MESSAGE.CONFIG
        mocked = self.MockBroker.return_value
        mocked.publish_install.assert_called_once_with(self.CONFIG_XML_SET)

    def test_publish_config_load_succeed(self):
        arguments = self.CONFIG_ARGUMENTS
        arguments.update(cmd="load")

        message = self.publisher.publish_config(**arguments)

        assert message == MESSAGE.CONFIG
        mocked = self.MockBroker.return_value
        mocked.publish_install.assert_called_once_with(self.CONFIG_XML_LOAD)

    def test_publish_config_with_invalid_cmd_fail(self):
        arguments = self.CONFIG_ARGUMENTS
        arguments.update(cmd="invalid")

        self.assertRaises(ValueError, self.publisher.publish_config, **arguments)

    def test_publish_config_without_arguments_fail(self):
        failed = False
        try:
            self.publisher.publish_config()
        except ValueError:
            failed = True
        assert failed

    def test_query_all(self):
        arguments = self.QUERY_ARGUMENTS_ALL

        message = self.publisher.publish_query(**arguments)

        assert message == MESSAGE.QUERY
        mocked = self.MockBroker.return_value
        mocked.publish_install.assert_called_once_with(self.QUERY_ALL)
    def test_query_hw(self):
        arguments = self.QUERY_ARGUMENTS_HW

        message = self.publisher.publish_query(**arguments)

        assert message == MESSAGE.QUERY
        mocked = self.MockBroker.return_value
        mocked.publish_install.assert_called_once_with(self.QUERY_HW)
    def test_query_fw(self):
        arguments = self.QUERY_ARGUMENTS_FW

        message = self.publisher.publish_query(**arguments)

        assert message == MESSAGE.QUERY
        mocked = self.MockBroker.return_value
        mocked.publish_install.assert_called_once_with(self.QUERY_FW)
    def test_query_os(self):
        arguments = self.QUERY_ARGUMENTS_OS

        message = self.publisher.publish_query(**arguments)

        assert message == MESSAGE.QUERY
        mocked = self.MockBroker.return_value
        mocked.publish_install.assert_called_once_with(self.QUERY_OS)
    def test_query_status(self):
        arguments = self.QUERY_ARGUMENTS_STATUS

        message = self.publisher.publish_query(**arguments)

        assert message == MESSAGE.QUERY
        mocked = self.MockBroker.return_value
        mocked.publish_install.assert_called_once_with(self.QUERY_STATUS)   
        
    def test_query_security(self):
        arguments = self.QUERY_ARGUMENTS_SECURITY

        message = self.publisher.publish_query(**arguments)

        assert message == MESSAGE.QUERY
        mocked = self.MockBroker.return_value
        mocked.publish_install.assert_called_once_with(self.QUERY_SECURITY)  
    def test_query_swbom(self):
        arguments = self.QUERY_ARGUMENTS_SWBOM

        message = self.publisher.publish_query(**arguments)

        assert message == MESSAGE.QUERY
        mocked = self.MockBroker.return_value
        mocked.publish_install.assert_called_once_with(self.QUERY_SWBOM)  
    def test_query_guid(self):
        arguments = self.QUERY_ARGUMENTS_GUID

        message = self.publisher.publish_query(**arguments)

        assert message == MESSAGE.QUERY
        mocked = self.MockBroker.return_value
        mocked.publish_install.assert_called_once_with(self.QUERY_GUID)
