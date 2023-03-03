# Copyright (C) 2017-2023 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

import logging
from threading import Lock
import datetime

from dispatcher.common.result_constants import *

# case 1: success case
from dispatcher.config_dbs import ConfigDbs
from dispatcher.dispatcher_broker import DispatcherBroker
from dispatcher.dispatcher_callbacks import DispatcherCallbacks
from dispatcher.dispatcher_class import Dispatcher
from inbm_common_lib.utility import canonicalize_uri
from inbm_common_lib.platform_info import PlatformInformation
from inbm_common_lib.constants import UNKNOWN, UNKNOWN_DATETIME
from inbm_lib.mqttclient.mqtt import MQTT

fake_ota_resource = {'fetch': 'https://www.abc.com', 'biosversion': 'F2', 'vendor': 'American Megatrends Inc.',
                     'manufacturer': 'Gigabyte Technology Co., Ltd.', 'product': 'Z170X-UD5', 'releasedate': '2100-01-01'}

fake_ota_success = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
                      <id>sampleId</id><name>SampleFOTA</name><description>Sample</description>
                      <type>fota</type><repo>remote</repo></header>
                      <type><fota name="sample-rpm"><fetch>http://localhost:8080</fetch>
                      <biosversion>A.B.D.E.F</biosversion><vendor>test</vendor>
                      <signature>testsig</signature><manufacturer>testmanufacturer</manufacturer><product>testproduct</product>
                      <releasedate>2017-06-12</releasedate><path>fakepath</path><tooloptions>/p /b</tooloptions>
                      </fota></type></ota></manifest>
                   """

fake_fota_mismatch_product = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
                      <type>fota</type><repo>remote</repo></header>
                      <type><fota name="sample-rpm"><fetch>http://127.0.0.1:80/BIOSUPDATE.tar</fetch>
                      <signature>`python3 /scripts/create_signature.py ${VAGRANT_INPUT_PATH}/succeed_rpm_key.pem ${VAGRANT_INPUT_PATH}/${BIOSUPDATE_TAR}  1234`</signature>
                      <biosversion>A..ZZZZ.B11.1</biosversion><vendor>Intel Corp.</vendor>
                      <manufacturer>testmanufacturer</manufacturer><product>invalidproduct</product>
                      <releasedate>2017-06-23</releasedate><path>/boot/efi/</path></fota></type></ota></manifest>
                   """

fake_ota_bad_uri = """<?xml version='1.0' encoding='utf-8'?><manifest><type>ota</type><ota><header><id>sampleId</id>
<name>Sample AOTA</name><description>Sample AOTA manifest file</description><type>aota</type><repo>remote</repo>
</header><type><aota name='sample-rpm'><cmd>load</cmd><app>docker</app><fetch>http;;//10.108.50.83/test_files/abcde/test-files-1119/succeed-1.0-1.noarch.tar</fetch><version>1.0</version><signature>7c2e78804564b341f6002a9de5cf82651de137ceec62e09490d4dfa7db044d52907ded9e92c7c49df506c900ab88178c75cd63daac7f8229746e18227734f0c36e34144bcc04aaa094efeeec927b24b9b0c1954260caa8f79900184777e0b884e2c1ada3be76217496e9fd6aa0bd36b7a250fbc85dfc3d37305d28e73378ace5ac1201b63229787e0e23d66a8a841215a07d1b592b38b86e9eaaef89712bec5d9b5141a46fddf9ea59d7326e3e6c02c3815f0a5974190e3018419dc3ee747a8c14394d2b79cc73e464efa95da2c628ca645123682746b15252daff50fa0ea9d72fee531913176b8cc44ee7366b8bcc3704fafc048e849f3c43ee2a339fb76a4335a7257a1f03a67112521e3a2543718db35b9a4efc2f325dd01e0c643e6a6a8a4e5198ab301e4952cfcd4e8a743fe38ba03083afd30ae0219c059f866f5fae07b089ceecedaf67e76714ecdf171bcb2b4bfb8bbf592225bb78e6b67f337f1834cf5bbb66b0c2ed7e8755dc83b97318f554e45a0ddbbbcd742251de4419950e19</signature><containerTag>sample-container</containerTag></aota></type></ota></manifest>"""

fake_fota_guid = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
                      <id>sampleId</id><name>SampleFOTA</name><description>Sample</description>
                      <type>fota</type><repo>remote</repo></header>
                      <type><fota name="sample-rpm"><fetch>http://localhost:8080</fetch>
                      <biosversion>A.B.D.E.F</biosversion><vendor>test</vendor>
                      <signature>testsig</signature><manufacturer>testmanufacturer</manufacturer><product>testproduct</product>
                      <releasedate>2017-06-12</releasedate><path>fakepath</path><guid>1234</guid>
                      </fota></type></ota></manifest>
                   """

fake_fota_no_guid = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
                      <id>sampleId</id><name>SampleFOTA</name><description>Sample</description>
                      <type>fota</type><repo>remote</repo></header>
                      <type><fota name="sample-rpm"><fetch>http://localhost:8080</fetch>
                      <biosversion>A.B.D.E.F</biosversion><vendor>test</vendor>
                      <signature>testsig</signature><manufacturer>testmanufacturer</manufacturer><product>testproduct</product>
                      <releasedate>2017-06-12</releasedate><path>fakepath</path>
                      </fota></type></ota></manifest>
                   """

fake_ota_no_tool_option = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
                      <id>sampleId</id><name>SampleFOTA</name><description>Sample</description>
                      <type>fota</type><repo>remote</repo></header>
                      <type><fota name="sample-rpm"><fetch>http://localhost:8080</fetch>
                      <biosversion>A.B.D.E.F</biosversion><vendor>test</vendor>
                      <signature>testsig</signature><manufacturer>testmanufacturer</manufacturer><product>testproduct</product>
                      <releasedate>2017-06-12</releasedate><path>fakepath</path></fota></type></ota></manifest>
                   """

# already applied
fake_ota_fail1 = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
                      <id>sampleId</id><name>SampleFOTA</name><description>Sample</description>
                      <type>fota</type><repo>remote</repo></header>
                      <type><fota name="sample-rpm"><fetch>http://localhost:8080</fetch>
                      <biosversion>A.B.D.E.F</biosversion><vendor>test</vendor>
                      <signature>testsig</signature><manufacturer>testmanufacturer</manufacturer><product>testproduct</product>
                      <releasedate>2010-06-12</releasedate><path>fakepath</path></fota></type></ota></manifest>
                 """

# manifest version or release date is lower
fake_ota_fail2 = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
                      <id>sampleId</id><name>SampleFOTA</name><description>Sample</description>
                      <type>fota</type><repo>remote</repo></header>
                      <type><fota name="sample-rpm"><fetch>http://localhost:8080</fetch>
                      <biosversion>A.B.D.E.F</biosversion><vendor>test</vendor>
                      <signature>testsig</signature><manufacturer>testmanufacturer</manufacturer><product>testproduct</product>
                      <releasedate>2009-06-12</releasedate><path>fakepath</path></fota></type></ota></manifest>
                 """

# manifest vendor name does not match
fake_ota_fail3 = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
                      <id>sampleId</id><name>SampleFOTA</name><description>Sample</description>
                      <type>fota</type><repo>remote</repo></header>
                      <type><fota name="sample-rpm"><fetch>http://localhost:8080</fetch>
                      <biosversion>A.B.D.E.F</biosversion><vendor>differentvendor</vendor>
                      <signature>testsig</signature><manufacturer>testmanufacturer</manufacturer><product>testproduct</product>
                      <releasedate>2011-06-12</releasedate><path>fakepath</path></fota></type></ota></manifest>
                 """

# manifest vendor name does not match and lower release date
fake_ota_fail4 = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
                      <id>sampleId</id><name>SampleFOTA</name><description>Sample</description>
                      <type>fota</type><repo>remote</repo></header>
                      <type><fota name="sample-rpm"><fetch>http://localhost:8080</fetch>
                      <biosversion>A.B.D.E.F</biosversion><vendor>differentvendor</vendor>
                      <signature>testsig</signature><manufacturer>testmanufacturer</manufacturer><product>testproduct</product>
                      <releasedate>2008-06-12</releasedate><path>fakepath</path></fota></type></ota></manifest>
                 """

# missing tags
fake_ota_invalid = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header>
                      <id>sampleId</id><name>SampleFOTA</name><description>Sample</description>
                      <type>fota</type><repo>remote</repo></header>
                      <type><fota name="sample-rpm"><fetch>http://localhost:8080</fetch>
                      <biosversion>X</biosversion><vendor>differntvendor</vendor>
                      <signature>testsig</signature><manufacturer>testmanufacturer</manufacturer><product>testproduct</product>
                      <releasedate>2009-06-12</releasedate><path>fakepath</path></fota></type></ota></manifest>
                   """

fake_sota_success = """<?xml version="1.0" encoding="utf-8"?><manifest><type>ota</type><ota><header><id>test</id><name>tesname</name><description>
                       </description><repo>remote</repo><type>sota</type></header><type><sota><cmd>update</cmd><path>/var/cache</path>
                       </sota></type></ota></manifest>
                    """

dummy_success = INSTALL_SUCCESS
dummy_failure = INSTALL_FAILURE
mock_url = canonicalize_uri("http://www.example.com:8976/capsule.tar")
username = None
password = None


parsed_dmi_current = PlatformInformation(datetime.datetime(
    2010, 6, 12, 0, 0), 'test', 'A.B.C.D.E.F', 'testmanufacturer', 'testproduct')
parsed_dmi_ami = PlatformInformation(datetime.datetime(
    2011, 10, 11, 0, 0), 'American Megatrends Inc.', '5.12', 'testmanufacturer', 'testproduct')
parsed_dmi_unknown_version = PlatformInformation(UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN, UNKNOWN)
parsed_dmi_mismatch_product = PlatformInformation(datetime.datetime(
    2011, 10, 13, 0, 0), 'Intel Corp.', 'A..Y.B11.1', 'testmanufacturer', 'Broxton P')

sota_cmd_list = ['pip list', 'apt-get update', 'apt-get -yq upgrade']

mock_apt_sources_list = """#Mocktest deb cdrom:[Ubuntu 16.04.1 LTS _Xenial Xerus_ - Release amd64 (20160719)]/ xenial main restricted

# See http://help.ubuntu.com/community/UpgradeNotes for how to upgrade to
# newer versions of the distribution.
deb http://us.archive.ubuntu.com/ubuntu/ xenial main restricted
# deb-src http://us.archive.ubuntu.com/ubuntu/ xenial main restricted

## Major bug fix updates produced after the final release of the
## distribution.
deb http://us.archive.ubuntu.com/ubuntu/ xenial-updates main restricted
# deb-src http://us.archive.ubuntu.com/ubuntu/ xenial-updates main restricted

## N.B. software from this repository is ENTIRELY UNSUPPORTED by the Ubuntu
## team, and may not be under a free licence. Please satisfy yourself as to
## your rights to use the software. Also, please note that software in
## universe WILL NOT receive any review or updates from the Ubuntu security
## team.
deb http://us.archive.ubuntu.com/ubuntu/ xenial universe
# deb-src http://us.archive.ubuntu.com/ubuntu/ xenial universe
deb http://us.archive.ubuntu.com/ubuntu/ xenial-updates universe
# deb-src http://us.archive.ubuntu.com/ubuntu/ xenial-updates universe

## N.B. software from this repository is ENTIRELY UNSUPPORTED by the Ubuntu 
## team, and may not be under a free licence. Please satisfy yourself as to 
## your rights to use the software. Also, please note that software in 
## multiverse WILL NOT receive any review or updates from the Ubuntu
## security team.
deb http://us.archive.ubuntu.com/ubuntu/ xenial multiverse
# deb-src http://us.archive.ubuntu.com/ubuntu/ xenial multiverse
deb http://us.archive.ubuntu.com/ubuntu/ xenial-updates multiverse
# deb-src http://us.archive.ubuntu.com/ubuntu/ xenial-updates multiverse

## N.B. software from this repository may not have been tested as
## extensively as that contained in the main release, although it includes
## newer versions of some applications which may provide useful features.
## Also, please note that software in backports WILL NOT receive any review
## or updates from the Ubuntu security team.
deb http://us.archive.ubuntu.com/ubuntu/ xenial-backports main restricted universe multiverse
# deb-src http://us.archive.ubuntu.com/ubuntu/ xenial-backports main restricted universe multiverse

## Uncomment the following two lines to add software from Canonical's
## 'partner' repository.
## This software is not part of Ubuntu, but is offered by Canonical and the
## respective vendors as a service to Ubuntu users.
# deb http://archive.canonical.com/ubuntu xenial partner
# deb-src http://archive.canonical.com/ubuntu xenial partner

deb http://security.ubuntu.com/ubuntu xenial-security main restricted
# deb-src http://security.ubuntu.com/ubuntu xenial-security main restricted
deb http://security.ubuntu.com/ubuntu xenial-security universe
# deb-src http://security.ubuntu.com/ubuntu xenial-security universe
deb http://security.ubuntu.com/ubuntu xenial-security multiverse
deb [arch=amd64] https://download.docker.com/linux/ubuntu xenial stable
# deb-src [arch=amd64] https://download.docker.com/linux/ubuntu xenial stable
# deb-src http://security.ubuntu.com/ubuntu xenial-security multiverse
"""

mock_apt_expected = """#Mocktest deb cdrom:[Ubuntu 16.04.1 LTS _Xenial Xerus_ - Release amd64 (20160719)]/ xenial main restricted

# See http://help.ubuntu.com/community/UpgradeNotes for how to upgrade to
# newer versions of the distribution.
deb http://testsuccess xenial main restricted
# deb-src http://us.archive.ubuntu.com/ubuntu/ xenial main restricted

## Major bug fix updates produced after the final release of the
## distribution.
deb http://testsuccess xenial-updates main restricted
# deb-src http://us.archive.ubuntu.com/ubuntu/ xenial-updates main restricted

## N.B. software from this repository is ENTIRELY UNSUPPORTED by the Ubuntu
## team, and may not be under a free licence. Please satisfy yourself as to
## your rights to use the software. Also, please note that software in
## universe WILL NOT receive any review or updates from the Ubuntu security
## team.
deb http://testsuccess xenial universe
# deb-src http://us.archive.ubuntu.com/ubuntu/ xenial universe
deb http://testsuccess xenial-updates universe
# deb-src http://us.archive.ubuntu.com/ubuntu/ xenial-updates universe

## N.B. software from this repository is ENTIRELY UNSUPPORTED by the Ubuntu 
## team, and may not be under a free licence. Please satisfy yourself as to 
## your rights to use the software. Also, please note that software in 
## multiverse WILL NOT receive any review or updates from the Ubuntu
## security team.
deb http://testsuccess xenial multiverse
# deb-src http://us.archive.ubuntu.com/ubuntu/ xenial multiverse
deb http://testsuccess xenial-updates multiverse
# deb-src http://us.archive.ubuntu.com/ubuntu/ xenial-updates multiverse

## N.B. software from this repository may not have been tested as
## extensively as that contained in the main release, although it includes
## newer versions of some applications which may provide useful features.
## Also, please note that software in backports WILL NOT receive any review
## or updates from the Ubuntu security team.
deb http://testsuccess xenial-backports main restricted universe multiverse
# deb-src http://us.archive.ubuntu.com/ubuntu/ xenial-backports main restricted universe multiverse

## Uncomment the following two lines to add software from Canonical's
## 'partner' repository.
## This software is not part of Ubuntu, but is offered by Canonical and the
## respective vendors as a service to Ubuntu users.
# deb http://archive.canonical.com/ubuntu xenial partner
# deb-src http://archive.canonical.com/ubuntu xenial partner

deb http://testsuccess xenial-security main restricted
# deb-src http://security.ubuntu.com/ubuntu xenial-security main restricted
deb http://testsuccess xenial-security universe
# deb-src http://security.ubuntu.com/ubuntu xenial-security universe
deb http://testsuccess xenial-security multiverse
deb [arch=amd64] https://download.docker.com/linux/ubuntu xenial stable
# deb-src [arch=amd64] https://download.docker.com/linux/ubuntu xenial stable
# deb-src http://security.ubuntu.com/ubuntu xenial-security multiverse
"""

LOGGERPATH = '../dispatcher-agent/fpm-template/etc/logging.ini'


class Mqtt(MQTT):

    def __init__(self):
        pass

    def publish(self, topic, payload):
        pass

    def subscribe(self, topic, callback):
        pass


class MockDispatcherCallbacks(DispatcherCallbacks):
    def __init__(self) -> None:
        self.broker_core = MockDispatcherBroker.build_mock_dispatcher_broker()
        self.sota_repos = None
        self.proceed_without_rollback = False

    def install_check(self, size: int, check_type: str) -> None:
        pass

    @staticmethod
    def build_mock_dispatcher_callbacks() -> DispatcherCallbacks:
        return MockDispatcherCallbacks()


class MockDispatcherBroker(DispatcherBroker):
    # Fake DispatcherBroker
    def __init__(self) -> None:
        pass

    def start(self, tls: bool) -> None:
        pass

    def send_result(self, message: str) -> None:
        pass

    def mqtt_publish(self, topic: str, payload: str, qos: int = 0, retain: bool = False) -> None:
        pass

    def mqtt_subscribe(self, topic, callback, qos=0) -> None:
        pass

    def telemetry(self, message: str) -> None:
        pass

    def stop(self) -> None:
        pass

    def is_started(self) -> bool:
        return True

    @staticmethod
    def build_mock_dispatcher_broker():
        return MockDispatcherBroker()


class MockDispatcher(Dispatcher):
    # Fake Dispatcher

    def __init__(self, logger):
        self.lock = Lock()
        self.mqttc = Mqtt()
        self._logger = logger
        self.config_dbs = ConfigDbs.ON
        self.dbs_remove_image_on_failed_container = True
        self.sota_repos = None
        self.proceed_without_rollback = False

    def install_check(self, size=None, check_type=None) -> None:
        pass

    def clear_dispatcher_state(self):
        pass

    @staticmethod
    def build_mock_dispatcher():
        return MockDispatcher(logging.getLogger(__name__))
