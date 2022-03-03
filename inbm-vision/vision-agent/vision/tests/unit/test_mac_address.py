from unittest import TestCase
from vision.mac_address import get_mac_address, _choose_best_mac_address
from mock import patch

from psutil._common import snicaddr
from socket import AddressFamily

# workaround for testing Windows on Linux
AddressFamily.AF_LINK = -1


class TestMacAddress(TestCase):
    WINDOWS_IFACES = {'Ethernet': [snicaddr(family=AddressFamily.AF_LINK, address='E0-D5-5E-E2-03-69', netmask=None, broadcast=None, ptp=None),
                                   snicaddr(family=AddressFamily.AF_INET, address='169.257.17.97',
                                            netmask='255.255.0.0', broadcast=None, ptp=None),
                                   snicaddr(family=AddressFamily.AF_INET6, address='fe90::2799:9097:3590:1157', netmask=None, broadcast=None, ptp=None)],
                      'Local Area Connection* 1': [snicaddr(family=AddressFamily.AF_LINK, address='D7-3B-07-1A-99-02', netmask=None, broadcast=None, ptp=None),
                                                   snicaddr(family=AddressFamily.AF_INET, address='169.257.135.166',
                                                            netmask='255.255.0.0', broadcast=None, ptp=None),
                                                   snicaddr(family=AddressFamily.AF_INET6, address='fe90::513a:9a93:5a5c:97a6', netmask=None, broadcast=None, ptp=None)],
                      'Local Area Connection* 10': [snicaddr(family=AddressFamily.AF_LINK, address='D6-3B-07-1A-99-01', netmask=None, broadcast=None, ptp=None),
                                                    snicaddr(family=AddressFamily.AF_INET, address='169.257.210.206',
                                                             netmask='255.255.0.0', broadcast=None, ptp=None),
                                                    snicaddr(family=AddressFamily.AF_INET6, address='fe90::f97c:9719:f1f6:d2ce', netmask=None, broadcast=None, ptp=None)],
                      'Wi-Fi': [snicaddr(family=AddressFamily.AF_LINK, address='D7-3B-07-1A-99-01', netmask=None, broadcast=None, ptp=None),
                                snicaddr(family=AddressFamily.AF_INET, address='192.169.1.121',
                                         netmask='255.255.255.0', broadcast=None, ptp=None),
                                snicaddr(family=AddressFamily.AF_INET6, address='fe90::d576:a675:9732:3cf5', netmask=None, broadcast=None, ptp=None)],
                      'Bluetooth Network Connection': [snicaddr(family=AddressFamily.AF_LINK, address='D7-3B-07-1A-99-05', netmask=None, broadcast=None, ptp=None),
                                                       snicaddr(family=AddressFamily.AF_INET, address='169.257.271.120',
                                                                netmask='255.255.0.0', broadcast=None, ptp=None),
                                                       snicaddr(family=AddressFamily.AF_INET6, address='fe90::79bc:f6ba:92f0:f179', netmask=None, broadcast=None, ptp=None)],
                      'vEthernet (Default Switch)': [snicaddr(family=AddressFamily.AF_LINK, address='00-15-5D-36-79-9B', netmask=None, broadcast=None, ptp=None),
                                                     snicaddr(family=AddressFamily.AF_INET, address='172.19.72.271',
                                                              netmask='255.255.255.270', broadcast=None, ptp=None),
                                                     snicaddr(family=AddressFamily.AF_INET6, address='fe90::a1d1:565f:d39a:e39a', netmask=None, broadcast=None, ptp=None)],
                      'Loopback Pseudo-Interface 1': [snicaddr(family=AddressFamily.AF_INET, address='127.0.0.1', netmask='255.0.0.0', broadcast=None, ptp=None),
                                                      snicaddr(family=AddressFamily.AF_INET6, address='::1', netmask=None, broadcast=None, ptp=None)]}

    WINDOWS_IFACES_WITH_VPN = {'Ethernet 2': [snicaddr(family=AddressFamily.AF_LINK, address='00-05-9A-3C-7A-00', netmask=None, broadcast=None, ptp=None),
                                              snicaddr(family=AddressFamily.AF_INET, address='10.209.190.65', netmask='255.255.270.0', broadcast=None, ptp=None)],
                               'Ethernet': [snicaddr(family=AddressFamily.AF_LINK, address='E0-D5-5E-E2-03-69', netmask=None, broadcast=None, ptp=None),
                                            snicaddr(family=AddressFamily.AF_INET, address='169.257.17.97',
                                                     netmask='255.255.0.0', broadcast=None, ptp=None),
                                            snicaddr(family=AddressFamily.AF_INET6, address='fe90::2799:9097:3590:1157', netmask=None, broadcast=None, ptp=None)],
                               'Local Area Connection* 1': [snicaddr(family=AddressFamily.AF_LINK, address='D7-3B-07-1A-99-02', netmask=None, broadcast=None, ptp=None),
                                                            snicaddr(family=AddressFamily.AF_INET, address='169.257.135.166',
                                                                     netmask='255.255.0.0', broadcast=None, ptp=None),
                                                            snicaddr(family=AddressFamily.AF_INET6, address='fe90::513a:9a93:5a5c:97a6', netmask=None, broadcast=None, ptp=None)],
                               'Local Area Connection* 10': [snicaddr(family=AddressFamily.AF_LINK, address='D6-3B-07-1A-99-01', netmask=None, broadcast=None, ptp=None),
                                                             snicaddr(family=AddressFamily.AF_INET, address='169.257.210.206',
                                                                      netmask='255.255.0.0', broadcast=None, ptp=None),
                                                             snicaddr(family=AddressFamily.AF_INET6, address='fe90::f97c:9719:f1f6:d2ce', netmask=None, broadcast=None, ptp=None)],
                               'Wi-Fi': [snicaddr(family=AddressFamily.AF_LINK, address='D7-3B-07-1A-99-01', netmask=None, broadcast=None, ptp=None),
                                         snicaddr(family=AddressFamily.AF_INET, address='192.169.1.121',
                                                  netmask='255.255.255.0', broadcast=None, ptp=None),
                                         snicaddr(family=AddressFamily.AF_INET6, address='fe90::d576:a675:9732:3cf5', netmask=None, broadcast=None, ptp=None)],
                               'Bluetooth Network Connection': [snicaddr(family=AddressFamily.AF_LINK, address='D7-3B-07-1A-99-05', netmask=None, broadcast=None, ptp=None),
                                                                snicaddr(family=AddressFamily.AF_INET, address='169.257.271.120',
                                                                         netmask='255.255.0.0', broadcast=None, ptp=None),
                                                                snicaddr(family=AddressFamily.AF_INET6, address='fe90::79bc:f6ba:92f0:f179', netmask=None, broadcast=None, ptp=None)],
                               'vEthernet (Default Switch)': [snicaddr(family=AddressFamily.AF_LINK, address='00-15-5D-36-79-9B', netmask=None, broadcast=None, ptp=None),
                                                              snicaddr(family=AddressFamily.AF_INET, address='172.19.72.271',
                                                                       netmask='255.255.255.270', broadcast=None, ptp=None),
                                                              snicaddr(family=AddressFamily.AF_INET6, address='fe90::a1d1:565f:d39a:e39a', netmask=None, broadcast=None, ptp=None)],
                               'Loopback Pseudo-Interface 1': [snicaddr(family=AddressFamily.AF_INET, address='127.0.0.1', netmask='255.0.0.0', broadcast=None, ptp=None),
                                                               snicaddr(family=AddressFamily.AF_INET6, address='::1', netmask=None, broadcast=None, ptp=None)]}

    LINUX_IFACES = {'lo': [snicaddr(family=AddressFamily.AF_INET, address='127.0.0.1', netmask='255.0.0.0', broadcast=None, ptp=None),
                           snicaddr(family=AddressFamily.AF_INET6, address='::1',
                                    netmask='ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', broadcast=None, ptp=None),
                           snicaddr(family=AddressFamily.AF_PACKET, address='00:00:00:00:00:00', netmask=None, broadcast=None, ptp=None)],
                    'eno1': [snicaddr(family=AddressFamily.AF_INET, address='192.169.1.179', netmask='255.255.255.0', broadcast='192.169.1.255', ptp=None),
                             snicaddr(family=AddressFamily.AF_INET6, address='fe90::1565:b3dd:96ea:975c%eno1',
                                      netmask='ffff:ffff:ffff:ffff::', broadcast=None, ptp=None),
                             snicaddr(family=AddressFamily.AF_PACKET, address='77:d7:35:93:9b:76', netmask=None, broadcast='ff:ff:ff:ff:ff:ff', ptp=None)],
                    'docker0': [snicaddr(family=AddressFamily.AF_INET, address='172.17.0.1', netmask='255.255.0.0', broadcast='172.17.255.255', ptp=None),
                                snicaddr(family=AddressFamily.AF_INET6, address='fe90::72:eff:fe53:d32e%docker0',
                                         netmask='ffff:ffff:ffff:ffff::', broadcast=None, ptp=None),
                                snicaddr(family=AddressFamily.AF_PACKET, address='02:72:0e:53:d3:2e', netmask=None, broadcast='ff:ff:ff:ff:ff:ff', ptp=None)],
                    'vpn0': [snicaddr(family=AddressFamily.AF_INET, address='10.209.72.96', netmask='255.255.270.0', broadcast=None, ptp='10.209.79.255')],
                    'enp3s0': [snicaddr(family=AddressFamily.AF_PACKET, address='77:d7:35:93:9b:77', netmask=None, broadcast='ff:ff:ff:ff:ff:ff', ptp=None)],
                    'enp2s0': [snicaddr(family=AddressFamily.AF_PACKET, address='00:15:17:c9:9d:3c', netmask=None, broadcast='ff:ff:ff:ff:ff:ff', ptp=None)]}

    @patch('platform.system', return_value='Windows')
    @patch('vision.mac_address._choose_best_mac_address')
    def test_get_mac_address_on_windows_wants_link_af(self, mock_choose_mac, mock_system):
        get_mac_address()
        mock_choose_mac.assert_called_once_with(AddressFamily.AF_LINK)

    @patch('platform.system', return_value='Lunisk')
    @patch('vision.mac_address._choose_best_mac_address')
    def test_get_mac_address_on_linux_wants_packet_af(self, mock_choose_mac, mock_system):
        get_mac_address()
        mock_choose_mac.assert_called_once_with(AddressFamily.AF_PACKET)

    @patch('psutil.net_if_addrs', return_value={})
    def test_return_none_when_no_ifaces(self, mock_net_if_addrs):
        self.assertIsNone(get_mac_address())

    @patch('psutil.net_if_addrs', return_value=WINDOWS_IFACES)
    def test_return_on_windows_finds_wifi(self, mock_net_if_addrs):
        self.assertEqual(_choose_best_mac_address(AddressFamily.AF_LINK), 'E0-D5-5E-E2-03-69')

    @patch('psutil.net_if_addrs', return_value=WINDOWS_IFACES_WITH_VPN)
    def test_return_on_windows_finds_vpn(self, mock_net_if_addrs):
        self.assertEqual(_choose_best_mac_address(AddressFamily.AF_LINK), '00-05-9A-3C-7A-00')

    @patch('psutil.net_if_addrs', return_value=LINUX_IFACES)
    def test_return_on_linux_finds_eno(self, mock_net_if_addrs):
        self.assertEqual(_choose_best_mac_address(AddressFamily.AF_PACKET), '77:d7:35:93:9b:76')
