"""
    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import xml.etree.ElementTree as ET
from google.protobuf.timestamp_pb2 import Timestamp
from cloudadapter.pb.common.v1.common_pb2 import UpdateSystemSoftwareOperation, Operation

def convert_operation_to_xml_manifests(operation: Operation) -> list[str]:
    """Converts an Operation message to a list of XML manifest strings for Dispatcher."""

    if not operation.HasField('update_system_software_operation'):
        raise ValueError("Operation type not supported")

    if len(operation.pre_operations) > 0:
        raise ValueError("Pre-operations not supported")

    if len(operation.post_operations) > 0:
        raise ValueError("Post-operations not supported")

    return [convert_system_software_operation_to_xml_manifest(operation.update_system_software_operation)]

def convert_system_software_operation_to_xml_manifest(operation: UpdateSystemSoftwareOperation) -> str:
    """Converts a UpdateSystemSoftwareOperation message to an XML manifest string for Dispatcher."""
    # Create the root element
    manifest = ET.Element('manifest')
    ota = ET.SubElement(manifest, 'ota')
    header = ET.SubElement(ota, 'header')
    ET.SubElement(header, 'type').text = 'sota'
    ET.SubElement(header, 'repo').text = 'remote'

    type = ET.SubElement(ota, 'type')
    sota = ET.SubElement(type, 'sota')
    ET.SubElement(sota, 'cmd', logtofile="y").text = 'update'

    if operation.mode == UpdateSystemSoftwareOperation.DownloadMode.DOWNLOAD_MODE_UNSPECIFIED:
        raise ValueError("Download mode cannot be unspecified")
    # Map the download mode to the correct string
    download_mode_map = {
        UpdateSystemSoftwareOperation.DownloadMode.DOWNLOAD_MODE_FULL: 'full',
        UpdateSystemSoftwareOperation.DownloadMode.DOWNLOAD_MODE_NO_DOWNLOAD: 'no_download',
        UpdateSystemSoftwareOperation.DownloadMode.DOWNLOAD_MODE_DOWNLOAD_ONLY: 'download_only',
    }
    mode_str = download_mode_map.get(operation.mode)
    ET.SubElement(sota, 'mode').text = mode_str

    # Convert package list to comma-separated string
    if len(operation.package_list) > 0:
        package_list_str = ','.join(operation.package_list)
        ET.SubElement(sota, 'packageList').text = package_list_str

    # Fetch URL
    if operation.url != '':
        ET.SubElement(sota, 'fetch').text = operation.url

    # Release date in the required format
    if operation.release_date.ToSeconds() > 0:
        release_date = Timestamp()
        release_date.FromDatetime(operation.release_date.ToDatetime())
        ET.SubElement(sota, 'releaseDate').text = release_date.ToDatetime().strftime('%Y-%m-%d')

    # Device reboot
    device_reboot = 'no' if operation.do_not_reboot else 'yes'
    ET.SubElement(sota, 'deviceReboot').text = device_reboot

    # Generate the XML string with declaration
    xml_declaration = '<?xml version="1.0" encoding="utf-8"?>'
    xml_str = ET.tostring(manifest, encoding='utf-8', method='xml').decode('utf-8')
    return xml_declaration + '\n' + xml_str