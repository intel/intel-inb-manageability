"""
    Copyright (C) 2017-2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import xml.etree.ElementTree as ET
from google.protobuf.timestamp_pb2 import Timestamp
from cloudadapter.pb.common.v1.common_pb2 import UpdateSystemSoftwareOperation, Operation, Schedule
from cloudadapter.pb.inbs.v1.inbs_sb_pb2 import UpdateScheduledOperations


def create_xml_element(tag: str, text: str | None = None, attrib: dict[str, str] | None = None) -> ET.Element:
    """Create an XML element with optional text and attributes."""

    element = ET.Element(tag)
    if text:
        element.text = text
    if attrib:
        element.attrib = attrib
    return element


def protobuf_timestamp_to_iso(timestamp: Timestamp) -> str:
    """Converts a protobuf Timestamp to an ISO formatted string."""

    return timestamp.ToDatetime().isoformat()


def convert_schedule_to_xml(schedule: Schedule) -> ET.Element:
    """Converts a Schedule message to an XML element."""

    outer_schedule_element = create_xml_element('schedule')

    if schedule.HasField('single_schedule'):
        single = schedule.single_schedule
        single_schedule = create_xml_element('single_schedule')
        if single.job_id:
            job_id = create_xml_element('job_id', single.job_id)
            single_schedule.append(job_id)
        if single.HasField('start_time'):
            start_time = create_xml_element(
                'start_time', protobuf_timestamp_to_iso(single.start_time))
            single_schedule.append(start_time)
        if single.HasField('end_time'):
            end_time = create_xml_element('end_time', protobuf_timestamp_to_iso(single.end_time))
            single_schedule.append(end_time)
        outer_schedule_element.append(single_schedule)
        return outer_schedule_element
    elif schedule.HasField('repeated_schedule'):
        repeated = schedule.repeated_schedule
        repeated_schedule = create_xml_element('repeated_schedule')
        if repeated.job_id:
            job_id = create_xml_element('job_id', repeated.job_id)
            repeated_schedule.append(job_id)
        duration = create_xml_element('duration', 'PT' + str(repeated.duration.ToSeconds()) + 'S')
        repeated_schedule.extend([
            duration,
            create_xml_element('cron_minutes', repeated.cron_minutes),
            create_xml_element('cron_hours', repeated.cron_hours),
            create_xml_element('cron_day_month', repeated.cron_day_month),
            create_xml_element('cron_month', repeated.cron_month),
            create_xml_element('cron_day_week', repeated.cron_day_week),
        ])
        outer_schedule_element.append(repeated_schedule)
        return outer_schedule_element
    else:
        raise ValueError("invalid Schedule protobuf")


def convert_updated_scheduled_operations_to_dispatcher_xml(request_id: str, update_operations_proto: UpdateScheduledOperations) -> str:
    """Converts an UpdateScheduledOperations message to an XML string for Dispatcher."""

    root = create_xml_element('schedule_request')
    xml_request_id = create_xml_element('request_id', text=request_id)
    root.append(xml_request_id)

    for scheduled_operation in update_operations_proto.scheduled_operations:
        update_schedule = create_xml_element('update_schedule')
        for schedule in scheduled_operation.schedules:
            xml_schedules = convert_schedule_to_xml(schedule)
            update_schedule.append(xml_schedules)

        xml_manifests = convert_operation_to_xml_manifests(scheduled_operation.operation)
        update_schedule.append(xml_manifests)
        root.append(update_schedule)

    return ET.tostring(root, encoding='unicode')


def convert_operation_to_xml_manifests(operation: Operation) -> ET.Element:
    """Converts an Operation message to an XML manifests element containing manifest_xml subelements for dispatcher."""

    if not operation.HasField('update_system_software_operation'):
        raise ValueError("Operation type not supported")

    if len(operation.pre_operations) > 0:
        raise ValueError("Pre-operations not supported")

    if len(operation.post_operations) > 0:
        raise ValueError("Post-operations not supported")

    result = create_xml_element('manifests')
    for manifest in [convert_system_software_operation_to_xml_manifest(operation.update_system_software_operation)]:
        xml_manifest = create_xml_element('manifest_xml', text=manifest)
        result.append(xml_manifest)
    return result


def convert_system_software_operation_to_xml_manifest(operation: UpdateSystemSoftwareOperation) -> str:
    """Converts a UpdateSystemSoftwareOperation message to an XML manifest string for Dispatcher."""
    # Create the root element
    manifest = ET.Element('manifest')
    ET.SubElement(manifest, 'type').text = 'ota'
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
        UpdateSystemSoftwareOperation.DownloadMode.DOWNLOAD_MODE_NO_DOWNLOAD: 'no-download',
        UpdateSystemSoftwareOperation.DownloadMode.DOWNLOAD_MODE_DOWNLOAD_ONLY: 'download-only',
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
