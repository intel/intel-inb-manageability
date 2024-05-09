"""
Conversion function to convert incoming proto messages from INBS to XML
"""

from datetime import datetime, timezone
import xml.etree.ElementTree as ET
import google.protobuf.timestamp_pb2
import google.protobuf.duration_pb2

from ..adapters.proto import inbs_sb_pb2


def convert_update_scheduled_tasks_request_to_xml(request_data: inbs_sb_pb2.UpdateScheduledTasksRequest, request_id: str) -> ET.Element:
    """Converts the UpdateScheduledTasksRequest protobuf (plus request ID) to Dispatcher XML format.
    """

    root = ET.Element('schedule_request')
    request_id_element = ET.SubElement(root, 'request_id')
    request_id_element.text = request_id

    for task in request_data.tasks:
        update_schedule = ET.SubElement(root, 'update_schedule')

        # Schedules
        for schedule in task.schedules:            
            if schedule.HasField('single_schedule'):
                schedule_element = ET.SubElement(update_schedule, 'single_schedule')
                schedule_element.append(convert_single_schedule_to_xml(schedule.single_schedule))
            elif schedule.HasField('repeated_schedule'):
                schedule_element = ET.SubElement(update_schedule, 'repeated_schedule')
                schedule_element.append(convert_repeated_schedule_to_xml(schedule.repeated_schedule))                

        update_schedule.append(convert_operation_to_manifests(task.operation))

    return root

def convert_single_schedule_to_xml(schedule: inbs_sb_pb2.SingleSchedule) -> ET.Element:
    """Converts the SingleSchedule protobuf to XML.
    """

    root = ET.Element('single_schedule')

    start_time_element = ET.SubElement(root, 'start_time')
    start_time_element.text = _google_timestamp_to_xml_datetime_format_quantized_seconds(schedule.start_time)

    end_time_element = ET.SubElement(root, 'end_time')
    end_time_element.text = _google_timestamp_to_xml_datetime_format_quantized_seconds(schedule.end_time)

    return root

def convert_repeated_schedule_to_xml(schedule: inbs_sb_pb2.RepeatedSchedule) -> ET.Element:
    """Converts the RepeatedSchedule protobuf to XML.
    """

    root = ET.Element('repeated_schedule')

    duration_element = ET.SubElement(root, 'duration')
    duration_element.text = str(protobuf_duration_to_xml_format(schedule.duration))

    cron_minutes_element = ET.SubElement(root, 'cron_minutes')
    cron_minutes_element.text = schedule.cron_minutes

    cron_hours_element = ET.SubElement(root, 'cron_hours')
    cron_hours_element.text = schedule.cron_hours

    cron_day_month_element = ET.SubElement(root, 'cron_day_month')
    cron_day_month_element.text = schedule.cron_day_month

    cron_month_element = ET.SubElement(root, 'cron_month')
    cron_month_element.text = schedule.cron_month

    cron_day_week_element = ET.SubElement(root, 'cron_day_week')
    cron_day_week_element.text = schedule.cron_day_week

    return root

def convert_operation_to_manifests(operation: inbs_sb_pb2.Operation) -> ET.Element:
    """Converts the Operation protobuf to a manifests XML element.
    """

    root = ET.Element('manifests')

    # Operation -> Manifests
    manifests_element = ET.SubElement(root, 'manifests')
    for pre_operation in operation.pre_operations:
        # TODO: encode pre_operation in XML
        pre_operation_xml_element = ET.SubElement(manifests_element, 'manifest_xml')
        pre_operation_xml_element.text = ''

    # TODO: encode operation in XML
    operation_xml_element = ET.SubElement(root, 'manifest_xml')
    operation_xml_element.text = ''

    for post_operation in operation.post_operations:
        # TODO encode post_operation in XML            
        post_operation_xml_element = ET.SubElement(root, 'manifest_xml')
        post_operation_xml_element.text = ''
    
    return root


def _google_timestamp_to_xml_datetime_format_quantized_seconds(timestamp: google.protobuf.timestamp_pb2.Timestamp) -> str:
    """Convert google timestamp to xml datetime, quantizing to seconds"""
    dt = datetime.fromtimestamp(timestamp.seconds, tz=timezone.utc)
    # Using replace to remove tzinfo while still maintaining it as UTC time
    dt = dt.replace(tzinfo=None)
    # Manually appending 'Z' to represent UTC
    return dt.isoformat() + 'Z'


def protobuf_duration_to_xml_format(duration: google.protobuf.duration_pb2.Duration) -> str:
    """Convert Google Protobuf Duration to XML duration string."""
    # Extract seconds and nanoseconds
    seconds = duration.seconds + 0.0
    nanos = duration.nanos

    # Calculate total seconds (including nanoseconds part)
    total_seconds = seconds + nanos / 1e9

    if total_seconds == 0:
        return "PT0S"

    # Get the sign and absolute value of total_seconds
    sign = '-' if total_seconds < 0 else ''
    total_seconds = abs(total_seconds)

    # Break the total seconds into days, hours, minutes, and seconds
    days, remainder = divmod(total_seconds, 86400)  # 86400 seconds in a day
    hours, remainder = divmod(remainder, 3600)     # 3600 seconds in an hour
    minutes, seconds = divmod(remainder, 60)       # 60 seconds in a minute

    # Build the ISO 8601 duration string
    duration_parts = [f"{int(days)}D" if days else "",
                      f"T",
                      f"{int(hours)}H" if hours else "",
                      f"{int(minutes)}M" if minutes else "",
                      f"{seconds:.6f}".rstrip('0').rstrip('.') + "S" if seconds else ""]
    duration_str = sign + 'P' + ''.join(duration_parts)

    if duration_str.endswith('T'):
        duration_str = duration_str[:-1]  # Remove trailing "T" if no time components

    return duration_str
