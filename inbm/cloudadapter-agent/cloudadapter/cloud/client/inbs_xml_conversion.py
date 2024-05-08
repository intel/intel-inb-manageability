"""
Conversion function to convert incoming proto messages from INBS to XML
"""

from datetime import datetime, timezone
import xml.etree.ElementTree as ET
import google.protobuf.timestamp_pb2
import google.protobuf.duration_pb2

from ..adapters.proto import inbs_sb_pb2


def convert_schedule_proto_to_xml(request_data: inbs_sb_pb2.SetScheduleRequestData) -> str:
    """Converts the SetSCheduleRequestData protobuf to XML"""

    root = ET.Element('ScheduleManifest')

    for task in request_data.tasks:
        update_schedule = ET.SubElement(root, 'update_schedule')

        # Manifests
        manifests_element = ET.SubElement(update_schedule, 'manifests')
        for manifest in task.manifests.manifest_xml:
            manifest_xml_element = ET.SubElement(manifests_element, 'manifest_xml')
            manifest_xml_element.text = manifest

        # Schedules
        if task.HasField('single_schedule'):
            schedule_element = ET.SubElement(update_schedule, 'single_schedule')
            start_time_element = ET.SubElement(schedule_element, 'start_time')
            end_time_element = ET.SubElement(schedule_element, 'end_time')

            start_time_element.text = _google_timestamp_to_xml_datetime_quantized_seconds(
                task.single_schedule.start_time)
            end_time_element.text = _google_timestamp_to_xml_datetime_quantized_seconds(
                task.single_schedule.end_time)

        elif task.HasField('repeated_schedule'):
            schedule_element = ET.SubElement(update_schedule, 'repeated_schedule')

            duration_element = ET.SubElement(schedule_element, 'duration')
            duration_element.text = str(protobuf_duration_to_xml(task.repeated_schedule.duration))

            cron_minutes_element = ET.SubElement(schedule_element, 'cron_minutes')
            cron_minutes_element.text = task.repeated_schedule.cron_minutes

            cron_hours_element = ET.SubElement(schedule_element, 'cron_hours')
            cron_hours_element.text = task.repeated_schedule.cron_hours

            cron_day_month_element = ET.SubElement(schedule_element, 'cron_day_month')
            cron_day_month_element.text = task.repeated_schedule.cron_day_month

            cron_month_element = ET.SubElement(schedule_element, 'cron_month')
            cron_month_element.text = task.repeated_schedule.cron_month

            cron_day_week_element = ET.SubElement(schedule_element, 'cron_day_week')
            cron_day_week_element.text = task.repeated_schedule.cron_day_week

    return ET.tostring(root, encoding="unicode")


def _google_timestamp_to_xml_datetime_quantized_seconds(timestamp: google.protobuf.timestamp_pb2.Timestamp):
    """Convert google timestamp to xml datetime, quantizing to seconds"""
    dt = datetime.fromtimestamp(timestamp.seconds, tz=timezone.utc)
    # Using replace to remove tzinfo while still maintaining it as UTC time
    dt = dt.replace(tzinfo=None)
    # Manually appending 'Z' to represent UTC
    return dt.isoformat() + 'Z'

def protobuf_duration_to_xml(duration: google.protobuf.duration_pb2.Duration):
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