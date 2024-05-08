"""
Unit tests for INBS Client XML Conversion
"""


from cloudadapter.cloud.client.inbs_xml_conversion import convert_schedule_proto_to_xml, protobuf_duration_to_xml
from cloudadapter.cloud.adapters.proto.inbs_sb_pb2 import SetScheduleRequestData, INBMScheduledTask, Manifests, SingleSchedule, RepeatedSchedule
import unittest
import google.protobuf.timestamp_pb2
import google.protobuf.duration_pb2


class TestInbsXmlConversion(unittest.TestCase):
    def test_convert_empty_schedule_request(self):
        xml = convert_schedule_proto_to_xml(SetScheduleRequestData())
        assert xml == "<ScheduleManifest />"

    def test_convert_task_with_empty_manifests(self):
        xml = convert_schedule_proto_to_xml(
            SetScheduleRequestData(
                tasks=[INBMScheduledTask(manifests=Manifests())]
            )
        )
        expected_xml = (
            "<ScheduleManifest>"
            "<update_schedule>"
            "<manifests />"
            "</update_schedule>"
            "</ScheduleManifest>"
        )
        self.assertEqual(xml, expected_xml)

    def test_convert_multiple_manifests(self):
        xml = convert_schedule_proto_to_xml(
            SetScheduleRequestData(
                tasks=[
                    INBMScheduledTask(
                        manifests=Manifests(
                            manifest_xml=["<xml1/>", "<xml2/>"]
                        ),
                        single_schedule=SingleSchedule(
                            start_time=google.protobuf.timestamp_pb2.Timestamp(
                                seconds=10, nanos=10),
                            end_time=google.protobuf.timestamp_pb2.Timestamp(seconds=20),
                        )
                    )
                ]
            )
        )
        expected_xml = (
            "<ScheduleManifest>"
            "<update_schedule>"
            "<manifests>"
            "<manifest_xml>&lt;xml1/&gt;</manifest_xml>"
            "<manifest_xml>&lt;xml2/&gt;</manifest_xml>"
            "</manifests>"
            "<single_schedule>"
            "<start_time>1970-01-01T00:00:10Z</start_time>"
            "<end_time>1970-01-01T00:00:20Z</end_time>"
            "</single_schedule>"
            "</update_schedule>"
            "</ScheduleManifest>"
        )
        self.assertEqual(xml, expected_xml)

    def test_convert_schedule_proto_to_xml(self):
        xml = convert_schedule_proto_to_xml(
            SetScheduleRequestData(
                tasks=[
                    INBMScheduledTask(
                        manifests=Manifests(
                            manifest_xml=["<xml1></xml1>", "<xml2></xml2>"]
                        ),
                        single_schedule=SingleSchedule(
                            start_time=google.protobuf.timestamp_pb2.Timestamp(
                                seconds=10
                            ),
                            end_time=google.protobuf.timestamp_pb2.Timestamp(
                                seconds=20
                            ),
                        ),
                    ),
                    INBMScheduledTask(
                        manifests=Manifests(
                            manifest_xml=["<xml3></xml3>"]
                        ),
                        repeated_schedule=RepeatedSchedule(
                            duration=google.protobuf.duration_pb2.Duration(
                                seconds=500
                            ),
                            cron_minutes="5",
                            cron_hours="*",
                            cron_day_month="*",
                            cron_month="*",
                            cron_day_week="*"
                        )
                    )
                ]
            )
        )
        self.maxDiff = None
        self.assertEqual(
            xml,
            (
                "<ScheduleManifest>"
                "<update_schedule>"
                "<manifests>"
                "<manifest_xml>&lt;xml1&gt;&lt;/xml1&gt;</manifest_xml>"
                "<manifest_xml>&lt;xml2&gt;&lt;/xml2&gt;</manifest_xml>"
                "</manifests>"
                "<single_schedule>"
                "<start_time>1970-01-01T00:00:10Z</start_time>"
                "<end_time>1970-01-01T00:00:20Z</end_time>"
                "</single_schedule>"
                "</update_schedule>"
                "<update_schedule>"
                "<manifests>"
                "<manifest_xml>&lt;xml3&gt;&lt;/xml3&gt;</manifest_xml>"
                "</manifests>"
                "<repeated_schedule>"
                "<duration>PT8M20S</duration>"
                "<cron_minutes>5</cron_minutes>"
                "<cron_hours>*</cron_hours>"
                "<cron_day_month>*</cron_day_month>"
                "<cron_month>*</cron_month>"
                "<cron_day_week>*</cron_day_week>"
                "</repeated_schedule>"
                "</update_schedule>"
                "</ScheduleManifest>"
            )
        )

    def test_positive_duration(self):
        # Create a Google protobuf Duration
        duration = google.protobuf.duration_pb2.Duration()
        duration.seconds = 3661
        duration.nanos = 500000000

        # Expected XML duration string
        expected = "PT1H1M1.5S"

        # Test the function
        result = protobuf_duration_to_xml(duration)
        self.assertEqual(result, expected)

    def test_negative_duration(self):
        # Create a Google protobuf Duration
        duration = google.protobuf.duration_pb2.Duration()
        duration.seconds = -3661
        duration.nanos = -200000000

        # Expected XML duration string
        expected = "-PT1H1M1.2S"

        # Test the function
        result = protobuf_duration_to_xml(duration)
        self.assertEqual(result, expected)

    def test_zero_duration(self):
        duration = google.protobuf.duration_pb2.Duration()
        duration.seconds = 0
        duration.nanos = 0

        expected = "PT0S"

        result = protobuf_duration_to_xml(duration)
        self.assertEqual(result, expected)

    def test_duration_with_days(self):
        duration = google.protobuf.duration_pb2.Duration()
        duration.seconds = 90000  # 1 day and 1 hour
        duration.nanos = 0

        expected = "P1DT1H"

        result = protobuf_duration_to_xml(duration)
        self.assertEqual(result, expected)

    def test_duration_with_fractional_seconds(self):
        duration = google.protobuf.duration_pb2.Duration()
        duration.seconds = 60
        duration.nanos = 9000000

        expected = "PT1M0.009S"

        result = protobuf_duration_to_xml(duration)
        self.assertEqual(result, expected)


if __name__ == '__main__':
    unittest.main()
