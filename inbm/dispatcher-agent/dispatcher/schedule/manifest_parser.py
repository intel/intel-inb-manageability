"""
    Parses the schedule manifest.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import untangle

from typing import Optional

from .schedules import SingleSchedule, RepeatedSchedule, Schedule
from ..dispatcher_exception import DispatcherException
from ..constants import SCHEMA_LOCATION

from inbm_common_lib.utility import get_canonical_representation_of_path
from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_SHARE_PATH_PREFIX
from inbm_lib.xmlhandler import *

logger = logging.getLogger(__name__)

SCHEDULE_SCHEMA_LOCATION = str(INTEL_MANAGEABILITY_SHARE_PATH_PREFIX /
                               'dispatcher-agent' / 'schedule_manifest_schema.xsd')


class ScheduleManifestParser:

    def __init__(self, manifest: str,
                 schedule_schema_location=SCHEDULE_SCHEMA_LOCATION, embedded_schema_location=SCHEMA_LOCATION) -> None:
        """Parses the Scheduled Manifest and stores the schedules and valid Inband
        manifests in the appropriate object and list.

        @param manifest (str): root of scheduled manifest
        @param schedule_schema_location (_type_, optional): XML Schema to use when validating the scheduled manifest. Defaults to SCHEDULE_SCHEMA_LOCATION.
        @param embedded_schema_location (_type_, optional): XML Schema to validate the embedded Inband manifests. Defaults to SCHEMA_LOCATION.
        """
        self._validate_schedule_manifest(manifest, schedule_schema_location)
        self._xml_obj = untangle.parse(manifest)
        self._embedded_schema_location = embedded_schema_location

        # Parsed manifest data
        self.immedate_requests: list[SingleSchedule] = []
        self.single_scheduled_requests: list[SingleSchedule] = []
        self.repeated_scheduled_requests: list[RepeatedSchedule] = []
        self._get_schedules()

    def _validate_schedule_manifest(self, xml: str,
                                    schema_location: Optional[str] = None) -> None:
        """Validate manifest against schema

        @param xml: manifest in XML format
        @param schema_location: optional location of schema
        """
        # Added schema_location variable for unit tests
        schema_location = get_canonical_representation_of_path(
            schema_location) if schema_location is not None else get_canonical_representation_of_path(SCHEMA_LOCATION)
        root = XmlHandler(xml=xml,
                          is_file=False,
                          schema_location=schema_location)

        logger.debug(f"parsed: {(str(root))!r}.")

    def _get_schedules(self) -> None:
        if not self._xml_obj:
            raise DispatcherException("Scheduled manifest was not parsed correctly")
        if not self._xml_obj.schedule_request:
            raise DispatcherException("No schedule requests found in the manifest")

        request_id = self._xml_obj.schedule_request.request_id.cdata
        if not request_id:
            raise DispatcherException("Request ID not found in the manifest")
        update_schedules: list[untangle.Element] = self._xml_obj.schedule_request.update_schedule

        for update_schedule in update_schedules:
            manifests = self._get_manifests(update_schedule.manifests.children)
            if hasattr(update_schedule, 'schedule'):
                schedule = update_schedule.schedule
                if 'single_schedule' in schedule:
                    schedule_details = Schedule(request_id=request_id, manifests=manifests)
                    self._parse_single_schedule(schedule, schedule_details)
                if 'repeated_schedule' in schedule:
                    schedule_details = Schedule(request_id=request_id, manifests=manifests)
                    self._parse_repeated_schedule(schedule, schedule_details)


    def _get_manifests(self, scheduled_manifests: list[untangle.Element]) -> list[str]:
        manifests: list[str] = []
        for manifest in scheduled_manifests:
            self._validate_inband_manifest(manifest.cdata)
            manifests.append(manifest.cdata)
        return manifests

    def _validate_inband_manifest(self, manifest: str) -> None:
        """Validate inband manifest.  This is just to make sure the manifest is valid
        that was provided within the schedule manifest.  

        @param manifest: inband manifest
        """
        XmlHandler(xml=manifest,
                   is_file=False,
                   schema_location=self._embedded_schema_location)

    def _parse_single_schedule(self, schedule: untangle.Element, schedule_details: Schedule) -> None:
        """Parses the single schedules in the manifest and stores them
        in the SingleSchedule object list.

        @param schedule (untangle.Element): pointer to the schedule elements
        @param manifests (list[str]): list of valid Inband manifests to be scheduled
        @param request_id (str): request ID from manifest
        """
        single_schedule = schedule.single_schedule
        for ss in single_schedule:
            if not hasattr(ss, 'start_time'):
                self.immedate_requests.append(
                    SingleSchedule(
                        request_id=schedule_details.request_id,
                        job_id=ss.job_id.cdata,
                        manifests=schedule_details.manifests))
            else:
                end = ss.end_time.cdata if hasattr(ss, 'end_time') else None
                self.single_scheduled_requests.append(
                    SingleSchedule(
                        request_id=schedule_details.request_id,
                        job_id=ss.job_id.cdata,
                        start_time=ss.start_time.cdata,
                        end_time=end,
                        manifests=schedule_details.manifests))

    def _parse_repeated_schedule(self, schedule: untangle.Element, schedule_details: Schedule) -> None:
        """Parses the repeated schedules in the manifest and stores them
        in the RepeatedSchedule object list.

        @param schedule (untangle.Element): pointer to the schedule elements
        @param manifests (list[str]): list of valid Inband manifests to be scheduled
        @param request_id (str): request ID from manifest
        """
        repeated_schedules = schedule.repeated_schedule
        for repeated_schedule in repeated_schedules:
            rs = RepeatedSchedule(
                request_id=schedule_details.request_id,
                job_id=repeated_schedule.job_id.cdata,
                cron_duration=repeated_schedule.duration.cdata,
                cron_minutes=repeated_schedule.cron_minutes.cdata,
                cron_hours=repeated_schedule.cron_hours.cdata,
                cron_day_month=repeated_schedule.cron_day_month.cdata,
                cron_month=repeated_schedule.cron_month.cdata,
                cron_day_week=repeated_schedule.cron_day_week.cdata,
                manifests=schedule_details.manifests)
            self.repeated_scheduled_requests.append(rs)
