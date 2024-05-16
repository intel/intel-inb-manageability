"""
    Parses the schedule manifest.

    Copyright (C) 2024 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import untangle

from typing import Optional

from .schedules import SingleSchedule, RepeatedSchedule
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
        self._validate_schedule_manifest(manifest, schedule_schema_location)
        self._xml_obj = untangle.parse(manifest)
        self._embedded_schema_location=embedded_schema_location
        
        # Parsed manifest data
        self.request_id = None
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
                
        self.request_id = self._xml_obj.schedule_request.request_id.cdata
        schedules: list[untangle.Element] = self._xml_obj.schedule_request.update_schedule
        
        for update_schedule in schedules:            
            manifests = self._get_manifests(update_schedule.manifests.children)
            if hasattr(update_schedule, 'schedule'):
                schedule = update_schedule.schedule
                if hasattr(schedule, 'single_schedule'):
                    self._parse_single_schedule(schedule, manifests)
                elif hasattr(schedule, 'repeated_schedule'):
                    repeated_schedule = schedule.repeated_schedule
                    rs = RepeatedSchedule(
                        cron_duration=repeated_schedule.duration.cdata,
                        cron_minutes=repeated_schedule.cron_minutes.cdata,
                        cron_hours=repeated_schedule.cron_hours.cdata,
                        cron_day_month=repeated_schedule.cron_day_month.cdata,
                        cron_month=repeated_schedule.cron_month.cdata,
                        cron_day_week=repeated_schedule.cron_day_week.cdata,
                        manifests=manifests)
                    self.repeated_scheduled_requests.append(rs)

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
    
    def _parse_single_schedule(self, schedule: untangle.Element, manifests: list[str]) -> None:
        single_schedule = schedule.single_schedule
        if not hasattr(single_schedule, 'start_time'):
            self.immedate_requests.append(
                SingleSchedule(
                    manifests=manifests))
        else: 
            end = schedule.single_schedule.end_time.cdata \
                if hasattr(single_schedule, 'end_time') else None

            self.single_scheduled_requests.append(
                SingleSchedule(
                start_time=schedule.single_schedule.start_time.cdata, 
                end_time=end,
                manifests=manifests))
