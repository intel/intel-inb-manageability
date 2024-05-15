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

from inbm_common_lib.utility import get_canonical_representation_of_path
from inbm_lib.path_prefixes import INTEL_MANAGEABILITY_SHARE_PATH_PREFIX
from inbm_lib.xmlhandler import *

logger = logging.getLogger(__name__)

SCHEMA_LOCATION = str(INTEL_MANAGEABILITY_SHARE_PATH_PREFIX /
                      'dispatcher-agent' / 'schedule_manifest_schema.xsd')


class ScheduleManifestParser:
    def __init__(self, manifest: str, schema_location=SCHEMA_LOCATION) -> None:
        self._manifest_root = self._validate_manifest(manifest, schema_location)
        self._xml_obj = untangle.parse(manifest)
        
        # Parsed manifest data
        self.request_id = None
        self.immedate_requests: SingleSchedule = []
        self.single_scheduled_requests: SingleSchedule = []
        self.repeated_scheduled_requests: RepeatedSchedule = []
        self._get_schedules()
        
    def _validate_manifest(self, xml: str,
                                      schema_location: Optional[str] = None) -> XmlHandler:
        """Validate manifest against schema

        @param xml: manifest in XML format
        @param schema_location: optional location of schema
        @return: root of manifest
        """
        # Added schema_location variable for unit tests
        schema_location = get_canonical_representation_of_path(
            schema_location) if schema_location is not None else get_canonical_representation_of_path(SCHEMA_LOCATION)
        root = XmlHandler(xml=xml,
                            is_file=False,
                            schema_location=schema_location)

        logger.debug(f"parsed: {(str(root))!r}.")                
        return root

    def _get_schedules(self) -> None:
        if not self._xml_obj:
            raise DispatcherException("Scheduled manifest was not parsed correctly")
        if not self._xml_obj.schedule_request:
            raise DispatcherException("No schedule requests found in the manifest")
                
        schedule_requests = self._xml_obj.schedule_request
        self.request_id = self._xml_obj.schedule_request.request_id.cdata
        update_schedules = self._xml_obj.schedule_request.update_schedule
        for request in schedule_requests:
            update_schedule = request.update_schedule
            manifests = self.get_manifests(update_schedule.manifests.children)
            if hasattr(update_schedule, 'schedule'):
                schedule = update_schedule.schedule
                if hasattr(schedule, 'single_schedule'):
                    if not hasattr(schedule, 'start_time'):
                        self.immedate_requests.append(
                            SingleSchedule(
                                manifests=manifests))
                    else:          
                        self.single_scheduled_requests.append(
                            SingleSchedule(
                            start_time=schedule.single_schedule.start_time.cdata, 
                            end_time=schedule.single_schedule.end_time.cdata,
                            manifests=manifests))                        
                elif hasattr(update_schedule, 'repeated_schedule'):
                    rs = RepeatedSchedule(
                        start_time=schedule.repeated_schedule.start_time.cdata, 
                        end_time=schedule.repeated_schedule.end_time.cdata,
                        repeat_interval=schedule.repeated_schedule.repeat_interval.cdata,
                        manifests=manifests)
                    self.repeated_scheduled_requests.append(rs)

    def get_manifests(self, scheduled_manifests: list[untangle.Element]) -> list[str]:
        manifests: list[str] = []
        for manifest in scheduled_manifests:
            manifests.append(manifest.cdata)
        return manifests
