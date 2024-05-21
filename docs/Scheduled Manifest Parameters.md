# Scheduled Request XML Schema Documentation

## Overview

This XML schema defines the structure for a scheduled request. It includes types for cron values, manifests, schedules, and the overall schedule request.

## Simple Types

### MinutesWithinHourCronValue

- **Type**: String
- **Pattern**: Matches a single minute within an hour (0-59), an asterisk (*), a hyphen (-), or a forward slash (/).

### HourWithinDayCronValue

- **Type**: String
- **Pattern**: Matches a single hour within a day (0-23), an asterisk (*), a hyphen (-), or a forward slash (/).

### DayOfMonthCronValue

- **Type**: String
- **Pattern**: Matches a single day within a month (1-31), an asterisk (*), a hyphen (-), or a forward slash (/).

### MonthCronValue

- **Type**: String
- **Pattern**: Matches a single month within a year (1-12), an asterisk (*), a hyphen (-), or a forward slash (/).

### DayOfWeekCronValue

- **Type**: String
- **Pattern**: Matches a single day within a week (0-6 where 0 is Sunday), an asterisk (*), a hyphen (-), or a forward slash (/).

## Complex Types

### INBMManifests

- **manifest_xml**: A sequence of strings, each representing a manifest XML. There can be multiple `manifest_xml` elements.

### SingleSchedule

- **start_time** (optional): The start time of the schedule, represented as a dateTime.
- **end_time** (optional): The end time of the schedule, represented as a dateTime.

### RepeatedSchedule

- **duration**: The duration of the schedule, represented as an XML duration.
- **cron_minutes**: The minute component of the cron schedule, using `MinutesWithinHourCronValue`.
- **cron_hours**: The hour component of the cron schedule, using `HourWithinDayCronValue`.
- **cron_day_month**: The day of the month component of the cron schedule, using `DayOfMonthCronValue`.
- **cron_month**: The month component of the cron schedule, using `MonthCronValue`.
- **cron_day_week**: The day of the week component of the cron schedule, using `DayOfWeekCronValue`.

### Schedule

- A choice between `single_schedule` and `repeated_schedule`. A schedule can contain zero or more of each.

### ScheduledOperation

- **schedule**: The schedule for the operation, using the `Schedule` type.
- **manifests**: The manifests associated with the operation, using the `INBMManifests` type.

## Root Element

### ScheduleRequest

- **request_id**: A string representing the unique identifier for the schedule request.
- **update_schedule**: A sequence of `ScheduledOperation` elements, each representing an operation to be scheduled. There can be multiple `update_schedule` elements.

## XML Structure

```xml
<schedule_request>
  <request_id>...</request_id>
  <update_schedule>
    <schedule>
      <!-- SingleSchedule or RepeatedSchedule -->
    </schedule>
    <manifests>
      <manifest_xml>...</manifest_xml>
      <!-- More manifest_xml elements allowed -->
    </manifests>
  </update_schedule>
  <!-- More update_schedule elements allowed -->
</schedule_request>
