# Scheduled Request XML Schema Documentation

## Overview

This XML schema defines the structure for a scheduled request. It includes types for cron values, manifests, schedules, and the overall schedule request.

NOTE: If the Dispatcher receives a new scheduled manifest, the contents of the APSheduler and Database will be removed and replaced with the entire contents of the received manifest.  Any schedules that were in the previous manifest and not in the new one will no longer be scheduled.

## XML Structure

```xml
<schedule_request>
  <request_id>...</request_id>
  <update_schedule>
    <schedule>
      <!-- multiple SingleSchedule and/or multiple RepeatedSchedule -->
    </schedule>
    <manifests>
      <manifest_xml>Valid INBM Manifest</manifest_xml>
      <!-- More manifest_xml elements allowed -->
    </manifests>
  </update_schedule>
  <!-- More update_schedule elements allowed -->
</schedule_request>
```

## Single Schedule - Immediate Execution

```xml
<single_schedule />
```

## Single Schedule with Start and End Time

```xml
<single_schedule>
  <job_id>swupd-f02131f9-b7d9-4e3f-9ee2-615e0fe005a5</job_id>
  <start_time>2023-04-01T08:00:00</start_time>
  <end_time>2023-04-01T17:00:00</end_time>
</single_schedule>
```

## Single Schedule with No End Time

```xml
<single_schedule>
  <job_id>swupd-f02131f9-b7d9-4e3f-9ee2-615e0fe005a5</job_id>
  <start_time>2023-04-01T08:00:00</start_time>
</single_schedule>
```

## Repeated Schedule

```xml
<repeated_schedule>
  <job_id>swupd-f02131f9-b7d9-4e3f-9ee2-615e0fe005a5</job_id>
  <duration>P1D</duration> <!-- P1D means a period of one day -->
  <cron_minutes>0</cron_minutes> <!-- At minute 0 -->
  <cron_hours>*/3</cron_hours> <!-- Every 3 hours -->
  <cron_day_month>*</cron_day_month> <!-- Every day of the month -->
  <cron_month>*</cron_month> <!-- Every month -->
  <cron_day_week>*</cron_day_week> <!-- Every day of the week -->
</repeated_schedule>    
```

## Root Element

### ScheduleRequest

- **request_id**: A string representing the unique identifier for the schedule request.
- **update_schedule**: A sequence of `ScheduledOperation` elements, each representing an operation to be scheduled. There can be multiple `update_schedule` elements.

## Complex Types

### INBMManifests

- **manifest_xml**: A sequence of strings, each representing a valid INBM manifest XML. There can be multiple `manifest_xml` elements.

### SingleSchedule

- **job_id**: Assigned by MJunct to track each individual schedule request.  In the format of an abbreviated job type descriptor (4-9 characters) followed by a UUID.
- **start_time** (optional): The start time of the schedule, represented as a dateTime.
- **end_time** (optional): The end time of the schedule, represented as a dateTime.

### RepeatedSchedule

- **job_id**: Assigned by MJunct to track each individual schedule request.  In the format of an abbreviated job type descriptor (4-9 characaters) followed by a UUID.
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
