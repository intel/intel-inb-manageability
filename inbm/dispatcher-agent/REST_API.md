# Telemetry REST API

### GET /telemetry

Get most recent log entries up to limit.  Default limit is 10.  Limit can be specified up to 1000.
- Parameters: `limit`
- Responses: 
    `400 Bad Request` and `200` 
- Sample response:
    ```
    [
        {timestamp: 123456.11, message: 'This is a debug log message'},
        {timestamp: 123459.43, message: 'This is an info log message' }
    ]
    ```
- Timestamps are seconds since epoch in UTC.
