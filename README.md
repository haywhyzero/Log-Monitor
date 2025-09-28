# Interactive Log Monitoring Script

A versatile Python script for monitoring and analyzing various types of log files. It interactively prompts the user to select a log type, parses the corresponding file for suspicious patterns based on predefined rules, and generates a detailed report with alerts.

This tool is designed to be a simple yet effective solution for quick log analysis, particularly for identifying security and operational issues like IP flooding, repeated login failures, and high error rates. 

## OpenSource Code
It is fully customizable 
All test logs used were generated for development stage
Tested and deloyed for tailing logs

## Features

- **Interactive CLI**: Simple command-line prompts to guide the user.
- **Multi-Log Support**: Out-of-the-box support for different log formats:
  - `apache`: Standard web server access logs.
  - `auth`: SSH authentication failure logs (e.g., from `/var/log/auth.log`).
  - `baggage`: Custom format for Baggage Handling System (BHS) operational errors.
- **Rule-Based Alerting**: Triggers alerts based on configurable thresholds for:
  - High request volume from a single IP.
  - Excessive server errors (5xx status codes).
  - Repeated failed login attempts.
- **Detailed Reporting**: Generates a clean, readable report file (`<log_type>_report.txt`) containing:
  - A summary of event counts.
  - A clear list of triggered alerts.
  - A sample of the suspicious log lines that triggered the alerts.
- **Extensible**: New log patterns and rules can be easily added by modifying the `LOG_PATTERNS` dictionary.

## Supported Log Formats

The script uses regular expressions to parse specific log formats.

### Apache
Matches the common log format for IP, user, timestamp, request, status, and size.
```log
192.168.1.10 - - [27/Sep/2025:15:23:01 +0000] "GET /login HTTP/1.1" 401 2966
```

### Auth
Matches failed SSH password attempts, capturing the timestamp, host, user, and source IP.
```log
May 27 10:30:00 my-server sshd[1234]: Failed password for invaliduser from 203.0.113.5 port 12345
```

### Baggage
A custom format designed to capture errors from operational equipment like BHS devices.
```log
2025-09-27 10:00:26 Belt02 ERROR Conveyor jam detected
```

## How to Run

1.  Ensure you have Python 3 installed.
2.  Open your terminal or command prompt and navigate to the project directory.
3.  Run the script:
    ```sh
    python auth_monitor.py
    ```
4.  The script will prompt you to choose a log type. Enter one of the available options (e.g., `apache`).
    ```
    Available log types: apache, auth, baggage
    Which log do you want to monitor? apache
    ```
5.  Next, provide the full path to the log file you want to analyze.
    ```
    Enter the path for apache log file (.log, .txt, etc): C:\Users\mycomputer\ocd\scripts\projects\test_log.log or public_html/access.log
    ```
6.  The script will wait for the file incase it isn't create yet, process it, and generate a report named `apache_report.txt` in the same directory.

## Configuration

The alerting thresholds can be easily configured by changing the constant values at the top of the `auth_monitor.py` file:

```python
# ---------- Thresholds ----------
REQUEST_THRESHOLD = 5
ERROR_STATUS_THRESHOLD = 3
FAILED_LOGIN_THRESHOLD = 3
```

- `REQUEST_THRESHOLD`: Maximum number of requests from a single IP before a "high volume" alert is triggered.
- `ERROR_STATUS_THRESHOLD`: Maximum number of 5xx errors from a single IP/device before an "error" alert is triggered.
- `FAILED_LOGIN_THRESHOLD`: Maximum number of failed logins from a single IP before a "failed logins" alert is triggered.

---

*Author: Ayomide Aregbe*
