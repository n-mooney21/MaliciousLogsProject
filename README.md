# MaliciousLogsProject
# Log Threat Detection Scripts

This project is a set of PowerShell scripts that scan log files for signs of suspicious or malicious activity and save the results to a report.

## What it checks

- **Malicious IP addresses** in the web server log (`access.log`)
- **Suspicious Linux commands** in the authentication log (`auth.log`)
- **Malicious web paths**, such as `/wp-admin` and `/phpmyadmin`, in the web server log (`access.log`)

Each detection is given a risk level, and the full matching log line is included in the report.

## How to use it

1. Download or clone this repository and keep all the files together in one folder.
2. Open the folder in VS Code or PowerShell.
3. Run `automator.ps1`:

   ```powershell
   .\automator.ps1
   ```

4. Open `ProjectReportFile.txt` to see the results. A new report is created each time the script runs.

## Files

- `automator.ps1` runs the detectors and creates the report
- `project1.ps1` contains the three detectors
- `access.log` and `auth.log` are the sample logs that get scanned
