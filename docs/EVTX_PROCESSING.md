# Windows EVTX Processing Workflow

## Overview

Windows Event Viewer stores event records in EVTX format.

The current analyzer processes CSV files exported from Windows Event Viewer.

## Processing Workflow

1. Open Windows Event Viewer.
2. Select the relevant Windows event log.
3. Export the required events into CSV format.
4. Transfer the CSV file to the authorized analysis environment.
5. Place the CSV file in the project's logs directory.
6. Run the Python analyzer.
7. Review the generated security report.

## Events Analyzed

- Event ID 4624: Successful logon.
- Event ID 4625: Failed logon.
- Event ID 6008: Unexpected shutdown.

## Current Limitation

The current version does not directly read EVTX files. EVTX records must first be exported into CSV format.
