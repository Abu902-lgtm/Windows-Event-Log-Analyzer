# Windows Event Log Analyzer

**Author:** Muhammad Abu Talib  
**Project Area:** Digital Forensics and Incident Response (DFIR)

## Overview

A Python-based tool that analyzes Windows Event Log data exported into CSV format and identifies potentially suspicious activities.

## Objectives

- Analyze Windows security events.
- Identify successful and failed logons.
- Detect repeated failed logon attempts.
- Extract available usernames, timestamps, workstation details and IP addresses.
- Generate a security analysis report.

## Technologies

- Python 3
- Kali Linux
- Windows Event Viewer
- CSV
- Git and GitHub

## Project Structure

- `analyzer.py` — Main analysis program.
- `logs/sample_logs.csv` — Sample input data.
- `reports/` — Generated reports.
- `docs/` — Project documentation.
- `PROJECT_DESIGN.md` — Project design.

## Detection Logic

- Event ID 4624: Successful logon.
- Event ID 4625: Failed logon.
- Event ID 6008: Unexpected shutdown.
- Repeated failed logons within a defined time window.

## Usage

Run:

    python3 analyzer.py

The analyzer processes the configured CSV file and generates a report.

## Input Format

The current version supports Windows Event Viewer data exported into CSV format.

Native EVTX parsing is not yet implemented.

## Limitations

- Some events do not contain a source IP address.
- Windows event fields may require additional parsing.
- Detection results are investigative leads and require manual verification.

## Author

Muhammad Abu Talib
