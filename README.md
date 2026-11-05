# Windows Event Log Analyzer

A Python-based tool to analyze Windows Event Log data for potentially suspicious activity.

**Author:** Muhammad Abu Talib  
**Project Area:** Digital Forensics and Incident Response (DFIR)

## 1. Overview

The Windows Event Log Analyzer is a Python-based project designed to examine Windows Event Log data exported into CSV format. It identifies selected security events and highlights potentially suspicious activity for further forensic investigation.

## 2. Objectives

- Analyze Windows security events.
- Identify successful and failed logons.
- Detect repeated failed logon attempts.
- Extract available usernames, timestamps, workstation details, and IP addresses.
- Identify unexpected system shutdown events.
- Generate a security analysis report.

## 3. Technologies Used

- Python 3
- Kali Linux
- Windows Event Viewer
- CSV
- Git and GitHub

## 4. Project Structure

```text
Windows-Event-Log-Analyzer/
├── analyzer.py
├── README.md
├── PROJECT_DESIGN.md
├── .gitignore
├── logs/
│   └── sample_logs.csv
├── reports/
│   └── .gitkeep
└── docs/
```

## 5. Detection Logic

| Event ID | Description | Forensic Significance |
|---|---|---|
| 4624 | Successful logon | Helps identify account access activity. |
| 4625 | Failed logon | Helps identify unsuccessful authentication attempts. |
| 6008 | Unexpected shutdown | Helps identify unexpected system shutdown activity. |

The analyzer also checks for repeated failed logon attempts within a 10-minute time window.

## 6. Installation and Usage

Requirements:
- Python 3
- Kali Linux or another Python-compatible operating system
- CSV data exported from Windows Event Viewer

Run the analyzer:

```bash
python3 analyzer.py
```

Review the generated report in the `reports/` directory.

## 7. Input Data Format

The CSV input should contain these columns:

```text
EventID,Timestamp,Username,SourceIP,Description
```

A synthetic sample dataset is provided in `logs/sample_logs.csv`.

## 8. EVTX Processing

Windows Event Viewer stores event logs in EVTX format. The current version of this analyzer processes CSV files exported from Windows Event Viewer.

EVTX files must therefore be exported into CSV format before analysis. Direct EVTX parsing is not currently implemented.

## 9. Testing and Evaluation

The analyzer was tested using synthetic sample data and an authorized Windows Event Viewer CSV export.

The real-data test processed 200 event records, including 139 successful logons and 61 failed logons. Repeated failed logon activity was identified for further investigation.

The availability of IP addresses and other fields depends on the original event data and CSV export.

## 10. Limitations

- The current version supports CSV input rather than direct EVTX parsing.
- Some event records may not contain source IP addresses.
- Detection is limited to the selected event IDs and implemented rules.
- Findings require further forensic investigation and do not independently prove malicious activity.

## 11. Future Improvements

- Add direct EVTX file parsing.
- Expand suspicious activity detection rules.
- Improve extraction and normalization of event details.
- Add additional reporting and visualization features.

## 12. Author

**Muhammad Abu Talib**  
Digital Forensics and Incident Response (DFIR) Project
