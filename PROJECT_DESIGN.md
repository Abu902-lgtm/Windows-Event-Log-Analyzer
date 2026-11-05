# Windows Event Log Analyzer

## 1. Problem Statement
Security logs can contain repeated failed logins and other events
that require investigation. Manually reviewing large log files can
be time-consuming.

## 2. Project Objectives
- Read Windows event records from a CSV file.
- Identify repeated failed login attempts.
- Flag unexpected shutdown events.
- Generate a readable security report.

## 3. Input Data
The initial version uses sample CSV records with event IDs,
timestamps, usernames, source IP addresses, and descriptions.

## 4. Detection Rules
- Event ID 4625: failed logon.
- Three or more failed logons from the same username and IP:
  generate a finding.
- Event ID 6008: unexpected shutdown.

## 5. Expected Output
A terminal summary and a text report saved in the reports folder.

## 6. Scope and Limitations
This is a learning prototype using CSV data. It does not yet
collect live logs, prove that an attack occurred, or replace a
professional security monitoring system.
