
import csv
import re
import ipaddress
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

LOG_FILE = BASE_DIR / "logs" / "windows_events.csv"
REPORT_FILE = BASE_DIR / "reports" / "security_report.txt"

FAILURE_THRESHOLD = 3
TIME_WINDOW_MINUTES = 10

ALIASES = {
    "eventid": ["eventid", "event id", "id"],
    "timestamp": [
        "timestamp", "timecreated", "date and time", "date"
    ],
    "username": [
        "username", "targetusername", "account name", "user"
    ],
    "sourceip": [
        "sourceip", "ipaddress", "source network address",
        "clientaddress"
    ],
    "description": [
        "description", "message", "general"
    ]
}


# --------------------------------------------------
# FIELD MAPPING AND EXTRACTION
# --------------------------------------------------

def normalize(value):
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def get_field(row, field):
    for key, value in row.items():
        if normalize(key) in ALIASES[field]:
            return str(value or "").strip()

    return ""


def extract_value(message, labels):
    """Extract a labelled value from a Windows event message."""

    for label in labels:
        pattern = (
            rf"{re.escape(label)}\s*:\s*([^\t\r\n]+)"
        )

        match = re.search(pattern, message, re.IGNORECASE)

        if match:
            value = match.group(1).strip()

            if value and value not in ("-", "N/A"):
                return value

    return ""


def extract_section(message, start_label, end_labels):
    """Extract a section of a Windows event message."""

    start = re.search(
        re.escape(start_label) + r"\s*:",
        message,
        re.IGNORECASE
    )

    if not start:
        return ""

    section = message[start.end():]

    end_positions = []

    for label in end_labels:
        match = re.search(
            re.escape(label) + r"\s*:",
            section,
            re.IGNORECASE
        )

        if match:
            end_positions.append(match.start())

    if end_positions:
        section = section[:min(end_positions)]

    return section


def extract_username(event_id, csv_username, message):
    """Extract the account involved in the logon event."""

    if event_id == "4625":
        section = extract_section(
            message,
            "Account For Which Logon Failed",
            [
                "Failure Information",
                "Process Information",
                "Network Information"
            ]
        )

        username = extract_value(section, ["Account Name"])

        if username:
            return username

    elif event_id == "4624":
        section = extract_section(
            message,
            "New Logon",
            [
                "Process Information",
                "Network Information",
                "Detailed Authentication Information"
            ]
        )

        username = extract_value(section, ["Account Name"])

        if username:
            return username

    username = extract_value(
        message,
        ["TargetUserName", "Account Name"]
    )

    if username:
        return username

    if csv_username and csv_username.upper() not in ("SYSTEM", "-"):
        return csv_username

    return "Unknown"


def extract_ip(csv_ip, message):
    """Accept only valid IPv4 or IPv6 addresses."""

    candidates = []

    if csv_ip:
        candidates.append(csv_ip)

    message_ip = extract_value(
        message,
        [
            "Source Network Address",
            "IpAddress",
            "Source IP Address",
            "Client Address"
        ]
    )

    if message_ip:
        candidates.append(message_ip)

    for candidate in candidates:
        candidate = candidate.strip().strip("[]")

        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue

    return "Not recorded"


def extract_timestamp(value):
    """Parse common Windows CSV timestamp formats."""

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%d/%m/%Y %H:%M:%S"
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue

    return None


def extract_event_details(message):
    return {
        "logon_type": extract_value(
            message, ["Logon Type"]
        ) or "Not recorded",

        "process": extract_value(
            message,
            ["Caller Process Name", "Process Name"]
        ) or "Not recorded",

        "workstation": extract_value(
            message, ["Workstation Name"]
        ) or "Not recorded",

        "failure_reason": extract_value(
            message, ["Failure Reason"]
        ) or "Not recorded"
    }


# --------------------------------------------------
# LOAD CSV EVENTS
# --------------------------------------------------

def load_events():

    events = []
    skipped = 0

    if not LOG_FILE.exists():
        raise FileNotFoundError(
            f"Input file not found: {LOG_FILE}"
        )

    with open(
        LOG_FILE,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("CSV file has no headers.")

        for row in reader:

            event_id = get_field(row, "eventid")
            timestamp = get_field(row, "timestamp")
            csv_username = get_field(row, "username")
            csv_ip = get_field(row, "sourceip")
            description = get_field(row, "description")

            if not event_id.isdigit():
                skipped += 1
                continue

            username = extract_username(
                event_id,
                csv_username,
                description
            )

            source_ip = extract_ip(
                csv_ip,
                description
            )

            details = extract_event_details(description)

            events.append({
                "event_id": event_id,
                "timestamp": timestamp or "Not recorded",
                "username": username,
                "source_ip": source_ip,
                "logon_type": details["logon_type"],
                "process": details["process"],
                "workstation": details["workstation"],
                "failure_reason": details["failure_reason"],
                "description": description
            })

    return events, skipped


# --------------------------------------------------
# DETECTION LOGIC
# --------------------------------------------------

def analyze(events, skipped):

    counts = Counter(
        event["event_id"] for event in events
    )

    failed_logons = [
        event for event in events
        if event["event_id"] == "4625"
    ]

    successful_logons = [
        event for event in events
        if event["event_id"] == "4624"
    ]

    findings = []

    # Group failed logons by account, IP, workstation
    # and logon type. Process name is retained as
    # evidence but is not used to split the groups.

    groups = defaultdict(list)

    for event in failed_logons:

        key = (
            event["username"],
            event["source_ip"],
            event["workstation"],
            event["logon_type"]
        )

        groups[key].append(event)

    # Detect repeated failures within a 10-minute window.

    for key, records in groups.items():

        username, source_ip, workstation, logon_type = key

        valid_records = []

        for event in records:

            event_time = extract_timestamp(
                event["timestamp"]
            )

            if event_time is not None:
                valid_records.append(
                    (event_time, event)
                )

        valid_records.sort(key=lambda item: item[0])

        best_window = []

        for i, (start_time, start_event) in enumerate(
            valid_records
        ):

            window = [
                item for item in valid_records[i:]
                if item[0] <= start_time + timedelta(
                    minutes=TIME_WINDOW_MINUTES
                )
            ]

            if len(window) > len(best_window):
                best_window = window

        if len(best_window) >= FAILURE_THRESHOLD:

            window_events = [
                item[1] for item in best_window
            ]

            processes = sorted(set(
                event["process"] for event in window_events
            ))

            reasons = sorted(set(
                event["failure_reason"]
                for event in window_events
            ))

            findings.append({
                "level": "ALERT",
                "title": "Repeated failed logons",
                "count": len(best_window),
                "username": username,
                "source_ip": source_ip,
                "workstation": workstation,
                "logon_type": logon_type,
                "process": "; ".join(processes),
                "failure_reason": "; ".join(reasons),
                "first_seen": best_window[0][1]["timestamp"],
                "last_seen": best_window[-1][1]["timestamp"],
                "explanation": (
                    f"{len(best_window)} failed logons occurred "
                    f"within {TIME_WINDOW_MINUTES} minutes. "
                    "This pattern may warrant investigation "
                    "for repeated authentication failures. "
                    "It does not independently prove an attack."
                )
            })

    # Detect unexpected shutdown events (6008).

    for event in events:

        if event["event_id"] == "6008":

            findings.append({
                "level": "WARNING",
                "title": "Unexpected system shutdown",
                "count": 1,
                "username": event["username"],
                "source_ip": event["source_ip"],
                "workstation": event["workstation"],
                "logon_type": event["logon_type"],
                "process": event["process"],
                "failure_reason": event["failure_reason"],
                "first_seen": event["timestamp"],
                "last_seen": event["timestamp"],
                "explanation": (
                    "An unexpected shutdown was recorded. "
                    "Correlate this event with surrounding "
                    "system events and the incident timeline."
                )
            })

    return (
        counts,
        failed_logons,
        successful_logons,
        findings,
        skipped
    )


# --------------------------------------------------
# REPORT GENERATION
# --------------------------------------------------

def create_report(
    events,
    counts,
    failed,
    successful,
    findings,
    skipped
):

    REPORT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as report:

        report.write("WINDOWS EVENT LOG ANALYZER\n")
        report.write("=" * 60 + "\n\n")

        report.write(f"Input file: {LOG_FILE.name}\n")
        report.write(f"Total events analyzed: {len(events)}\n")
        report.write(
            f"Successful logons (4624): {len(successful)}\n"
        )
        report.write(
            f"Failed logons (4625): {len(failed)}\n"
        )
        report.write(
            f"Invalid or skipped rows: {skipped}\n"
        )
        report.write(
            f"Findings generated: {len(findings)}\n"
        )

        report.write("\nEVENT ID SUMMARY\n")
        report.write("-" * 60 + "\n")

        for event_id, count in sorted(counts.items()):
            report.write(
                f"Event ID {event_id}: {count}\n"
            )

        report.write("\nDETECTION FINDINGS\n")
        report.write("-" * 60 + "\n")

        if not findings:
            report.write(
                "No findings met the configured detection rules.\n"
            )

        for number, finding in enumerate(findings, 1):

            report.write(
                f"\nFinding {number}: {finding['title']}\n"
            )

            report.write(
                f"Severity: {finding['level']}\n"
            )
            report.write(
                f"Count: {finding['count']}\n"
            )
            report.write(
                f"Username: {finding['username']}\n"
            )
            report.write(
                f"Source IP: {finding['source_ip']}\n"
            )
            report.write(
                f"Workstation: {finding['workstation']}\n"
            )
            report.write(
                f"Logon Type: {finding['logon_type']}\n"
            )
            report.write(
                f"Process: {finding['process']}\n"
            )
            report.write(
                f"Failure Reason: {finding['failure_reason']}\n"
            )
            report.write(
                f"First observed: {finding['first_seen']}\n"
            )
            report.write(
                f"Last observed: {finding['last_seen']}\n"
            )
            report.write(
                f"Forensic significance: {finding['explanation']}\n"
            )

        # Include relevant individual event details.

        report.write("\nEVENT DETAILS\n")
        report.write("-" * 60 + "\n")

        for event in events:

            if event["event_id"] in (
                "4624", "4625", "6008"
            ):

                report.write(
                    f"\nEvent ID: {event['event_id']}\n"
                )
                report.write(
                    f"Timestamp: {event['timestamp']}\n"
                )
                report.write(
                    f"Username: {event['username']}\n"
                )
                report.write(
                    f"Source IP: {event['source_ip']}\n"
                )
                report.write(
                    f"Workstation: {event['workstation']}\n"
                )
                report.write(
                    f"Logon Type: {event['logon_type']}\n"
                )
                report.write(
                    f"Process: {event['process']}\n"
                )
                report.write(
                    f"Failure Reason: {event['failure_reason']}\n"
                )

        # Document limitations and configuration.

        report.write("\nANALYZER CONFIGURATION\n")
        report.write("-" * 60 + "\n")
        report.write(
            f"Repeated failure threshold: {FAILURE_THRESHOLD}\n"
        )
        report.write(
            f"Detection window: {TIME_WINDOW_MINUTES} minutes\n"
        )

        report.write("\nIMPORTANT LIMITATIONS\n")
        report.write("-" * 60 + "\n")
        report.write(
            "1. Current input format: CSV.\n"
            "2. Native EVTX parsing is not implemented.\n"
            "3. Missing IP addresses are reported as Not recorded.\n"
            "4. Alerts are investigative leads, not proof of attacks.\n"
            "5. Event findings should be correlated with other evidence.\n"
            "6. Timestamp formats not recognized by the parser "
            "are excluded from time-window detection.\n"
        )

    # Display results in the terminal.

    print("\nWINDOWS EVENT LOG ANALYZER")
    print("=" * 45)

    print(f"Input file: {LOG_FILE.name}")
    print(f"Total events analyzed: {len(events)}")
    print(f"Successful logons (4624): {len(successful)}")
    print(f"Failed logons (4625): {len(failed)}")
    print(f"Invalid or skipped rows: {skipped}")
    print(f"Findings generated: {len(findings)}")

    print("\nFINDINGS")

    if not findings:
        print("No findings met the configured rules.")

    for finding in findings:

        print(
            f"[{finding['level']}] "
            f"{finding['title']} | "
            f"Count: {finding['count']} | "
            f"User: {finding['username']} | "
            f"Source IP: {finding['source_ip']} | "
            f"Workstation: {finding['workstation']}"
        )

    print(f"\nReport saved to: {REPORT_FILE}")


# --------------------------------------------------
# MAIN PROGRAM
# --------------------------------------------------

def main():

    try:

        events, skipped = load_events()

        (
            counts,
            failed,
            successful,
            findings,
            skipped
        ) = analyze(events, skipped)

        create_report(
            events,
            counts,
            failed,
            successful,
            findings,
            skipped
        )

    except (FileNotFoundError, ValueError, csv.Error, OSError) as error:

        print(f"\nError: {error}")


if __name__ == "__main__":
    main()
