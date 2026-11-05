# Testing and Evaluation

## Testing Environment

- Operating System: Kali Linux
- Programming Language: Python 3
- Input Format: CSV
- Test Data: Synthetic sample logs and an authorized Windows Event Viewer CSV export

## Test Cases

| Test | Description | Expected Result |
|---|---|---|
| Test 1 | Successful logon (4624) | Successful logon identified |
| Test 2 | Failed logon (4625) | Failed logon counted |
| Test 3 | Repeated failed logons | Suspicious pattern detected |
| Test 4 | Unexpected shutdown (6008) | Event reported |

## Evaluation

The analyzer was tested using synthetic sample logs and an authorized Windows Event Viewer CSV export.

The real-data test processed 200 records:
- Successful logons: 139
- Failed logons: 61

The analyzer identified repeated failed logon activity for further investigation.

## Limitations

- Native EVTX parsing is not currently implemented.
- Some records do not contain source IP addresses.
- Findings require manual forensic verification.
