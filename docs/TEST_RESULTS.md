# AegisSOC Test Results

Validation date: 2026-10-22

## Passed checks

- Python source files compiled successfully.
- The latest incident review found 523 parseable incident records.
- No incident IDs were missing.
- No duplicate incident IDs were found.
- All 170 alert snapshot records parsed successfully.
- Windows Security telemetry was observed in Wazuh archives for agent 003.
- Wazuh analysis configuration test returned no error output.
- A pre-final backup archive was created.

## Incident state

| Status | Count |
|---|---:|
| NEW | 519 |
| APPROVED_FOR_DRY_RUN | 3 |
| REJECTED | 1 |

## Custom failed-logon detection
- Rule 100102 is configured to match parent rule 60122.
- Parent rule 60122 matches Windows Event IDs 4625 and 529.
- Rule 100101 is configured for three matching events within 60 seconds.
- On October 22, 2026, a Windows Event ID 4625 from agent 003 triggered
  custom rule 100102 at level 8.
- The event represented a failed authentication attempt; a single event
  does not by itself establish brute-force activity.
- A fresh alert confirming the updated MITRE mapping has not yet been
  verified.
- A trigger of threshold rule 100101 has not yet been verified.

Result: rule 100102 has demonstrated failed-logon detection. The MITRE
mapping and repeated-failure threshold remain pending validation.

## Response validation

An earlier test demonstrated approval-gated dry-run behavior. No system or
network changes were made during that simulation.

## Limitations

The snapshot is saved input and does not establish continuous real-time
processing. No actual endpoint isolation or network blocking has been
validated. No validated AI detection model or predictive accuracy result
is claimed.

## Investigation Record Module — 2026-10-26



- Python syntax check: passed.

- Investigation creation and read-back: passed.

- Duplicate-prevention check: passed.

- Original incident file: 523 records after testing.

- Investigation file: 1 record after testing.

- Source-record SHA-256 comparison: matched.

- Analyst decision: PENDING.

- MITRE assessment: NOT_ASSESSED.

- AI advisory: NOT_RUN.

- Response executed: false.



These tests verify record handling and source-line fingerprint consistency. They do not validate the security alert, confirm malicious activity, or test live response actions.
