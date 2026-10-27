# AegisSOC — Security Incident Review and Response Prototype

## Overview

AegisSOC is a lab-based security incident processing and analyst-review
prototype built around Wazuh telemetry. It converts alert records into
structured incident records, assigns a risk score, supports analyst review,
and provides an approval-gated dry-run response workflow.

This project demonstrates security monitoring, incident triage, structured
event processing, human approval, and safe response simulation.

## Architecture

1. **Telemetry:** Wazuh collects events from monitored lab endpoints.
2. **Detection:** Wazuh rules analyse incoming events and produce alerts.
3. **Snapshot input:** AegisSOC reads a saved alert snapshot.
4. **Incident processing:** `src/incident_processor.py` processes eligible
   alerts and records incidents in `data/incidents.jsonl`.
5. **Analyst review:** `src/review.py` lists incidents and supports review
   decisions.
6. **Dry-run response:** The workflow can simulate an approved response
   without making system or network changes.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/TEST_RESULTS.md](docs/TEST_RESULTS.md).

## Lab components

- Wazuh Manager, Indexer and Dashboard
- Windows endpoint monitored by Wazuh agent ID `003`
- Suricata network monitoring in the lab
- Python incident processing and review scripts
- JSON Lines incident history

## Project layout

- `src/incident_processor.py` — alert-to-incident processing
- `src/review.py` — incident listing, review and dry-run workflow
- `data/alerts_snapshot.json` — saved Wazuh alert records in JSON Lines format
- `data/incidents.jsonl` — structured incident history
- `backups/` — project backup archives
- `docs/` — architecture and test documentation

## Validation performed

- Python source files compile successfully.
- The latest incident review found 523 parseable incident records.
- The current incident history contains 523 valid records with 523 unique IDs, zero duplicate IDs, and zero invalid or missing-ID records.
- Incident statuses include `NEW`, `APPROVED_FOR_DRY_RUN`, and `REJECTED`.
- The current snapshot contains 1,068 unique alert IDs; all match the 1,068 IDs in the ingestion state.
- Windows Security telemetry from agent `003` was observed in Wazuh archives.
- Wazuh analysis configuration test completed without reported errors.
- Custom failed-logon rule `100102` is configured; its historical trigger on October 22, 2026 could not be independently re-verified from the currently available logs.
- Threshold rule `100101` and the updated MITRE mapping remain unverified.

## Safety and limitations

This is a lab prototype, not a production-ready autonomous SOC platform.
The October 22, 2026 trigger of custom rule `100102` is a historical claim that could not be independently re-verified during the latest review. A fresh failed-logon event, the updated MITRE mapping, and a trigger of threshold rule `100101` remain to be verified.

The demonstrated response workflow is dry-run only. Do not describe it as
performing real endpoint isolation, account blocking, or network containment
unless those capabilities are separately implemented and tested.

Risk scoring is a prototype feature, not a validated predictive model.
The project should not be represented as having validated AI-based detection
unless a model is implemented and evaluated separately.

## Run

Activate the project environment:

    source .venv/bin/activate

List incidents:

    python src/review.py list

Use the review script's supported commands and arguments for approval,
rejection, or dry-run simulation. Check the script's usage output before
performing a review action.

## Data protection

The incident history and alert snapshot are project data. Back them up before
changing processing logic or running a batch operation. Do not delete or reset
the existing incident history to make a test pass.

## Intended use

For cybersecurity learning, lab validation, portfolio demonstration, and
controlled testing only.

## Evidence-Aware Investigation Records



AegisSOC includes an initial investigation-record module at `src/investigation.py`.

It stores records separately in `data/investigations.jsonl`, preserving the original incident history.



### Current capabilities

- Links investigation records to existing incidents.

- Stores a SHA-256 fingerprint of the source incident line.

- Separates observed alert fields from interpretation and uncertainty.

- Tracks MITRE ATT&CK assessment and AI advisory status explicitly.

- Records pending analyst decisions and dry-run-only response state.

- Prevents duplicate investigation records for the same incident ID.



### Limitations and safety

This is an initial investigation-record framework, not a complete automated investigation engine. Investigation steps remain unpopulated; MITRE techniques require supporting evidence; and AI output requires analyst verification. It does not execute response actions.



### Example

```bash

./.venv/bin/python src/investigation.py create 6dfee24ad2d25fb3

./.venv/bin/python src/investigation.py show 6dfee24ad2d25fb3

```
