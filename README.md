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

## Wazuh SIEM Detection Rules

AegisSOC uses custom Wazuh rules for Windows authentication monitoring and Suricata network-alert integration. Wazuh rule levels use a scale from 0 to 15.

| Rule ID | Level | Detection logic | MITRE ATT&CK | Validation status |
|---|---:|---|---|---|
| `100102` | 8 | Child of built-in rule `60122`; Windows failed-authentication detection | No explicit mapping in this rule | Runtime alert observed in Wazuh dashboard; Level 8 |
| `100101` | 10 | Correlates matches of rule `100102` using a frequency threshold of 3 within 60 seconds | `T1110` — Brute Force | Configured; correlation trigger not yet verified |
| `100103` | 8 | Child of built-in rule `86601`; Suricata network-security alert detection | No explicit mapping in this rule | Runtime alerts observed in Wazuh dashboard; Level 8 |

### Detection workflow

1. A Windows endpoint generates a Security event.
2. Wazuh collects and evaluates the event against its decoders and rules.
3. Rule `100102` is intended to classify a failed-authentication event when built-in rule `60122` matches.
4. Rule `100101` is intended to correlate repeated matches of `100102` within 60 seconds.
5. AegisSOC processes available Wazuh alerts into incident records for analyst review.
6. Rule `100103` provides a separate integration path for Suricata network alerts.

**Evidence standard:** Rule configuration alone does not prove detection. Wazuh dashboard evidence confirms runtime alerts for rules `100102` (Windows failed authentication) and `100103` (Suricata network-security alerts). The dashboard showed 47 matching results for the `100103` search within the displayed time range; this count is not proof of 47 distinct attacks. Rule `100101` brute-force correlation remains unverified. End-to-end processing of these specific alerts into AegisSOC incidents has not been established by these screenshots. AI analysis is advisory; the workflow does not automatically perform endpoint containment.

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

## AI Integration and Rationale

AegisSOC uses a locally hosted Large Language Model (LLM) through **Ollama and Qwen2.5:1.5b** to provide advisory assistance during security incident investigation.

### Why I used AI

Security analysts need to review alert details, interpret available evidence, assess potential risks, and prioritize incidents for further investigation. I added local AI assistance to explore how an LLM can help organize incident context and provide useful investigation guidance while keeping the analyst in control.

### How it is used

- Analyzes selected incident fields supplied by AegisSOC.
- Generates advisory findings to support human investigation.
- Runs locally through Ollama, without requiring an external LLM API for this integration.
- Keeps AI analysis separate from incident processing and response actions.

### Human oversight and limitations

The AI is an **advisory assistant, not a validated threat-detection model or autonomous response engine**. Its output may be incomplete or incorrect and must be checked against the available evidence. It does not automatically approve incidents, modify incident records, isolate endpoints, or block network traffic.

This integration demonstrates how local LLM assistance can complement a human-reviewed security operations workflow. It does not claim validated AI detection accuracy or production-ready autonomous response.

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

## Data Protection and Operational Safety

AegisSOC processes persistent security telemetry, alert snapshots, incident records, and analyst review decisions. These records are treated as operational evidence and must be preserved.

- Back up relevant project data before modifying processing logic, schemas, or batch workflows.
- Validate changes against isolated test copies whenever practical.
- Preserve existing incident history, alert snapshots, processing checkpoints, and analyst decisions.
- Never delete or reset production-like records merely to make a test pass.
- Keep incident processing idempotent and investigate duplicate or missing records before making corrections.
- Document test conditions, expected outcomes, observed results, and any limitations.

## Intended Use and Operational Scope

AegisSOC is a hands-on Security Operations Center (SOC) engineering project built around endpoint telemetry collection, SIEM detection, incident processing, AI-assisted triage, and analyst-controlled response workflows.

The lab uses Windows endpoint telemetry, Wazuh security monitoring, and locally hosted AI analysis to investigate suspicious activity and assess potential security incidents. Controlled security-event generation and attack emulation may be conducted only on systems owned by the operator or explicitly authorized for testing.

The platform is designed to demonstrate practical SOC workflows, including:

- Windows security-event collection and investigation.
- Detection-rule validation against observed telemetry.
- Alert enrichment and incident prioritization.
- AI-generated investigative recommendations with evidence-based reasoning.
- Human review, approval tracking, and dry-run response evaluation.
- Auditability, data integrity, and reproducible validation.

**Response safety:** AI analysis is advisory only. Incident approval does not automatically authorize or execute endpoint isolation, account disabling, process termination, or other containment actions. Any future response integration must include explicit authorization, safeguards, and independent validation.

**Evidence standard:** A configured detection rule is not considered validated until its expected event, corresponding SIEM alert, and resulting incident-processing behavior have been verified and documented.

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
