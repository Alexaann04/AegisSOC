#!/usr/bin/env python3
"""Append-only, evidence-aware AegisSOC investigation trail."""

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INCIDENTS = ROOT / "data" / "incidents.jsonl"
INVESTIGATIONS = ROOT / "data" / "investigations.jsonl"


def load_incident(incident_id):
    with INCIDENTS.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("incident_id") == incident_id:
                return record, hashlib.sha256(
                    line.encode("utf-8")
                ).hexdigest()
    raise ValueError(f"Incident not found: {incident_id}")


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in {"create", "show"}:
        print(
            "Usage:\n"
            "  ./.venv/bin/python src/investigation.py create INCIDENT_ID\n"
            "  ./.venv/bin/python src/investigation.py show INCIDENT_ID"
        )
        return 2

    command, incident_id = sys.argv[1:]
    incident, source_hash = load_incident(incident_id)

    if command == "create":
        INVESTIGATIONS.parent.mkdir(parents=True, exist_ok=True)

        if INVESTIGATIONS.exists():
            with INVESTIGATIONS.open(encoding="utf-8") as handle:
                for line in handle:
                    try:
                        prior = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if prior.get("incident_id") == incident_id:
                        print("Investigation already exists; no changes made.")
                        return 0

        investigation = {
            "investigation_id": hashlib.sha256(
                f"{incident_id}:{source_hash}".encode()
            ).hexdigest()[:16],
            "incident_id": incident_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_record_sha256": source_hash,
            "source_record": {
                key: incident.get(key)
                for key in (
                    "timestamp", "rule_id", "rule_level", "description",
                    "agent_id", "agent_name", "event_id", "source_ip",
                    "source_ip_context", "target_user", "risk_score",
                    "risk_method", "recommended_action", "response_mode",
                )
            },
            "observed_evidence": [
                f"{key}={incident.get(key)!r}"
                for key in (
                    "rule_id", "rule_level", "description",
                    "agent_id", "event_id", "source_ip_context",
                )
                if incident.get(key) is not None
            ],
            "investigation_steps": [],
            "interpretation": "Pending analyst verification.",
            "uncertainties": [
                "This record contains an alert summary, not necessarily raw event evidence.",
                "No attack or compromise is confirmed by this record alone.",
            ],
            "mitre_attack": {
                "status": "NOT_ASSESSED",
                "techniques": [],
                "reason": "Map only after validating supporting evidence.",
            },
            "ai_advisory": {
                "status": "NOT_RUN",
                "model_output": None,
                "verified_by_analyst": False,
            },
            "analyst_decision": "PENDING",
            "decision_rationale": None,
            "response_mode": "DRY_RUN_ONLY",
            "response_executed": False,
        }

        with INVESTIGATIONS.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(investigation, ensure_ascii=False) + "\n")

        print("Investigation record created.")
        print(f"Incident: {incident_id}")
        print(f"Investigation: {investigation['investigation_id']}")
        print(f"Source SHA-256: {source_hash}")
        print(f"File: {INVESTIGATIONS}")
        print("MITRE assessment: NOT_ASSESSED")
        print("Analyst decision: PENDING")
        print("Response: DRY_RUN_ONLY; no action executed.")
        return 0

    if not INVESTIGATIONS.exists():
        print("No investigation records exist yet.")
        return 1

    with INVESTIGATIONS.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("incident_id") == incident_id:
                print(json.dumps(item, indent=2, ensure_ascii=False))
                return 0

    print(f"No investigation record found for incident: {incident_id}")
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"Investigation error: {exc}", file=sys.stderr)
        raise SystemExit(1)
