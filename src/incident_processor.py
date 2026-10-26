import argparse
import hashlib
import ipaddress
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

BASE = Path.home() / "AegisSOC"
INPUT = BASE / "data" / "alerts_snapshot.json"
OUTPUT = BASE / "data" / "incidents.jsonl"
STATE_PATH = BASE / "data" / "processed_alert_ids.json"


def ip_context(value):
    if not value:
        return "unknown"
    try:
        ip = ipaddress.ip_address(value)
        if ip.is_private:
            return "private_internal"
        if not ip.is_global:
            return "non_public_special"
        return "public"
    except ValueError:
        return "unknown"


def calculate_risk(level, description, source_ip):
    # Triage heuristic, not a probability of compromise.
    score = min(max(int(level or 0), 0), 15) * 5
    text = (description or "").lower()

    if "brute-force" in text or "brute force" in text:
        score += 20
    if "failed authentication" in text or "logon failure" in text:
        score += 10
    if "malware" in text or "ransomware" in text:
        score += 20
    if ip_context(source_ip) == "public":
        score += 5

    return min(score, 100)


def normalize(alert):
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    description = rule.get("description", "Unspecified alert")

    source_ip = (
        data.get("srcip")
        or data.get("src_ip")
        or alert.get("srcip")
        or ""
    )
    level = int(rule.get("level") or 0)

    win = data.get("win") or {}
    system = win.get("system") or {}
    eventdata = win.get("eventdata") or {}
    event_id = system.get("eventID") or data.get("eventID")

    # Preserve the existing incident-ID algorithm.
    fingerprint = {
        "timestamp": alert.get("timestamp"),
        "rule_id": rule.get("id"),
        "agent_id": agent.get("id"),
        "description": description,
        "data": data,
    }
    incident_id = hashlib.sha256(
        json.dumps(
            fingerprint, sort_keys=True, default=str
        ).encode()
    ).hexdigest()[:16]

    return {
        "incident_id": incident_id,
        "source_alert_id": str(alert["id"]),
        "timestamp": alert.get("timestamp"),
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "rule_id": str(rule.get("id", "")),
        "rule_level": level,
        "description": description,
        "agent_id": str(agent.get("id", "")),
        "agent_name": agent.get("name", "unknown"),
        "source_ip": source_ip or None,
        "source_ip_context": ip_context(source_ip),
        "event_id": str(event_id) if event_id is not None else None,
        "target_user": (
            eventdata.get("targetUserName")
            or data.get("targetUserName")
        ),
        "risk_score": calculate_risk(level, description, source_ip),
        "risk_method": "rule-level heuristic",
        "status": "NEW",
        "human_approval": "PENDING",
        "recommended_action": "REVIEW",
        "response_mode": "DRY_RUN",
    }


def read_existing_incidents():
    existing = set()

    if not OUTPUT.exists():
        return existing

    with OUTPUT.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError as exc:
                raise SystemExit(
                    f"STOP: Invalid JSON in {OUTPUT}, "
                    f"line {line_number}: {exc}"
                )

            incident_id = record.get("incident_id")
            if incident_id:
                existing.add(incident_id)

    return existing


def atomic_write_state(state):
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=STATE_PATH.parent,
            prefix=".processed_alert_ids.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            temp_path = Path(tmp.name)
            json.dump(state, tmp, indent=2)
            tmp.write("\n")
            tmp.flush()
            os.fsync(tmp.fileno())

        os.replace(temp_path, STATE_PATH)
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink()


def main():
    parser = argparse.ArgumentParser(
        description="Incremental AegisSOC snapshot ingestion"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Append new incidents and save processed alert IDs",
    )
    args = parser.parse_args()

    if not INPUT.exists():
        raise SystemExit(f"Snapshot not found: {INPUT}")

    if not STATE_PATH.exists():
        raise SystemExit(
            f"STOP: Baseline state missing: {STATE_PATH}\n"
            "Initialize and verify the baseline before ingestion."
        )

    try:
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise SystemExit(f"STOP: Cannot read ingestion state: {exc}")

    if state.get("version") != 1:
        raise SystemExit("STOP: Unsupported ingestion state version.")

    processed_list = state.get("processed_alert_ids")
    if not isinstance(processed_list, list):
        raise SystemExit("STOP: State has no valid processed_alert_ids list.")

    processed = {str(item) for item in processed_list}
    if len(processed) != len(processed_list):
        raise SystemExit("STOP: Duplicate IDs in ingestion state.")

    existing_incidents = read_existing_incidents()
    scanned = skipped = eligible = added = 0
    newly_seen_ids = set()
    pending_incidents = []
    snapshot_ids = set()

    with INPUT.open(encoding="utf-8", errors="replace") as source:
        for line_number, line in enumerate(source, 1):
            try:
                alert = json.loads(line)
            except ValueError as exc:
                raise SystemExit(
                    f"STOP: Invalid snapshot JSON at line "
                    f"{line_number}: {exc}"
                )

            if not isinstance(alert, dict):
                raise SystemExit(
                    f"STOP: Non-object alert at line {line_number}."
                )

            alert_id = alert.get("id")
            if alert_id is None or not str(alert_id).strip():
                raise SystemExit(
                    f"STOP: Missing Wazuh alert ID at line {line_number}."
                )

            alert_id = str(alert_id)
            if alert_id in snapshot_ids:
                raise SystemExit(
                    f"STOP: Duplicate Wazuh alert ID {alert_id} "
                    f"in snapshot."
                )
            snapshot_ids.add(alert_id)
            scanned += 1

            if alert_id in processed:
                skipped += 1
                continue

            newly_seen_ids.add(alert_id)
            rule = alert.get("rule") or {}
            level = int(rule.get("level") or 0)

            if level < 3:
                continue

            eligible += 1
            incident = normalize(alert)

            if incident["incident_id"] in existing_incidents:
                # Existing incident: mark source alert as seen on apply,
                # but do not overwrite its status or analyst decisions.
                continue

            pending_incidents.append(incident)
            existing_incidents.add(incident["incident_id"])

    print("Mode:", "APPLY" if args.apply else "DRY RUN")
    print("Snapshot alerts scanned:", scanned)
    print("Already processed alerts skipped:", skipped)
    print("New eligible alerts:", eligible)
    print("New incidents to append:", len(pending_incidents))
    print("New alert IDs to record:", len(newly_seen_ids))
    print("Current incident database:", OUTPUT)

    if not args.apply:
        print("DRY RUN ONLY: no files were changed.")
        print("Review the results before running with --apply.")
        return

    # Append only new incidents. Existing records are never rewritten.
    if pending_incidents:
        with OUTPUT.open("a", encoding="utf-8") as destination:
            for incident in pending_incidents:
                destination.write(json.dumps(incident) + "\n")
            destination.flush()
            os.fsync(destination.fileno())
        added = len(pending_incidents)

    # Commit IDs only after the incident append has completed.
    processed.update(newly_seen_ids)
    state["processed_alert_ids"] = sorted(processed)
    state["last_run_at"] = datetime.now(timezone.utc).isoformat()
    state["last_run_snapshot_records"] = scanned
    state["last_run_incidents_added"] = added
    atomic_write_state(state)

    print("Incidents appended:", added)
    print("Processed alert IDs saved:", len(processed))
    print("Ingestion state updated:", STATE_PATH)


if __name__ == "__main__":
    main()
