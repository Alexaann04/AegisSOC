
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

FILE = Path.home() / "AegisSOC" / "data" / "incidents.jsonl"


def load_records():
    if not FILE.exists():
        return []

    records = []
    with FILE.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                records.append(json.loads(line))
            except ValueError:
                continue
    return records


def save_records(records):
    temp = FILE.with_suffix(".tmp")

    with temp.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")

    temp.replace(FILE)


def main():
    if len(sys.argv) < 2:
        print("Usage: review.py list | approve ID | reject ID | simulate ID")
        raise SystemExit(2)

    command = sys.argv[1].lower()
    records = load_records()

    if command == "list":
        if not records:
            print("No incidents found.")
            return

        for item in records:
            print(
                f'{item["incident_id"]} | '
                f'risk={item["risk_score"]:3} | '
                f'{item["status"]} | '
                f'approval={item["human_approval"]} | '
                f'{item["description"]}'
            )
        return

    if len(sys.argv) != 3:
        raise SystemExit("This command requires an incident ID.")

    incident_id = sys.argv[2]
    incident = next(
        (item for item in records
         if item.get("incident_id") == incident_id),
        None,
    )

    if incident is None:
        raise SystemExit(f"Incident not found: {incident_id}")

    now = datetime.now(timezone.utc).isoformat()

    if command == "approve":
        if incident["human_approval"] != "PENDING":
            raise SystemExit("Incident is not pending approval.")

        incident["human_approval"] = "APPROVED"
        incident["status"] = "APPROVED_FOR_DRY_RUN"
        incident["approved_at"] = now
        incident["approved_by"] = "lab_analyst"
        save_records(records)

        print("Approval recorded. No system changes were made.")

    elif command == "reject":
        if incident["human_approval"] != "PENDING":
            raise SystemExit("Incident is not pending approval.")

        incident["human_approval"] = "REJECTED"
        incident["status"] = "REJECTED"
        incident["reviewed_at"] = now
        incident["reviewed_by"] = "lab_analyst"
        save_records(records)

        print("Rejection recorded. No response action was executed.")

    elif command == "simulate":
        if incident["human_approval"] != "APPROVED":
            raise SystemExit(
                "Approve the incident before simulating a response."
            )

        print("=== AegisSOC DRY-RUN RESPONSE ===")
        print(f'Incident: {incident["incident_id"]}')
        print(f'Alert: {incident["description"]}')
        print(f'Risk score: {incident["risk_score"]}')
        print("Recommended action: investigate and validate the alert.")
        print("Execution: NONE — dry-run only.")
        print("No system or network settings were changed.")

    else:
        raise SystemExit("Unknown command.")


if __name__ == "__main__":
    main()
