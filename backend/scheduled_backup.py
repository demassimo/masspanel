#!/usr/bin/env python3
import json
import re
import sys

from app import app, run_backup_schedule


def main():
    if len(sys.argv) != 2 or not re.fullmatch(r"[a-f0-9]{16}", sys.argv[1]):
        raise SystemExit("Usage: scheduled_backup.py SCHEDULE_ID")
    with app.app_context():
        result = run_backup_schedule(sys.argv[1])
    print(json.dumps({"ok": True, **result}))


if __name__ == "__main__":
    main()
