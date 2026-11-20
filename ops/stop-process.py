#!/usr/bin/env python3
"""Stop one verified managed dev service (Java jar or Node script) and its observed descendants."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import time


def snapshot():
    rows = subprocess.check_output(
        ["ps", "-axo", "pid=,ppid=,lstart=,command="], text=True
    ).splitlines()
    result = {}
    for row in rows:
        fields = row.split(None, 7)
        if len(fields) == 8:
            result[int(fields[0])] = (int(fields[1]), " ".join(fields[2:7]), fields[7])
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid-file", required=True, type=Path)
    parser.add_argument("--jar", required=False, help="Expected jar path substring")
    parser.add_argument("--cmd-contains", required=False, help="Expected command line substring")
    args = parser.parse_args()
    if args.pid_file.is_symlink() or not args.pid_file.is_file():
        return
    lines = args.pid_file.read_text().splitlines()
    if len(lines) != 2 or not lines[0].isdigit():
        raise SystemExit("Invalid managed process identity file")
    root = int(lines[0])
    initial = snapshot()
    expected_start = " ".join(lines[1].split())
    observed = initial.get(root)
    if root <= 1 or not observed or observed[1] != expected_start:
        print("No matching managed process; no signal sent")
        return

    # Check process command signature
    if args.jar and (" -jar " + args.jar not in observed[2]):
        print("No matching managed process command; no signal sent")
        return
    if args.cmd_contains and (args.cmd_contains not in observed[2]):
        print("No matching managed process command; no signal sent")
        return

    selected = {root}
    while True:
        children = {pid for pid, row in initial.items() if row[0] in selected}
        expanded = selected | children
        if expanded == selected:
            break
        selected = expanded
    identities = {pid: initial[pid][1:] for pid in selected}

    def live():
        current = snapshot()
        return {pid for pid, identity in identities.items() if pid in current and current[pid][1:] == identity}

    def send(pid, sig):
        current = snapshot().get(pid)
        if current and current[1:] == identities[pid]:
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass

    send(root, signal.SIGTERM)
    for pid in selected - {root}:
        send(pid, signal.SIGTERM)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and live():
        time.sleep(0.1)
    for pid in live():
        send(pid, signal.SIGKILL)
    print("Stopped verified service process tree (%d observed processes)" % len(selected))


if __name__ == "__main__":
    main()
