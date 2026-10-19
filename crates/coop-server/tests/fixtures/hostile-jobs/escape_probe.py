import os
import sys

problems = []

try:
    with open("/etc/shadow", "rb") as f:
        f.read(64)
    problems.append("read /etc/shadow")
except OSError:
    pass

try:
    with open("/etc/coop-escape-marker", "w") as f:
        f.write("escaped")
    problems.append("wrote /etc/coop-escape-marker")
except OSError:
    pass

try:
    host_id = os.uname().nodename
    if host_id:
        print(f"nodename visible: {host_id}")
except OSError as e:
    problems.append(f"uname failed: {e}")

if problems:
    for p in problems:
        print(f"LEAK: {p}")
    sys.exit(1)

print("no escape found")
sys.exit(1)
