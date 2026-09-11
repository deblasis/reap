#!/usr/bin/env python3
"""Types a command script into the terminal char-by-char (a human-feeling
feeder for asciinema recordings): reads (delay, line) pairs from a file."""
import sys
import time

for raw in sys.stdin:
    line = raw.rstrip("\n")
    if line.startswith("SLEEP "):
        time.sleep(float(line.split(" ", 1)[1]))
        continue
    for ch in line:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(0.03)
    sys.stdout.write("\n")
    sys.stdout.flush()
    time.sleep(0.3)
