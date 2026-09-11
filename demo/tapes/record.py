#!/usr/bin/env python3
"""A small pty recorder that types a command script into bash and writes an
asciinema v2 .cast file.

The feeder can SEE the output, and it does not type on a clock: after each
command it waits for bash to print a fresh prompt (bracketed-paste enable
plus our PS1), so nothing is ever typed while a command is still running -
even one that stays silent for its whole gh round-trip. "exit" lands after
the last table, never over it.

Input lines: plain text (typed char-by-char at 30 ms), or "SLEEP <sec>" for
a minimum-settle directive. The script ends with a typed `exit`.
"""
import json
import os
import pty
import select
import struct
import sys
import time

PROMPT_CAP = 120 # hard ceiling waiting for a prompt (a command that hangs)
CHAR_MS = 30     # typing speed
COLS, ROWS = 100, 28
ANSI = __import__("re").compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07")

def is_prompt(data):
    """bash ready for input: bracketed-paste enable, then (after whatever
    title escape it interleaves) our PS1 at the chunk's visible end."""
    if b"\x1b[?2004h" not in data:
        return False
    return ANSI.sub("", data.decode("utf-8", "replace")).endswith("$ ")

def main():
    cast_path = sys.argv[1]
    lines = [l.rstrip("\n") for l in sys.stdin]

    import fcntl, termios
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    pid = os.fork()
    if pid == 0:
        os.close(master)
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        os.dup2(slave, 0); os.dup2(slave, 1); os.dup2(slave, 2)
        if slave > 2:
            os.close(slave)
        os.execvp("bash", ["bash"])

    os.close(slave)
    os.set_blocking(master, False)

    cast = open(cast_path, "w", encoding="utf-8", newline="\n")
    t0 = None
    last_out = time.monotonic()
    prompt_ready = False
    script = lines + ["exit"]

    def drain(timeout):
        """Read whatever the pty offers within timeout; record it. Returns
        False only on true EOF/error - a spurious EAGAIN keeps the loop
        alive."""
        try:
            ready, _, _ = select.select([master], [], [], timeout)
        except (OSError, ValueError):
            return False
        if not ready:
            return True
        try:
            data = os.read(master, 65536)
        except BlockingIOError:
            return True
        except OSError:
            return False
        if not data:
            return False
        nonlocal t0
        now = time.monotonic()
        if t0 is None:
            t0 = now
        cast.write(json.dumps([round(now - t0, 6), "o", data.decode("utf-8", "replace")]) + "\n")
        cast.flush()
        last_out = now
        if is_prompt(data):
            nonlocal prompt_ready
            prompt_ready = True
        return True

    alive = True
    for raw in script:
        if raw.startswith("SLEEP "):
            settle_until = time.monotonic() + float(raw.split(" ", 1)[1])
            while alive and time.monotonic() < settle_until:
                alive = drain(0.2)
            continue
        # wait for bash to be ready: a REAL prompt, nothing else. A command
        # that stays silent its whole gh round-trip must not be typed over
        # (idle is not done - the earlier idle fallback is what shipped the
        # premature exits). The cap is the only way out for a hung command.
        wait_start = time.monotonic()
        while alive and not prompt_ready:
            if time.monotonic() - wait_start > PROMPT_CAP:
                break
            alive = drain(0.2)
        if not alive:
            break
        prompt_ready = False
        for ch in raw:
            try:
                os.write(master, ch.encode())
            except OSError:
                alive = False
                break
            time.sleep(CHAR_MS / 1000.0)
            alive = drain(0.01)
        if not alive:
            break
        os.write(master, b"\n")
        time.sleep(0.25)
        alive = drain(0.1)

    # let the exit land and the shell finish
    deadline = time.monotonic() + 15
    while alive and time.monotonic() < deadline:
        alive = drain(0.3)

    try:
        os.close(master)
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass

    cast.close()
    header = {"version": 2, "width": COLS, "height": ROWS,
              "timestamp": int(time.time()), "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"}}
    # rewrite with the header first (we streamed events before knowing t0)
    with open(cast_path, encoding="utf-8") as f:
        events = [l for l in f.read().splitlines() if l]
    with open(cast_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(header) + "\n")
        for e in events:
            f.write(e + "\n")

if __name__ == "__main__":
    main()
