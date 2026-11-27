"""Remote host resource stats (CPU, memory, disk "/") collected over SSH.

The command is a fixed string run in a separate exec channel of the existing SSH
connection; nothing from the client is ever interpolated into it. Linux only
(/proc); on other systems parsing fails and the browser shows "n/a".
"""

from __future__ import annotations

from typing import Optional

# Lower bound for the polling interval, enforced on server and client.
STATS_MIN_INTERVAL = 10

# `sh -c` so the script works whatever the login shell of the remote user is.
STATS_COMMAND = (
    "sh -c '"
    "a=$(head -n1 /proc/stat); sleep 1; b=$(head -n1 /proc/stat); "
    'echo "$a"; echo "$b"; '
    'grep -E "^(MemTotal|MemAvailable):" /proc/meminfo; '
    "df -P / | tail -n1'"
)


def _cpu_times(line: str) -> tuple[int, int]:
    parts = line.split()
    if len(parts) < 5 or parts[0] != "cpu":
        raise ValueError("bad /proc/stat line")
    vals = [int(p) for p in parts[1:9]]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)  # idle + iowait
    return idle, sum(vals)


def _pct(value: float) -> int:
    return max(0, min(100, round(value)))


def parse_stats(output: str) -> Optional[dict]:
    """Parse STATS_COMMAND output into {"cpu","mem","disk"} percentages (0-100).

    Returns None when the output is not what we expect.
    """
    try:
        lines = [ln for ln in output.splitlines() if ln.strip()]
        idle1, total1 = _cpu_times(lines[0])
        idle2, total2 = _cpu_times(lines[1])
        dtotal = total2 - total1
        cpu = _pct(100 * (1 - (idle2 - idle1) / dtotal)) if dtotal > 0 else 0

        mem: dict[str, int] = {}
        for ln in lines[2:4]:
            key, _, rest = ln.partition(":")
            mem[key] = int(rest.split()[0])
        mem_pct = _pct(100 * (1 - mem["MemAvailable"] / mem["MemTotal"]))

        disk_pct = _pct(int(lines[4].split()[4].rstrip("%")))
    except (IndexError, KeyError, ValueError, ZeroDivisionError):
        return None
    return {"cpu": cpu, "mem": mem_pct, "disk": disk_pct}
