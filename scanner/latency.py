import re
import subprocess
import sys


def probe_latency(ip, timeout_ms=500):
    try:
        if sys.platform.startswith('win'):
            cmd = ['ping', '-n', '1', '-w', str(timeout_ms), ip]
        else:
            timeout_s = max(1, int(timeout_ms / 1000))
            cmd = ['ping', '-c', '1', '-W', str(timeout_s), ip]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max(2, timeout_ms / 1000 + 1))
        if proc.returncode == 0:
            out = proc.stdout or ''
            match = re.search(r'time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms', out, re.IGNORECASE)
            if match:
                val = match.group(1)
                return str(int(float(val))) if float(val).is_integer() else val
    except Exception:
        pass
    return None
