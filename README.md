# Local Network Scanner

A Tkinter GUI that scans a local IPv4 network (ARP + nmap probing), shows devices, lets you run full port scans, and export results.

## Quick overview
- ARP scan to discover devices on the LAN.
- Light nmap probes for hostname, vendor, open ports, OS guess, latency.
- Full-port button runs an intensive nmap scan for a selected device.
- Export results to CSV or JSON.

## Requirements
- Windows 10/11 (tested)
- Python 3.9+ (3.10+ recommended)
- Nmap installed and on PATH (download from https://nmap.org/)
- Npcap installed (required by scapy on Windows) — choose "WinPcap-compatible mode" if offered
- Run script with Administrator privileges for complete functionality (ARP, raw sockets, some nmap features)

Python packages (install via requirements.txt):
- scapy
- python-nmap
- tqdm
- requests

## Install
1. Open PowerShell (recommended: run as Administrator for convenience)
2. Create and activate virtual environment (optional but recommended)
   - python -m venv .venv
   - .\.venv\Scripts\Activate.ps1
3. Install packages
   - pip install -r requirements.txt

Ensure nmap.exe is installed and available on PATH (run `nmap --version` to verify).

## Run the GUI
Recommended (Windows):
- Right-click Visual Studio Code and choose "Run as administrator", open the project, press F5 to debug or Run.
- Or open an Administrator PowerShell and run:
  - python "c:\Users\liamh\OneDrive - Skagerak International School\Documents\Coding\test.py"

Notes:
- The program will request elevation on start (ShellExecute). If you run from VS Code, start VS Code as admin to let the integrated debugger launch correctly with privileges.
- If the GUI does not appear after accepting the UAC prompt, run the script directly from an elevated PowerShell to verify.

## VS Code configuration
If you want a debug configuration, add `.vscode/launch.json` (example):

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Network Scanner (Admin)",
      "type": "debugpy",
      "request": "launch",
      "program": "${workspaceFolder}/test.py",
      "console": "integratedTerminal",
      "args": ["--run-as-admin"]
    }
  ]
}
```

Important: On Windows it is simpler to run VS Code itself as Administrator (right-click → Run as administrator) before launching the debug configuration.

## Using the GUI
- IP range input accepts:
  - CIDR: `192.168.1.0/24`
  - Single IP: `192.168.1.10`
  - Hyphen ranges: `192.168.1.1-254` or `192.168.1.10-192.168.1.20`
  - Wildcard: `192.168.1.*`
  - Comma list: `192.168.1.1,192.168.1.5,192.168.1.100`
- Buttons:
  - Start Scan — ARP discover + light probes
  - Full Port Scan — select a row, click to run an intensive nmap scan on that IP
  - Stop — request scan stop
  - Export CSV / Save JSON — save collected device info
  - Quit — close app
- Click a device row to show structured details in the lower panel. You can click lines in the log to auto-select devices if an IP is present.

## Behavior & limits
- ARP scanning works only on the local Ethernet/LAN segment.
- Full port scans and OS detection may require admin privileges and can take several minutes per host.
- The hyphen/wildcard expansion includes limits to avoid accidental huge scans (defensive).
- Nmap must be installed separately — python-nmap is only a wrapper.

## Troubleshooting
- If "accept admin" UAC dialog appears but no GUI opens:
  - Ensure VS Code was started as admin (preferred) or run the script in an Administrator PowerShell.
  - Verify `nmap --version` works from the same environment.
  - If using the debugger, run the debug session from an elevated VS Code instance.
- If scapy fails on Windows: verify Npcap installed and your virtualenv uses the same Python interpreter.

## Security and legal
Only scan networks and devices you own or have explicit permission to test. Unauthorized scanning can be illegal and disruptive.

## Contact / Feedback
Open the script in VS Code and modify as needed. For feature requests or issues, add notes to the top of `test.py`.