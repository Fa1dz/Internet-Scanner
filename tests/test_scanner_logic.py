import sys
import types
import unittest
from pathlib import Path


# Stub optional runtime deps so tests can import module in minimal CI env.
if 'scapy' not in sys.modules:
    scapy_mod = types.ModuleType('scapy')
    scapy_all = types.ModuleType('scapy.all')
    scapy_all.ARP = object
    scapy_all.Ether = object
    def _srp(*_args, **_kwargs):
        return ([], [])
    scapy_all.srp = _srp
    scapy_mod.all = scapy_all
    sys.modules['scapy'] = scapy_mod
    sys.modules['scapy.all'] = scapy_all

if 'nmap' not in sys.modules:
    nmap_mod = types.ModuleType('nmap')
    class _PortScanner:
        def scan(self, *_args, **_kwargs):
            return {}
        def all_hosts(self):
            return []
    nmap_mod.PortScanner = _PortScanner
    sys.modules['nmap'] = nmap_mod

if 'tqdm' not in sys.modules:
    tqdm_mod = types.ModuleType('tqdm')
    def _tqdm(iterable=None, *args, **kwargs):
        return iterable if iterable is not None else []
    tqdm_mod.tqdm = _tqdm
    sys.modules['tqdm'] = tqdm_mod

if 'tkinter' not in sys.modules:
    tk_mod = types.ModuleType('tkinter')
    class _StringVar:
        def __init__(self, value=None):
            self._value = value
        def get(self):
            return self._value
        def set(self, value):
            self._value = value
    tk_mod.StringVar = _StringVar
    tk_mod.BooleanVar = _StringVar
    tk_mod.filedialog = types.SimpleNamespace(asksaveasfilename=lambda **_kwargs: "")
    tk_mod.ttk = types.SimpleNamespace()
    tk_mod.messagebox = types.SimpleNamespace(showinfo=lambda *a, **k: None, showerror=lambda *a, **k: None)
    tk_mod.scrolledtext = types.SimpleNamespace(ScrolledText=object)
    sys.modules['tkinter'] = tk_mod
    sys.modules['tkinter.ttk'] = tk_mod.ttk
    sys.modules['tkinter.messagebox'] = tk_mod.messagebox
    sys.modules['tkinter.scrolledtext'] = tk_mod.scrolledtext
    sys.modules['tkinter.filedialog'] = tk_mod.filedialog

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import Internet_Scanner as scanner


class ParseRangeTests(unittest.TestCase):
    def test_single_ip(self):
        self.assertEqual(scanner.parse_ip_range('192.168.1.10'), ['192.168.1.10'])

    def test_hyphen_short_form(self):
        self.assertEqual(
            scanner.parse_ip_range('192.168.1.10-12'),
            ['192.168.1.10', '192.168.1.11', '192.168.1.12'],
        )

    def test_comma_list_deduplicates(self):
        self.assertEqual(
            scanner.parse_ip_range('192.168.1.10, 192.168.1.10, 192.168.1.11'),
            ['192.168.1.10', '192.168.1.11'],
        )


class RiskScoringTests(unittest.TestCase):
    def test_low_risk_without_open_ports(self):
        self.assertEqual(scanner._assess_risk([]), 'Low')

    def test_high_risk_for_many_sensitive_ports(self):
        ports = [
            {'port': p, 'state': 'open', 'proto': 'tcp', 'service': 'svc'}
            for p in (22, 23, 25, 80)
        ]
        self.assertEqual(scanner._assess_risk(ports), 'High')

    def test_ports_summary_human_readable(self):
        ports = [
            {'port': 443, 'state': 'open', 'proto': 'tcp', 'service': 'https'},
            {'port': 22, 'state': 'open', 'proto': 'tcp', 'service': 'ssh'},
        ]
        self.assertEqual(
            scanner._format_ports_summary(ports),
            '22/tcp:ssh, 443/tcp:https'
        )


if __name__ == '__main__':
    unittest.main()
