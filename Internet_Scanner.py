import socket
import requests
from scapy.all import ARP, Ether, srp
from tqdm import tqdm
from tkinter import ttk, messagebox, scrolledtext, filedialog
import tkinter as tk
import nmap
import argparse
import ctypes
import sys
import os
import subprocess
import json
import csv
import time
import ipaddress
import platform
import re
from collections import Counter
from datetime import datetime
import queue
import threading

def scan_network(ip_range):
    devices = []
    try:
        if isinstance(ip_range, list):
            pdst = ','.join(ip_range)
        else:
            pdst = ip_range

        arp = ARP(pdst=pdst)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=2, verbose=0)[0]

        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    except Exception as e:
        print(f"Network scan error: {e}")
    return devices

def get_device_info_nmap(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-sP -sV --max-retries 1 --host-timeout 10s')
        return nm
    except Exception as e:
        print(f"Error scanning {ip}: {e}")
        return None

def get_device_info_nmap_gui(ip, put):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-sP -sV --max-retries 1 --host-timeout 10s')
        for host in nm.all_hosts():
            put(f"Host : {host} ({nm[host].hostname()})\n")
            put(f"State : {nm[host].state()}\n")
            if 'osclass' in nm[host]:
                oc = nm[host]["osclass"][0]
                put(f"OS : {oc.get('osfamily','?')} {oc.get('osgen','?')} {oc.get('type','?')}\n")
            if 'address' in nm[host]:
                put(f"MAC Address : {nm[host]['address']}\n")
                if 'vendor' in nm[host]['address']:
                    try:
                        put(f"Vendor : {nm[host]['address'].vendor()}\n")
                    except Exception:
                        pass
            if 'traceroute' in nm[host]:
                put(f"Traceroute : {nm[host].traceroute()}\n")
            for proto in nm[host].all_protocols():
                put(f"Protocol : {proto}\n")
                lport = nm[host][proto].keys()
                for port in lport:
                    s = nm[host][proto][port]
                    put(f"  port: {port}\tstate: {s.get('state','?')}\n")
    except Exception as e:
        put(f"Error scanning {ip}: {e}\n")

CRITICAL_PORTS = {21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 5900}


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


def _assess_risk(ports):
    if not ports:
        return "Low"
    open_ports = [p for p in ports if p.get('state') == 'open']
    if not open_ports:
        return "Low"
    risky = [p for p in open_ports if int(p.get('port', 0)) in CRITICAL_PORTS]
    if len(open_ports) >= 12 or len(risky) >= 6:
        return "Critical"
    if len(open_ports) >= 7 or len(risky) >= 4:
        return "High"
    if len(open_ports) >= 3 or len(risky) >= 2:
        return "Medium"
    return "Low"


def _format_ports_summary(ports, limit=8):
    open_ports = [p for p in ports if p.get('state') == 'open']
    open_ports = sorted(open_ports, key=lambda x: int(x.get('port', 0)))
    samples = [f"{p.get('port')}/{p.get('proto')}:{p.get('service') or 'unknown'}" for p in open_ports[:limit]]
    more = "..." if len(open_ports) > limit else ""
    return ", ".join(samples) + more


def format_device_details(dev):
    open_ports = [p for p in dev.get('ports', []) if p.get('state') == 'open']
    service_counter = Counter((p.get('service') or 'unknown') for p in open_ports)
    top_services = ", ".join(f"{name} ({count})" for name, count in service_counter.most_common(6)) or "None"
    lines = [
        f"IP Address: {dev.get('ip', '')}",
        f"Hostname: {dev.get('hostname') or 'Unknown'}",
        f"State: {dev.get('state') or 'Unknown'}",
        f"MAC Address: {dev.get('mac') or 'Unknown'}",
        f"Vendor: {dev.get('vendor') or 'Unknown'}",
        f"Operating System: {dev.get('os') or 'Unknown'}",
        f"Latency: {dev.get('latency_ms') or 'N/A'} ms",
        f"Risk Level: {dev.get('risk') or 'Unknown'}",
        f"Open Ports ({len(open_ports)}): {_format_ports_summary(dev.get('ports', [])) or 'None'}",
        f"Top Services: {top_services}",
        f"Last Scan: {dev.get('scan_time') or 'Unknown'}",
    ]
    return "\n".join(lines)

def get_device_info_struct(ip):
    info = {'ip': ip, 'hostname': None, 'state': None, 'mac': None, 'vendor': None,
            'os': None, 'latency_ms': None, 'ports': [], 'raw': None, 'risk': 'Unknown',
            'open_port_count': 0, 'scan_time': datetime.now().isoformat(timespec='seconds')}
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-sn -PE -PS22,80,443 -PA3389 -T3 --host-timeout 8s')

        if ip in nm.all_hosts():
            host = nm[ip]
            info.update({
                'hostname': host.get('hostnames', [{'name': None}])[0].get('name'),
                'state': host.get('status', {}).get('state'),
                'mac': host.get('addresses', {}).get('mac'),
                'vendor': host.get('vendor', {}).get(host.get('addresses', {}).get('mac', ''), '')
            })

        nm.scan(ip, arguments='-sS -sV -O --osscan-limit --version-light --top-ports 200 --open --host-timeout 20s')
        if ip in nm.all_hosts():
            host = nm[ip]
            if not info.get('hostname'):
                info['hostname'] = host.get('hostnames', [{'name': None}])[0].get('name')
            if not info.get('state'):
                info['state'] = host.get('status', {}).get('state')
            if not info.get('mac'):
                info['mac'] = host.get('addresses', {}).get('mac')
            if not info.get('vendor'):
                info['vendor'] = host.get('vendor', {}).get(host.get('addresses', {}).get('mac', ''), '')

            if 'osmatch' in host and host['osmatch']:
                info['os'] = host['osmatch'][0].get('name', '')
            elif host.get('fingerprint'):
                info['os'] = host.get('fingerprint')

            for proto in host.all_protocols():
                ports = host[proto].keys()
                for p in ports:
                    port_info = host[proto][p]
                    info['ports'].append({
                        'port': int(p),
                        'proto': proto,
                        'state': port_info.get('state', ''),
                        'service': port_info.get('name', ''),
                        'version': port_info.get('version', ''),
                        'product': port_info.get('product', '')
                    })

        info['latency_ms'] = probe_latency(ip, timeout_ms=500)
        open_ports = [p for p in info['ports'] if p.get('state') == 'open']
        info['open_port_count'] = len(open_ports)
        info['risk'] = _assess_risk(info['ports'])
        info['ports_summary'] = _format_ports_summary(info['ports'])
    except Exception as e:
        print(f"Error scanning {ip}: {e}")

    return info

def is_admin():
    try:
        if sys.platform.startswith('win'):
            return ctypes.windll.shell32.IsUserAnAdmin()
        return os.geteuid() == 0
    except:
        return False

def restart_as_admin():
    if not is_admin():
        try:
            script_path = os.path.abspath(__file__)
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, script_path, None, 1)
            sys.exit(0)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to restart with admin rights: {e}")
            sys.exit(1)

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Local Network Scanner Pro")
        root.geometry("1200x760")
        self.style = ttk.Style()
        if "clam" in self.style.theme_names():
            self.style.theme_use("clam")
        self.style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"))
        self.style.configure("SubHeader.TLabel", font=("Segoe UI", 10))
        self.style.configure("Stats.TLabel", font=("Segoe UI", 10, "bold"))

        self.sort_state = {}
        self.filter_var = tk.StringVar()
        self.only_open_var = tk.BooleanVar(value=False)

        # Header frame
        header = ttk.Frame(root, padding=(10, 10, 10, 6))
        header.pack(fill='x')
        ttk.Label(header, text="Network Scanner Pro", style="Header.TLabel").pack(anchor='w')
        ttk.Label(
            header,
            text="Real-time LAN discovery, richer host insights, smart risk scoring, and fast filtering.",
            style="SubHeader.TLabel"
        ).pack(anchor='w', pady=(2, 0))

        # Input frame
        frm = ttk.Frame(root, padding=(10, 2, 10, 8))
        frm.pack(fill='x')

        examples = (
            "Examples:\n"
            "  CIDR:        192.168.1.0/24\n"
            "  Single IP:   192.168.1.10\n"
            "  Hyphen:      192.168.1.1-254  or  192.168.1.10-192.168.1.20\n"
            "  Wildcard:    192.168.1.*\n"
            "  Comma list:  192.168.1.1,192.168.1.5,192.168.1.100\n"
        )
        lbl_examples = ttk.Label(frm, text=examples, justify='left')
        lbl_examples.pack(fill='x')

        entry_frame = ttk.Frame(frm)
        entry_frame.pack(fill='x', pady=(6, 0))
        ttk.Label(entry_frame, text="IP range:").pack(side='left')
        self.ip_var = tk.StringVar(value="192.168.1.0/24")
        self.entry = ttk.Entry(entry_frame, textvariable=self.ip_var, width=50)
        self.entry.pack(side='left', padx=(6, 6))

        self.start_btn = ttk.Button(entry_frame, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side='left')
        self.full_scan_btn = ttk.Button(entry_frame, text="Full Port Scan", command=self.full_port_scan)
        self.full_scan_btn.pack(side='left', padx=(6, 0))
        self.rescan_btn = ttk.Button(entry_frame, text="Rescan Selected", command=self.rescan_selected)
        self.rescan_btn.pack(side='left', padx=(6, 0))
        self.stop_btn = ttk.Button(entry_frame, text="Stop", command=self.stop_scan, state='disabled')
        self.stop_btn.pack(side='left', padx=(6, 0))
        self.export_btn = ttk.Button(entry_frame, text="Export CSV", command=self.export_csv)
        self.export_btn.pack(side='left', padx=(6, 0))
        self.save_btn = ttk.Button(entry_frame, text="Save JSON", command=self.save_json)
        self.save_btn.pack(side='left', padx=(6, 0))
        self.copy_ip_btn = ttk.Button(entry_frame, text="Copy IP", command=self.copy_selected_ip)
        self.copy_ip_btn.pack(side='left', padx=(6, 0))
        self.insights_btn = ttk.Button(entry_frame, text="Network Insights", command=self.show_network_insights)
        self.insights_btn.pack(side='left', padx=(6, 0))
        self.quit_btn = ttk.Button(entry_frame, text="Quit", command=root.quit)
        self.quit_btn.pack(side='left', padx=(6, 0))

        filter_frame = ttk.Frame(frm)
        filter_frame.pack(fill='x', pady=(8, 2))
        ttk.Label(filter_frame, text="Filter devices:").pack(side='left')
        self.filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=36)
        self.filter_entry.pack(side='left', padx=(6, 8))
        self.filter_entry.bind('<KeyRelease>', lambda _e: self.apply_filters())
        ttk.Checkbutton(
            filter_frame, text="Show only devices with open ports", variable=self.only_open_var,
            command=self.apply_filters
        ).pack(side='left')

        stats = ttk.Frame(frm)
        stats.pack(fill='x', pady=(4, 0))
        self.total_lbl = ttk.Label(stats, text="Total: 0", style="Stats.TLabel")
        self.total_lbl.pack(side='left', padx=(0, 12))
        self.open_lbl = ttk.Label(stats, text="With Open Ports: 0", style="Stats.TLabel")
        self.open_lbl.pack(side='left', padx=(0, 12))
        self.risk_lbl = ttk.Label(stats, text="High/Critical Risk: 0", style="Stats.TLabel")
        self.risk_lbl.pack(side='left', padx=(0, 12))
        self.latency_lbl = ttk.Label(stats, text="Avg Latency: N/A", style="Stats.TLabel")
        self.latency_lbl.pack(side='left')

        # Progress bar
        self.progress = ttk.Progressbar(frm, mode='determinate')
        self.progress.pack(fill='x', pady=(8, 0))

        # Upper: device table; Lower: details text
        paned = ttk.PanedWindow(root, orient='vertical')
        paned.pack(fill='both', expand=True, padx=8, pady=8)

        # Treeview for devices
        cols = ('ip', 'hostname', 'vendor', 'latency_ms', 'open_port_count', 'risk', 'open_ports', 'os', 'mac')
        self.tree = ttk.Treeview(paned, columns=cols, show='headings', selectmode='browse')
        for c in cols:
            self.tree.heading(c, text=c.upper(), command=lambda col=c: self.sort_tree(col))
            self.tree.column(c, anchor='w', width=120)
        self.tree.column('ip', width=140)
        self.tree.column('hostname', width=170)
        self.tree.column('vendor', width=170)
        self.tree.column('open_ports', width=220)
        self.tree.column('os', width=240)
        self.tree.column('mac', width=130)
        self.tree.column('open_port_count', width=115)
        self.tree.column('risk', width=100)
        self.tree.bind('<<TreeviewSelect>>', self.on_tree_select)
        tree_frame = ttk.Frame(paned)
        self.tree.pack(fill='both', expand=True, in_=tree_frame)
        paned.add(tree_frame, weight=3)

        # Details text
        self.text = scrolledtext.ScrolledText(paned, wrap='word', height=15)
        self.text.bind('<Button-1>', self.on_text_click)  # Add click handler
        paned.add(self.text, weight=2)

        # Threading / queue
        self.q = queue.Queue()
        self.worker = None
        self.stop_event = threading.Event()
        self.devices_data = []  # list of structured device dicts
        self.selected_ip = None
        self.root.after(200, self._poll_queue)

    def append_text(self, text):
        self.text.insert('end', text)
        self.text.see('end')

    def _poll_queue(self):
        try:
            while True:
                item = self.q.get_nowait()
                if isinstance(item, dict) and item.get('type') == 'progress':
                    self.progress['maximum'] = item.get('total', 1)
                    self.progress['value'] = item.get('value', 0)
                elif isinstance(item, dict) and item.get('type') == 'device_update':
                    dev = item.get('device')
                    self._upsert_device_in_table(dev)
                else:
                    self.append_text(str(item))
        except queue.Empty:
            pass
        self.root.after(200, self._poll_queue)

    def _upsert_device_in_table(self, dev):
        ip = dev.get('ip')
        existing = next((d for d in self.devices_data if d.get('ip') == ip), None)
        if existing:
            existing.update(dev)
        else:
            self.devices_data.append(dev)
        self.apply_filters()
        self._update_stats()

    def _to_float(self, value):
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _update_stats(self):
        total = len(self.devices_data)
        with_open = [d for d in self.devices_data if d.get('open_port_count', 0) > 0]
        high_risk = [d for d in self.devices_data if d.get('risk') in ("High", "Critical")]
        latency_values = [self._to_float(d.get('latency_ms')) for d in self.devices_data]
        latency_values = [v for v in latency_values if v is not None]
        avg_latency = f"{sum(latency_values)/len(latency_values):.1f} ms" if latency_values else "N/A"

        self.total_lbl.configure(text=f"Total: {total}")
        self.open_lbl.configure(text=f"With Open Ports: {len(with_open)}")
        self.risk_lbl.configure(text=f"High/Critical Risk: {len(high_risk)}")
        self.latency_lbl.configure(text=f"Avg Latency: {avg_latency}")

    def apply_filters(self):
        query = self.filter_var.get().strip().lower()
        only_open = self.only_open_var.get()
        selected = self.tree.selection()
        selected_ip = self.tree.set(selected[0], 'ip') if selected else None

        for item in self.tree.get_children():
            self.tree.delete(item)

        for dev in self.devices_data:
            if only_open and dev.get('open_port_count', 0) <= 0:
                continue
            searchable = " ".join([
                str(dev.get('ip', '')), str(dev.get('hostname', '')), str(dev.get('vendor', '')),
                str(dev.get('os', '')), str(dev.get('risk', ''))
            ]).lower()
            if query and query not in searchable:
                continue
            values = (
                dev.get('ip'),
                dev.get('hostname') or '',
                dev.get('vendor') or '',
                dev.get('latency_ms') or '',
                dev.get('open_port_count') or 0,
                dev.get('risk') or '',
                dev.get('ports_summary') or '',
                dev.get('os') or '',
                dev.get('mac') or ''
            )
            iid = self.tree.insert('', 'end', values=values)
            if selected_ip and dev.get('ip') == selected_ip:
                self.tree.selection_set(iid)

    def sort_tree(self, column):
        reverse = self.sort_state.get(column, False)
        self.sort_state[column] = not reverse
        rows = [(self.tree.set(item, column), item) for item in self.tree.get_children('')]
        numeric_cols = {'latency_ms', 'open_port_count'}
        if column in numeric_cols:
            rows.sort(key=lambda x: float(x[0]) if str(x[0]).replace('.', '', 1).isdigit() else float('inf'), reverse=reverse)
        else:
            rows.sort(key=lambda x: str(x[0]).lower(), reverse=reverse)
        for idx, (_, item) in enumerate(rows):
            self.tree.move(item, '', idx)

    def on_tree_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        ip = self.tree.set(iid, 'ip')
        self.selected_ip = ip
        dev = next((d for d in self.devices_data if d.get('ip') == ip), None)
        if not dev:
            return
        self.text.delete('1.0', 'end')
        self.append_text(format_device_details(dev) + '\n\n')
        self.append_text("Raw Data:\n")
        self.append_text(json.dumps(dev, indent=2, default=str) + '\n')

    def start_scan(self):
        val = self.ip_var.get().strip()
        if not val:
            messagebox.showinfo("Input required", "Please enter an IP range.")
            return
        try:
            parsed = parse_ip_range(val)
        except Exception as e:
            messagebox.showerror("Invalid input", str(e))
            return

        # disable start, enable stop
        self.start_btn['state'] = 'disabled'
        self.full_scan_btn['state'] = 'disabled'
        self.rescan_btn['state'] = 'disabled'
        self.stop_btn['state'] = 'normal'
        self.text.delete('1.0', 'end')
        self.progress['value'] = 0
        self.stop_event.clear()
        # clear table
        for c in self.tree.get_children():
            self.tree.delete(c)
        self.devices_data = []
        self._update_stats()

        # launch worker thread
        self.worker = threading.Thread(target=self._worker_thread, args=(parsed,), daemon=True)
        self.worker.start()

    def copy_selected_ip(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select Device", "Select a device first.")
            return
        ip = self.tree.set(sel[0], 'ip')
        if not ip:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(ip)
        self.append_text(f"Copied IP to clipboard: {ip}\n")

    def rescan_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select Device", "Select a device from the table first.")
            return
        ip = self.tree.set(sel[0], 'ip')
        if not ip:
            return

        self.start_btn['state'] = 'disabled'
        self.full_scan_btn['state'] = 'disabled'
        self.rescan_btn['state'] = 'disabled'
        self.stop_btn['state'] = 'normal'
        self.progress['value'] = 0
        self.stop_event.clear()

        def scan_selected():
            try:
                self.q.put(f"Rescanning {ip}...\n")
                devinfo = get_device_info_struct(ip)
                self.q.put({'type': 'device_update', 'device': devinfo})
                self.q.put(format_device_details(devinfo) + '\n')
                self.q.put({'type': 'progress', 'total': 1, 'value': 1})
            except Exception as e:
                self.q.put(f"Rescan error: {e}\n")
            finally:
                self._finish_worker()

        threading.Thread(target=scan_selected, daemon=True).start()

    def show_network_insights(self):
        self.append_text("\nNetwork Insights:\n")
        try:
            host_name = socket.gethostname()
            local_ip = socket.gethostbyname(host_name)
            self.append_text(f"  Hostname: {host_name}\n")
            self.append_text(f"  Local IP: {local_ip}\n")
            self.append_text(f"  Platform: {platform.system()} {platform.release()}\n")
        except Exception as e:
            self.append_text(f"  Local network info unavailable: {e}\n")

        try:
            response = requests.get("https://api.ipify.org?format=json", timeout=2)
            if response.ok:
                public_ip = response.json().get('ip')
                self.append_text(f"  Public IP: {public_ip}\n")
        except Exception:
            self.append_text("  Public IP lookup unavailable.\n")

    def stop_scan(self):
        self.stop_event.set()
        self.append_text("\nStop requested. Finishing current operation...\n")
        self.stop_btn['state'] = 'disabled'

    def _worker_thread(self, parsed_range):
        try:
            ip_arg = parsed_range
            total_targets = None
            if isinstance(parsed_range, list):
                total_targets = len(parsed_range)
            else:
                try:
                    net = ipaddress.ip_network(parsed_range, strict=False)
                    total_targets = net.num_addresses
                except Exception:
                    total_targets = 1

            self.q.put(f"Starting ARP scan over {total_targets} addresses...\n")
            if self.stop_event.is_set():
                self.q.put("Scan cancelled before start.\n")
                self._finish_worker()
                return

            devices = scan_network(ip_arg)
            if self.stop_event.is_set():
                self.q.put("Scan cancelled.\n")
                self._finish_worker()
                return

            if not devices:
                self.q.put("No devices found for the provided range.\n")
                self._finish_worker()
                return

            self.q.put({'type':'progress', 'total': len(devices), 'value': 0})
            idx = 0
            for device in devices:
                if self.stop_event.is_set():
                    self.q.put("Stop requested. Ending device scans.\n")
                    break
                ip = device.get('ip')
                mac = device.get('mac', '')
                self.q.put(f"\nProbing device {idx+1}/{len(devices)}: {ip}  MAC: {mac}\n")
                # get structured info (nmap + latency)
                devinfo = get_device_info_struct(ip)
                # fill mac if missing
                if not devinfo.get('mac'):
                    devinfo['mac'] = mac
                # queue device update for UI table
                self.q.put({'type':'device_update', 'device': devinfo})
                self.q.put(format_device_details(devinfo) + '\n')
                idx += 1
                self.q.put({'type':'progress', 'total': len(devices), 'value': idx})
                # small delay to avoid overwhelming local network/nmap
                time.sleep(0.2)

            self.q.put("\nScan complete.\n")
        except Exception as e:
            self.q.put(f"Error in scan thread: {e}\n")
        finally:
            self._finish_worker()

    def _finish_worker(self):
        self.q.put("\nReady for next scan.\n")
        self.start_btn['state'] = 'normal'
        self.full_scan_btn['state'] = 'normal'
        self.rescan_btn['state'] = 'normal'
        self.stop_btn['state'] = 'disabled'
        self.stop_event.clear()

    def export_csv(self):
        try:
            if not self.devices_data:
                messagebox.showinfo("No data", "No devices to export.")
                return
            path = tk.filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV','*.csv')])
            if not path:
                return
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['ip','hostname','vendor','mac','latency_ms','risk','open_port_count','os','open_ports'])
                for d in self.devices_data:
                    ports = ';'.join(f"{p['port']}/{p['proto']}({p['state']})" for p in d.get('ports',[]))
                    writer.writerow([
                        d.get('ip'), d.get('hostname'), d.get('vendor'), d.get('mac'),
                        d.get('latency_ms'), d.get('risk'), d.get('open_port_count'),
                        d.get('os'), ports
                    ])
            messagebox.showinfo("Exported", f"Saved CSV to {path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def save_json(self):
        try:
            if not self.devices_data:
                messagebox.showinfo("No data", "No devices to save.")
                return
            path = tk.filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON','*.json')])
            if not path:
                return
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.devices_data, f, indent=2, default=str)
            messagebox.showinfo("Saved", f"Saved JSON to {path}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def full_port_scan(self):
        """Run intensive port scan on selected device"""
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select Device", "Please select a device from the table first.")
            return
        
        iid = sel[0]  # Get the selected item ID
        ip = self.tree.set(iid, 'ip')  # Get IP from the selected row
        
        if not ip:
            messagebox.showerror("Error", "Could not get IP address from selection")
            return
            
        if messagebox.askyesno("Full Port Scan", 
                              f"Run full port scan on {ip}?\nThis may take several minutes."):
            self.start_btn['state'] = 'disabled'
            self.full_scan_btn['state'] = 'disabled'
            self.rescan_btn['state'] = 'disabled'
            self.stop_btn['state'] = 'normal'
            self.text.delete('1.0', 'end')
            self.progress['value'] = 0
            self.stop_event.clear()

            def scan_thread():
                try:
                    self.q.put(f"Starting full port scan of {ip}...\n")
                    nm = nmap.PortScanner()
                    
                    # Show progress during scan
                    self.q.put({'type': 'progress', 'total': 100, 'value': 0})
                    
                    # Run the intensive scan
                    nm.scan(ip, arguments='-p- -sV --version-intensity 5')
                    
                    if ip in nm.all_hosts():
                        host = nm[ip]
                        self.q.put("Scan complete. Results:\n\n")
                        
                        # Format and display results
                        for proto in host.all_protocols():
                            ports = host[proto].keys()
                            for port in sorted(ports):
                                service = host[proto][port]
                                self.q.put(
                                    f"Port {port}/{proto}:\n"
                                    f"  State: {service.get('state','?')}\n"
                                    f"  Service: {service.get('name','?')}\n"
                                    f"  Version: {service.get('version','?')}\n"
                                    f"  Product: {service.get('product','?')}\n"
                                    f"  Extra info: {service.get('extrainfo','')}\n"
                                    f"----------------------------------------\n"
                                )
                        
                        # Update device info in table
                        device = next((d for d in self.devices_data if d['ip'] == ip), None)
                        if device:
                            device['ports'] = [
                                {
                                    'port': port,
                                    'proto': proto,
                                    'state': host[proto][port]['state'],
                                    'service': host[proto][port]['name'],
                                    'version': host[proto][port]['version']
                            }
                            for proto in host.all_protocols()
                            for port in host[proto].keys()
                            ]
                            device['open_port_count'] = len([p for p in device['ports'] if p.get('state') == 'open'])
                            device['risk'] = _assess_risk(device['ports'])
                            device['ports_summary'] = _format_ports_summary(device['ports'])
                            device['scan_time'] = datetime.now().isoformat(timespec='seconds')
                            self.q.put({'type': 'device_update', 'device': device})
                            self.q.put("\nUpdated Device Summary:\n")
                            self.q.put(format_device_details(device) + "\n")
                    else:
                        self.q.put(f"No results found for {ip}\n")
                        
                except Exception as e:
                    self.q.put(f"Scan error: {e}\n")
                finally:
                    self._finish_worker()
                    self.q.put({'type': 'progress', 'total': 100, 'value': 100})

            threading.Thread(target=scan_thread, daemon=True).start()

    def on_text_click(self, event):
        try:
            # Get clicked line
            index = self.text.index(f"@{event.x},{event.y}")
            line = self.text.get(f"{index} linestart", f"{index} lineend")
            
            # Look for IP address in the line
            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            if ip_match:
                ip = ip_match.group(0)
                
                # Find and select corresponding row in tree
                for item in self.tree.get_children():
                    if self.tree.set(item, 'ip') == ip:
                        self.tree.selection_set(item)
                        self.tree.see(item)
                        self.on_tree_select(None)  # Update details
                        break
        except Exception as e:
            print(f"Text selection error: {e}")

# Parse command-line arguments for IP range with validation and many formats
def parse_ip_range(value):
    """
    Accepts:
      - CIDR (e.g. 192.168.1.0/24)
      - Single IP (e.g. 192.168.1.10)
      - Hyphen ranges:
          * full IPs: 192.168.1.10-192.168.1.20
          * shorthand last-octet: 192.168.1.1-254
      - Wildcard: 192.168.1.*
      - Comma separated list: 192.168.1.1,192.168.1.5,192.168.1.100
    Returns either a canonical CIDR string (for networks) or a list of IP strings.
    """
    value = value.strip()
    max_expand = 65536
    # Comma separated -> expand each and flatten
    if ',' in value:
        parts = [p.strip() for p in value.split(',') if p.strip()]
        ips = []
        for p in parts:
            expanded = parse_ip_range(p)
            if isinstance(expanded, list):
                ips.extend(expanded)
            else:
                # network string -> expand to addresses (beware large networks)
                net = ipaddress.ip_network(expanded, strict=False)
                ips.extend([str(ip) for ip in net.hosts()] or [str(ip) for ip in net])
            if len(ips) > max_expand:
                raise argparse.ArgumentTypeError(f"Range too large ({len(ips)} addresses). Limit is {max_expand}.")
        # preserve order while removing duplicates
        seen = set()
        deduped = []
        for ip in ips:
            if ip not in seen:
                deduped.append(ip)
                seen.add(ip)
        return deduped

    # CIDR?
    if '/' in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
            # return canonical network string (let scapy accept CIDR directly)
            return str(net)
        except ValueError:
            pass

    # Wildcard (e.g. 192.168.1.*)
    if '*' in value:
        base = value.replace('*', '0')
        try:
            net = ipaddress.ip_network(base + '/24', strict=False)
        except Exception:
            raise argparse.ArgumentTypeError(f"Invalid wildcard network: {value}")
        # derive start/end from wildcard by replacing '*' with 0..255
        # build explicit list (note: can be large)
        prefix_parts = value.split('.')
        if prefix_parts[-1] == '*':
            net = ipaddress.ip_network('.'.join(prefix_parts[:3] + ['0']) + '/24', strict=False)
            return [str(ip) for ip in net.hosts()] or [str(ip) for ip in net]
        else:
            raise argparse.ArgumentTypeError(f"Unsupported wildcard format: {value}")

    # Hyphen range
    if '-' in value:
        start_s, end_s = value.split('-', 1)
        start_s = start_s.strip()
        end_s = end_s.strip()
        try:
            start_ip = ipaddress.ip_address(start_s)
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid start IP: {start_s}")

        # If end is a full IP
        if '.' in end_s:
            try:
                end_ip = ipaddress.ip_address(end_s)
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid end IP: {end_s}")
        else:
            # shorthand end (last octet only)
            start_parts = start_s.split('.')
            if len(start_parts) != 4:
                raise argparse.ArgumentTypeError(f"Invalid start IP for shorthand range: {start_s}")
            end_parts = start_parts[:3] + [end_s]
            end_ip_str = '.'.join(end_parts)
            try:
                end_ip = ipaddress.ip_address(end_ip_str)
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid shorthand end IP: {end_ip_str}")

        # Ensure same IP version and start <= end
        if start_ip.version != end_ip.version:
            raise argparse.ArgumentTypeError("Start and end IP versions differ")
        if int(end_ip) < int(start_ip):
            raise argparse.ArgumentTypeError("End IP must be >= start IP")

        # build list (beware very large ranges)
        count = int(end_ip) - int(start_ip) + 1
        if count > max_expand:
            # defensive limit to avoid accidental huge expansions; remove or increase if you need
            raise argparse.ArgumentTypeError(f"Range too large ({count} addresses). Limit is {max_expand}.")
        return [str(ipaddress.ip_address(int(start_ip) + i)) for i in range(count)]

    # Single IP?
    try:
        ipaddress.ip_address(value)
        return [value]
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid IP, network or range: {value}")

# --- replaced argparse block with an interactive prompt
def prompt_for_ip_range(default="192.168.1.0/24"):
    prompt = (
        "IP range to scan (examples: CIDR, single IP, hyphen range, wildcard '*', comma list)\n"
        "Examples:\n"
        "  - CIDR:        192.168.1.0/24\n"
        "  - Single IP:   192.168.1.10\n"
        "  - Hyphen:      192.168.1.1-254   or   192.168.1.10-192.168.1.20\n"
        "  - Wildcard:    192.168.1.*\n"
        "  - Comma list:  192.168.1.1,192.168.1.5,192.168.1.100\n"
        "Type 'q' or 'quit' to exit.\n\n"
        f"Press Enter to use default [{default}]: "
    )
    try:
        raw = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print("\nExiting.")
        sys.exit(0)

    if not raw:
        raw = default

    if raw.lower() in ('q', 'quit', 'exit'):
        print("Exiting.")
        sys.exit(0)

    try:
        return parse_ip_range(raw)
    except argparse.ArgumentTypeError as e:
        print(f"Invalid IP range: {e}")
        return None

# Replace existing __main__ behavior with GUI
if __name__ == '__main__':
    print("Starting Network Scanner...")
    if sys.platform.startswith('win') and not is_admin():
        print("Requesting admin privileges...")
        try:
            script = sys.executable
            script_path = os.path.abspath(__file__)
            params = ' '.join([script, script_path])
            shell32 = ctypes.windll.shell32
            ret = shell32.ShellExecuteW(None, "runas", script, script_path, None, 1)
            if ret <= 32:  # Error codes from ShellExecute are 32 or less
                raise Exception(f"ShellExecute failed with code {ret}")
            sys.exit(0)
        except Exception as e:
            print(f"Error: Failed to restart with admin rights: {e}")
            input("Press Enter to exit...")
            sys.exit(1)
    else:
        try:
            root = tk.Tk()
            root.withdraw()  # Hide the root window initially
            
            # Center the window on screen
            screen_width = root.winfo_screenwidth()
            screen_height = root.winfo_screenheight()
            window_width = 1000
            window_height = 700
            x = (screen_width - window_width) // 2
            y = (screen_height - window_height) // 2
            
            root.geometry(f"{window_width}x{window_height}+{x}+{y}")
            root.deiconify()  # Show the window
            
            app = ScannerGUI(root)
            root.mainloop()
        except Exception as e:
            print(f"Error starting GUI: {e}")
            input("Press Enter to exit...")
            sys.exit(1)