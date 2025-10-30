import socket
import requests
from scapy.all import ARP, Ether, srp
from tqdm import tqdm
from tkinter import ttk, messagebox, scrolledtext, filedialog
import tkinter as tk
import nmap
import ctypes
import sys
import os
import subprocess
import json
import csv
import time
import ipaddress
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

def probe_latency(ip, timeout_ms=500):
    try:
        if sys.platform.startswith('win'):
            proc = subprocess.run(['ping', '-n', '1', '-w', str(timeout_ms), ip],
                                capture_output=True, text=True, timeout=timeout_ms/1000)
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if 'time=' in line:
                        return line.split('time=')[1].split('ms')[0].strip()
    except Exception:
        pass
    return None

def get_device_info_struct(ip):
    info = {'ip': ip, 'hostname': None, 'state': None, 'mac': None, 'vendor': None,
            'os': None, 'latency_ms': None, 'ports': [], 'raw': None}
    try:
        # Faster scan with fewer options
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-sn -T4 --host-timeout 5s')  # Quick ping scan
        
        if ip in nm.all_hosts():
            host = nm[ip]
            
            # Basic info from initial scan
            info.update({
                'hostname': host.get('hostnames', [{'name': None}])[0].get('name'),
                'state': host.get('status', {}).get('state'),
                'mac': host.get('addresses', {}).get('mac'),
                'vendor': host.get('vendor', {}).get(host.get('addresses', {}).get('mac', ''), '')
            })
            
            # Quick port scan for most common ports
            nm.scan(ip, arguments='-sS -T4 -F --version-light --host-timeout 10s')
            if ip in nm.all_hosts():
                host = nm[ip]
                
                # Handle OS detection (if available)
                if 'osmatch' in host and host['osmatch']:
                    info['os'] = host['osmatch'][0].get('name', '')
                
                # Handle ports (only most common)
                for proto in host.all_protocols():
                    ports = host[proto].keys()
                    for p in ports:
                        port_info = host[proto][p]
                        info['ports'].append({
                            'port': int(p),
                            'proto': proto,
                            'state': port_info.get('state', ''),
                            'service': port_info.get('name', ''),
                            'version': port_info.get('version', '')
                        })
        
        # Quick latency check
        info['latency_ms'] = probe_latency(ip, timeout_ms=500)
        
    except Exception as e:
        print(f"Error scanning {ip}: {e}")
        
    return info

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
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
        root.title("Local Network Scanner")
        root.geometry("1000x700")

        # Input frame
        frm = ttk.Frame(root, padding=8)
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
        entry_frame.pack(fill='x', pady=(6,0))
        ttk.Label(entry_frame, text="IP range:").pack(side='left')
        self.ip_var = tk.StringVar(value="192.168.1.0/24")
        self.entry = ttk.Entry(entry_frame, textvariable=self.ip_var, width=50)
        self.entry.pack(side='left', padx=(6,6))

        self.start_btn = ttk.Button(entry_frame, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side='left')
        self.full_scan_btn = ttk.Button(entry_frame, text="Full Port Scan", command=self.full_port_scan)
        self.full_scan_btn.pack(side='left', padx=(6,0))
        self.stop_btn = ttk.Button(entry_frame, text="Stop", command=self.stop_scan, state='disabled')
        self.stop_btn.pack(side='left', padx=(6,0))
        self.export_btn = ttk.Button(entry_frame, text="Export CSV", command=self.export_csv)
        self.export_btn.pack(side='left', padx=(6,0))
        self.save_btn = ttk.Button(entry_frame, text="Save JSON", command=self.save_json)
        self.save_btn.pack(side='left', padx=(6,0))
        self.quit_btn = ttk.Button(entry_frame, text="Quit", command=root.quit)
        self.quit_btn.pack(side='left', padx=(6,0))

        # Progress bar
        self.progress = ttk.Progressbar(frm, mode='determinate')
        self.progress.pack(fill='x', pady=(8,0))

        # Upper: device table; Lower: details text
        paned = ttk.PanedWindow(root, orient='vertical')
        paned.pack(fill='both', expand=True, padx=8, pady=8)

        # Treeview for devices
        cols = ('ip','mac','hostname','vendor','latency_ms','open_ports','os')
        self.tree = ttk.Treeview(paned, columns=cols, show='headings', selectmode='browse')
        for c in cols:
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, anchor='w', width=120)
        self.tree.column('open_ports', width=180)
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
        # find existing by IP
        ip = dev.get('ip')
        for iid in self.tree.get_children():
            if self.tree.set(iid, 'ip') == ip:
                # update
                self.tree.set(iid, 'mac', dev.get('mac') or '')
                self.tree.set(iid, 'hostname', dev.get('hostname') or '')
                self.tree.set(iid, 'vendor', dev.get('vendor') or '')
                self.tree.set(iid, 'latency_ms', dev.get('latency_ms') or '')
                # open_ports summary
                ports = ','.join(str(p['port']) for p in dev.get('ports', [])[:6])
                self.tree.set(iid, 'open_ports', ports)
                self.tree.set(iid, 'os', dev.get('os') or '')
                return
        # insert new
        ports = ','.join(str(p['port']) for p in dev.get('ports', [])[:6])
        iid = self.tree.insert('', 'end', values=(
            dev.get('ip'), dev.get('mac') or '', dev.get('hostname') or '',
            dev.get('vendor') or '', dev.get('latency_ms') or '', ports, dev.get('os') or ''
        ))
        # save mapping index
        self.devices_data.append(dev)

    def on_tree_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        ip = self.tree.set(iid, 'ip')
        # find device struct
        dev = None
        for d in self.devices_data:
            if d.get('ip') == ip:
                dev = d; break
        if not dev:
            return
        # show detailed info
        text = json.dumps(dev, indent=2, default=str)
        self.text.delete('1.0', 'end')
        self.append_text(text + '\n')

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
        self.stop_btn['state'] = 'normal'
        self.text.delete('1.0', 'end')
        self.progress['value'] = 0
        self.stop_event.clear()
        # clear table
        for c in self.tree.get_children():
            self.tree.delete(c)
        self.devices_data = []

        # launch worker thread
        self.worker = threading.Thread(target=self._worker_thread, args=(parsed,), daemon=True)
        self.worker.start()

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
                # append full detail to text window as well
                self.q.put(json.dumps(devinfo, indent=2, default=str) + '\n')
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
                writer.writerow(['ip','mac','hostname','vendor','latency_ms','os','open_ports'])
                for d in self.devices_data:
                    ports = ';'.join(f"{p['port']}/{p['proto']}({p['state']})" for p in d.get('ports',[]))
                    writer.writerow([d.get('ip'), d.get('mac'), d.get('hostname'), d.get('vendor'), d.get('latency_ms'), d.get('os'), ports])
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
                            self.q.put({'type': 'device_update', 'device': device})
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
            import re
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
        return ips

    # CIDR?
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
        if count > 65536:
            # defensive limit to avoid accidental huge expansions; remove or increase if you need
            raise argparse.ArgumentTypeError(f"Range too large ({count} addresses). Limit is 65536.")
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
    if not is_admin():
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