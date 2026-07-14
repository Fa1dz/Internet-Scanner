import json
import platform
import queue
import socket
import threading
import time
import tkinter as tk
from tkinter import scrolledtext, ttk

import requests

from export.csv_export import export_devices_csv
from export.json_export import export_devices_json
from gui.dialogs import ask_full_port_scan, ask_save_csv_path, ask_save_json_path, show_error, show_info
from gui.table import COLUMN_WIDTHS, DEVICE_COLUMNS, NUMERIC_COLUMNS, device_row_values
from scanner.arp_scan import scan_network
from scanner.models import format_device_details
from scanner.nmap_scan import get_device_info_struct, scan_full_port_details_chunked
from scanner.risk import _assess_risk, _format_ports_summary
from utils.ip_parser import parse_ip_range


class ScannerGUI:
    def __init__(self, root):
        self.root = root
        root.title('Local Network Scanner Pro')
        root.geometry('1200x760')
        self.style = ttk.Style()
        if 'clam' in self.style.theme_names():
            self.style.theme_use('clam')
        self.style.configure('Header.TLabel', font=('Segoe UI', 16, 'bold'))
        self.style.configure('SubHeader.TLabel', font=('Segoe UI', 10))
        self.style.configure('Stats.TLabel', font=('Segoe UI', 10, 'bold'))

        self.sort_state = {}
        self.filter_var = tk.StringVar()
        self.only_open_var = tk.BooleanVar(value=False)

        header = ttk.Frame(root, padding=(10, 10, 10, 6))
        header.pack(fill='x')
        ttk.Label(header, text='Network Scanner Pro', style='Header.TLabel').pack(anchor='w')
        ttk.Label(
            header,
            text='Real-time LAN discovery, richer host insights, smart risk scoring, and fast filtering.',
            style='SubHeader.TLabel',
        ).pack(anchor='w', pady=(2, 0))

        frm = ttk.Frame(root, padding=(10, 2, 10, 8))
        frm.pack(fill='x')

        examples = (
            'Examples:\n'
            '  CIDR:        192.168.1.0/24\n'
            '  Single IP:   192.168.1.10\n'
            '  Hyphen:      192.168.1.1-254  or  192.168.1.10-192.168.1.20\n'
            '  Wildcard:    192.168.1.*\n'
            '  Comma list:  192.168.1.1,192.168.1.5,192.168.1.100\n'
        )
        ttk.Label(frm, text=examples, justify='left').pack(fill='x')

        entry_frame = ttk.Frame(frm)
        entry_frame.pack(fill='x', pady=(6, 0))
        ttk.Label(entry_frame, text='IP range:').pack(side='left')
        self.ip_var = tk.StringVar(value='192.168.1.0/24')
        self.entry = ttk.Entry(entry_frame, textvariable=self.ip_var, width=50)
        self.entry.pack(side='left', padx=(6, 6))

        self.start_btn = ttk.Button(entry_frame, text='Start Scan', command=self.start_scan)
        self.start_btn.pack(side='left')
        self.full_scan_btn = ttk.Button(entry_frame, text='Full Port Scan', command=self.full_port_scan)
        self.full_scan_btn.pack(side='left', padx=(6, 0))
        self.rescan_btn = ttk.Button(entry_frame, text='Rescan Selected', command=self.rescan_selected)
        self.rescan_btn.pack(side='left', padx=(6, 0))
        self.stop_btn = ttk.Button(entry_frame, text='Stop', command=self.stop_scan, state='disabled')
        self.stop_btn.pack(side='left', padx=(6, 0))
        self.export_btn = ttk.Button(entry_frame, text='Export CSV', command=self.export_csv)
        self.export_btn.pack(side='left', padx=(6, 0))
        self.save_btn = ttk.Button(entry_frame, text='Save JSON', command=self.save_json)
        self.save_btn.pack(side='left', padx=(6, 0))
        self.copy_ip_btn = ttk.Button(entry_frame, text='Copy IP', command=self.copy_selected_ip)
        self.copy_ip_btn.pack(side='left', padx=(6, 0))
        self.insights_btn = ttk.Button(entry_frame, text='Network Insights', command=self.show_network_insights)
        self.insights_btn.pack(side='left', padx=(6, 0))
        self.quit_btn = ttk.Button(entry_frame, text='Quit', command=root.quit)
        self.quit_btn.pack(side='left', padx=(6, 0))

        filter_frame = ttk.Frame(frm)
        filter_frame.pack(fill='x', pady=(8, 2))
        ttk.Label(filter_frame, text='Filter devices:').pack(side='left')
        self.filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=36)
        self.filter_entry.pack(side='left', padx=(6, 8))
        self.filter_entry.bind('<KeyRelease>', lambda _e: self.apply_filters())
        ttk.Checkbutton(
            filter_frame,
            text='Show only devices with open ports',
            variable=self.only_open_var,
            command=self.apply_filters,
        ).pack(side='left')

        stats = ttk.Frame(frm)
        stats.pack(fill='x', pady=(4, 0))
        self.total_lbl = ttk.Label(stats, text='Total: 0', style='Stats.TLabel')
        self.total_lbl.pack(side='left', padx=(0, 12))
        self.open_lbl = ttk.Label(stats, text='With Open Ports: 0', style='Stats.TLabel')
        self.open_lbl.pack(side='left', padx=(0, 12))
        self.risk_lbl = ttk.Label(stats, text='High/Critical Risk: 0', style='Stats.TLabel')
        self.risk_lbl.pack(side='left', padx=(0, 12))
        self.latency_lbl = ttk.Label(stats, text='Avg Latency: N/A', style='Stats.TLabel')
        self.latency_lbl.pack(side='left')

        self.progress = ttk.Progressbar(frm, mode='determinate')
        self.progress.pack(fill='x', pady=(8, 0))

        paned = ttk.PanedWindow(root, orient='vertical')
        paned.pack(fill='both', expand=True, padx=8, pady=8)

        self.tree = ttk.Treeview(paned, columns=DEVICE_COLUMNS, show='headings', selectmode='browse')
        for column in DEVICE_COLUMNS:
            self.tree.heading(column, text=column.upper(), command=lambda col=column: self.sort_tree(col))
            self.tree.column(column, anchor='w', width=COLUMN_WIDTHS.get(column, 120))
        self.tree.bind('<<TreeviewSelect>>', self.on_tree_select)
        tree_frame = ttk.Frame(paned)
        self.tree.pack(fill='both', expand=True, in_=tree_frame)
        paned.add(tree_frame, weight=3)

        self.text = scrolledtext.ScrolledText(paned, wrap='word', height=15)
        self.text.bind('<Button-1>', self.on_text_click)
        paned.add(self.text, weight=2)

        self.q = queue.Queue()
        self.worker = None
        self.stop_event = threading.Event()
        self.devices_data = []
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
                    self._upsert_device_in_table(item.get('device'))
                else:
                    self.append_text(str(item))
        except queue.Empty:
            pass
        self.root.after(200, self._poll_queue)

    def _upsert_device_in_table(self, dev):
        if not dev:
            return
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
        high_risk = [d for d in self.devices_data if d.get('risk') in ('High', 'Critical')]
        latency_values = [self._to_float(d.get('latency_ms')) for d in self.devices_data]
        latency_values = [v for v in latency_values if v is not None]
        avg_latency = f"{sum(latency_values) / len(latency_values):.1f} ms" if latency_values else 'N/A'

        self.total_lbl.configure(text=f'Total: {total}')
        self.open_lbl.configure(text=f'With Open Ports: {len(with_open)}')
        self.risk_lbl.configure(text=f'High/Critical Risk: {len(high_risk)}')
        self.latency_lbl.configure(text=f'Avg Latency: {avg_latency}')

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
            searchable = ' '.join([
                str(dev.get('ip', '')),
                str(dev.get('hostname', '')),
                str(dev.get('vendor', '')),
                str(dev.get('os', '')),
                str(dev.get('risk', '')),
            ]).lower()
            if query and query not in searchable:
                continue
            iid = self.tree.insert('', 'end', values=device_row_values(dev))
            if selected_ip and dev.get('ip') == selected_ip:
                self.tree.selection_set(iid)

    def sort_tree(self, column):
        reverse = self.sort_state.get(column, False)
        self.sort_state[column] = not reverse
        rows = [(self.tree.set(item, column), item) for item in self.tree.get_children('')]
        if column in NUMERIC_COLUMNS:
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
        self.append_text('Raw Data:\n')
        self.append_text(json.dumps(dev, indent=2, default=str) + '\n')

    def start_scan(self):
        val = self.ip_var.get().strip()
        if not val:
            show_info('Input required', 'Please enter an IP range.')
            return
        try:
            parsed = parse_ip_range(val)
        except Exception as e:
            show_error('Invalid input', str(e))
            return

        self.start_btn['state'] = 'disabled'
        self.full_scan_btn['state'] = 'disabled'
        self.rescan_btn['state'] = 'disabled'
        self.stop_btn['state'] = 'normal'
        self.text.delete('1.0', 'end')
        self.progress['value'] = 0
        self.stop_event.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.devices_data = []
        self._update_stats()

        self.worker = threading.Thread(target=self._worker_thread, args=(parsed,), daemon=True)
        self.worker.start()

    def copy_selected_ip(self):
        sel = self.tree.selection()
        if not sel:
            show_info('Select Device', 'Select a device first.')
            return
        ip = self.tree.set(sel[0], 'ip')
        if not ip:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(ip)
        self.append_text(f'Copied IP to clipboard: {ip}\n')

    def rescan_selected(self):
        sel = self.tree.selection()
        if not sel:
            show_info('Select Device', 'Select a device from the table first.')
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
                self.q.put(f'Rescanning {ip}...\n')
                devinfo = get_device_info_struct(ip)
                self.q.put({'type': 'device_update', 'device': devinfo})
                self.q.put(format_device_details(devinfo) + '\n')
                self.q.put({'type': 'progress', 'total': 1, 'value': 1})
            except Exception as e:
                self.q.put(f'Rescan error: {e}\n')
            finally:
                self._finish_worker()

        threading.Thread(target=scan_selected, daemon=True).start()

    def show_network_insights(self):
        self.append_text('\nNetwork Insights:\n')
        try:
            host_name = socket.gethostname()
            local_ip = socket.gethostbyname(host_name)
            self.append_text(f'  Hostname: {host_name}\n')
            self.append_text(f'  Local IP: {local_ip}\n')
            self.append_text(f'  Platform: {platform.system()} {platform.release()}\n')
        except Exception as e:
            self.append_text(f'  Local network info unavailable: {e}\n')

        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=2)
            if response.ok:
                public_ip = response.json().get('ip')
                self.append_text(f'  Public IP: {public_ip}\n')
        except Exception:
            self.append_text('  Public IP lookup unavailable.\n')

    def stop_scan(self):
        self.stop_event.set()
        self.append_text('\nStop requested. Finishing current operation...\n')
        self.stop_btn['state'] = 'disabled'

    def _worker_thread(self, parsed_range):
        try:
            ip_arg = parsed_range
            total_targets = len(parsed_range) if isinstance(parsed_range, list) else 1

            self.q.put(f'Starting ARP scan over {total_targets} addresses...\n')
            if self.stop_event.is_set():
                self.q.put('Scan cancelled before start.\n')
                self._finish_worker()
                return

            devices = scan_network(ip_arg)
            if self.stop_event.is_set():
                self.q.put('Scan cancelled.\n')
                self._finish_worker()
                return

            if not devices:
                self.q.put('No devices found for the provided range.\n')
                self._finish_worker()
                return

            self.q.put({'type': 'progress', 'total': len(devices), 'value': 0})
            idx = 0
            for device in devices:
                if self.stop_event.is_set():
                    self.q.put('Stop requested. Ending device scans.\n')
                    break
                ip = device.get('ip')
                mac = device.get('mac', '')
                self.q.put(f'\nProbing device {idx + 1}/{len(devices)}: {ip}  MAC: {mac}\n')
                devinfo = get_device_info_struct(ip)
                if not devinfo.get('mac'):
                    devinfo['mac'] = mac
                self.q.put({'type': 'device_update', 'device': devinfo})
                self.q.put(format_device_details(devinfo) + '\n')
                idx += 1
                self.q.put({'type': 'progress', 'total': len(devices), 'value': idx})
                time.sleep(0.2)

            self.q.put('\nScan complete.\n')
        except Exception as e:
            self.q.put(f'Error in scan thread: {e}\n')
        finally:
            self._finish_worker()

    def _finish_worker(self):
        self.q.put('\nReady for next scan.\n')
        self.start_btn['state'] = 'normal'
        self.full_scan_btn['state'] = 'normal'
        self.rescan_btn['state'] = 'normal'
        self.stop_btn['state'] = 'disabled'
        self.stop_event.clear()

    def export_csv(self):
        try:
            if not self.devices_data:
                show_info('No data', 'No devices to export.')
                return
            path = ask_save_csv_path()
            if not path:
                return
            export_devices_csv(path, self.devices_data)
            show_info('Exported', f'Saved CSV to {path}')
        except Exception as e:
            show_error('Export failed', str(e))

    def save_json(self):
        try:
            if not self.devices_data:
                show_info('No data', 'No devices to save.')
                return
            path = ask_save_json_path()
            if not path:
                return
            export_devices_json(path, self.devices_data)
            show_info('Saved', f'Saved JSON to {path}')
        except Exception as e:
            show_error('Save failed', str(e))

    def full_port_scan(self):
        sel = self.tree.selection()
        if not sel:
            show_info('Select Device', 'Please select a device from the table first.')
            return

        iid = sel[0]
        ip = self.tree.set(iid, 'ip')
        if not ip:
            show_error('Error', 'Could not get IP address from selection')
            return

        if not ask_full_port_scan(ip):
            return

        self.start_btn['state'] = 'disabled'
        self.full_scan_btn['state'] = 'disabled'
        self.rescan_btn['state'] = 'disabled'
        self.stop_btn['state'] = 'normal'
        self.text.delete('1.0', 'end')
        self.progress['value'] = 0
        self.stop_event.clear()

        def scan_thread():
            try:
                self.q.put(f'Starting full port scan of {ip}...\n')
                self.q.put({'type': 'progress', 'total': 100, 'value': 0})

                chunk_messages = []

                def progress_cb(chunk_index, total_chunks, start_port, end_port):
                    percent = int((chunk_index / total_chunks) * 100)
                    self.q.put({'type': 'progress', 'total': 100, 'value': percent})
                    self.q.put(f'Completed port range {start_port}-{end_port} ({chunk_index}/{total_chunks})\n')

                scan_result = scan_full_port_details_chunked(
                    ip,
                    progress_cb=progress_cb,
                    stop_event=self.stop_event,
                    chunk_size=4096,
                )

                if self.stop_event.is_set():
                    self.q.put('Full port scan stopped before completion.\n')
                    return

                if not scan_result:
                    self.q.put(f'No results found for {ip}\n')
                    return
                if scan_result.get('error'):
                    self.q.put(f"Scan error: {scan_result['error']}\n")
                    return

                self.q.put('Scan complete. Results:\n\n')
                for port in scan_result.get('ports', []):
                    chunk_messages.append(
                        f"Port {port['port']}/{port['proto']}:\n"
                        f"  State: {port.get('state','?')}\n"
                        f"  Service: {port.get('service','?')}\n"
                        f"  Version: {port.get('version','?')}\n"
                        f"  Product: {port.get('product','?')}\n"
                        f"  Extra info: {port.get('extrainfo','')}\n"
                        f"----------------------------------------\n"
                    )

                if chunk_messages:
                    self.q.put(''.join(chunk_messages))

                device = next((d for d in self.devices_data if d['ip'] == ip), None)
                if device:
                    device['ports'] = scan_result.get('ports', [])
                    device['open_port_count'] = len([p for p in device['ports'] if p.get('state') == 'open'])
                    device['risk'] = _assess_risk(device['ports'])
                    device['ports_summary'] = _format_ports_summary(device['ports'])
                    device['scan_time'] = scan_result.get('scan_time')
                    self.q.put({'type': 'device_update', 'device': device})
                    self.q.put('\nUpdated Device Summary:\n')
                    self.q.put(format_device_details(device) + '\n')
            except Exception as e:
                self.q.put(f'Scan error: {e}\n')
            finally:
                self._finish_worker()
                self.q.put({'type': 'progress', 'total': 100, 'value': 100})

        threading.Thread(target=scan_thread, daemon=True).start()

    def on_text_click(self, event):
        try:
            index = self.text.index(f'@{event.x},{event.y}')
            line = self.text.get(f'{index} linestart', f'{index} lineend')
            import re

            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            if ip_match:
                ip = ip_match.group(0)
                for item in self.tree.get_children():
                    if self.tree.set(item, 'ip') == ip:
                        self.tree.selection_set(item)
                        self.tree.see(item)
                        self.on_tree_select(None)
                        break
        except Exception as e:
            print(f'Text selection error: {e}')


def run_gui():
    root = tk.Tk()
    root.withdraw()

    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    window_width = 1000
    window_height = 700
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2

    root.geometry(f'{window_width}x{window_height}+{x}+{y}')
    root.deiconify()

    ScannerGUI(root)
    root.mainloop()
