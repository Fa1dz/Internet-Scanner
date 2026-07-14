from datetime import datetime
import math

import nmap

from .latency import probe_latency
from .risk import _assess_risk, _format_ports_summary


def get_device_info_nmap(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-sP -sV --max-retries 1 --host-timeout 10s')
        return nm
    except Exception as e:
        print(f'Error scanning {ip}: {e}')
        return None


def get_device_info_nmap_gui(ip, put):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments='-sP -sV --max-retries 1 --host-timeout 10s')
        for host in nm.all_hosts():
            put(f'Host : {host} ({nm[host].hostname()})\n')
            put(f'State : {nm[host].state()}\n')
            if 'osclass' in nm[host]:
                oc = nm[host]['osclass'][0]
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
                put(f'Protocol : {proto}\n')
                lport = nm[host][proto].keys()
                for port in lport:
                    s = nm[host][proto][port]
                    put(f"  port: {port}\tstate: {s.get('state','?')}\n")
    except Exception as e:
        put(f'Error scanning {ip}: {e}\n')


def get_device_info_struct(ip):
    info = {
        'ip': ip,
        'hostname': None,
        'state': None,
        'mac': None,
        'vendor': None,
        'os': None,
        'latency_ms': None,
        'ports': [],
        'raw': None,
        'risk': 'Unknown',
        'open_port_count': 0,
        'scan_time': datetime.now().isoformat(timespec='seconds'),
    }
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-sn -PE -PS22,80,443 -PA3389 -T3 --host-timeout 8s')

        if ip in nm.all_hosts():
            host = nm[ip]
            info.update({
                'hostname': host.get('hostnames', [{'name': None}])[0].get('name'),
                'state': host.get('status', {}).get('state'),
                'mac': host.get('addresses', {}).get('mac'),
                'vendor': host.get('vendor', {}).get(host.get('addresses', {}).get('mac', ''), ''),
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
                        'product': port_info.get('product', ''),
                    })

        info['latency_ms'] = probe_latency(ip, timeout_ms=500)
        open_ports = [p for p in info['ports'] if p.get('state') == 'open']
        info['open_port_count'] = len(open_ports)
        info['risk'] = _assess_risk(info['ports'])
        info['ports_summary'] = _format_ports_summary(info['ports'])
    except Exception as e:
        print(f'Error scanning {ip}: {e}')

    return info


def scan_full_port_details(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-p- -sV --version-intensity 5')
        if ip not in nm.all_hosts():
            return None

        host = nm[ip]
        ports = []
        for proto in host.all_protocols():
            for port in sorted(host[proto].keys()):
                service = host[proto][port]
                ports.append({
                    'port': int(port),
                    'proto': proto,
                    'state': service.get('state', ''),
                    'service': service.get('name', ''),
                    'version': service.get('version', ''),
                    'product': service.get('product', ''),
                    'extrainfo': service.get('extrainfo', ''),
                })

        return {
            'ip': ip,
            'ports': ports,
            'scan_time': datetime.now().isoformat(timespec='seconds'),
        }
    except Exception as e:
        return {'ip': ip, 'error': str(e), 'ports': []}


def scan_full_port_details_chunked(ip, progress_cb=None, stop_event=None, chunk_size=4096):
    all_ports = []
    total_ports = 65535
    total_chunks = math.ceil(total_ports / chunk_size)

    for chunk_index in range(total_chunks):
        if stop_event is not None and stop_event.is_set():
            break

        start_port = chunk_index * chunk_size + 1
        end_port = min(total_ports, start_port + chunk_size - 1)
        nm = nmap.PortScanner()
        nm.scan(
            ip,
            arguments=f'-Pn -n -T4 --max-retries 1 --host-timeout 5m -p {start_port}-{end_port} -sV --version-light',
        )

        if ip in nm.all_hosts():
            host = nm[ip]
            for proto in host.all_protocols():
                for port in sorted(host[proto].keys()):
                    service = host[proto][port]
                    all_ports.append({
                        'port': int(port),
                        'proto': proto,
                        'state': service.get('state', ''),
                        'service': service.get('name', ''),
                        'version': service.get('version', ''),
                        'product': service.get('product', ''),
                        'extrainfo': service.get('extrainfo', ''),
                    })

        if progress_cb is not None:
            progress_cb(chunk_index + 1, total_chunks, start_port, end_port)

    return {
        'ip': ip,
        'ports': all_ports,
        'scan_time': datetime.now().isoformat(timespec='seconds'),
    }
