from collections import Counter

from .risk import _format_ports_summary


def format_device_details(dev):
    open_ports = [p for p in dev.get('ports', []) if p.get('state') == 'open']
    service_counter = Counter((p.get('service') or 'unknown') for p in open_ports)
    top_services = ', '.join(f'{name} ({count})' for name, count in service_counter.most_common(6)) or 'None'
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
    return '\n'.join(lines)


def device_row_values(dev):
    return (
        dev.get('ip'),
        dev.get('hostname') or '',
        dev.get('vendor') or '',
        dev.get('latency_ms') or '',
        dev.get('open_port_count') or 0,
        dev.get('risk') or '',
        dev.get('ports_summary') or '',
        dev.get('os') or '',
        dev.get('mac') or '',
    )
