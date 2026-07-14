import csv


def export_devices_csv(path, devices):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['ip', 'hostname', 'vendor', 'mac', 'latency_ms', 'risk', 'open_port_count', 'os', 'open_ports'])
        for d in devices:
            ports = ';'.join(f"{p['port']}/{p['proto']}({p['state']})" for p in d.get('ports', []))
            writer.writerow([
                d.get('ip'), d.get('hostname'), d.get('vendor'), d.get('mac'),
                d.get('latency_ms'), d.get('risk'), d.get('open_port_count'),
                d.get('os'), ports,
            ])
