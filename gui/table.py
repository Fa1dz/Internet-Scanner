DEVICE_COLUMNS = ('ip', 'hostname', 'vendor', 'latency_ms', 'open_port_count', 'risk', 'open_ports', 'os', 'mac')

COLUMN_WIDTHS = {
    'ip': 140,
    'hostname': 170,
    'vendor': 170,
    'latency_ms': 120,
    'open_port_count': 115,
    'risk': 100,
    'open_ports': 220,
    'os': 240,
    'mac': 130,
}

NUMERIC_COLUMNS = {'latency_ms', 'open_port_count'}


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
