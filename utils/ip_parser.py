import argparse
import ipaddress


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
    if ',' in value:
        parts = [p.strip() for p in value.split(',') if p.strip()]
        ips = []
        for p in parts:
            expanded = parse_ip_range(p)
            if isinstance(expanded, list):
                ips.extend(expanded)
            else:
                net = ipaddress.ip_network(expanded, strict=False)
                ips.extend([str(ip) for ip in net.hosts()] or [str(ip) for ip in net])
            if len(ips) > max_expand:
                raise argparse.ArgumentTypeError(f'Range too large ({len(ips)} addresses). Limit is {max_expand}.')
        seen = set()
        deduped = []
        for ip in ips:
            if ip not in seen:
                deduped.append(ip)
                seen.add(ip)
        return deduped

    if '/' in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
            return str(net)
        except ValueError:
            pass

    if '*' in value:
        base = value.replace('*', '0')
        try:
            net = ipaddress.ip_network(base + '/24', strict=False)
        except Exception:
            raise argparse.ArgumentTypeError(f'Invalid wildcard network: {value}')
        prefix_parts = value.split('.')
        if prefix_parts[-1] == '*':
            net = ipaddress.ip_network('.'.join(prefix_parts[:3] + ['0']) + '/24', strict=False)
            return [str(ip) for ip in net.hosts()] or [str(ip) for ip in net]
        raise argparse.ArgumentTypeError(f'Unsupported wildcard format: {value}')

    if '-' in value:
        start_s, end_s = value.split('-', 1)
        start_s = start_s.strip()
        end_s = end_s.strip()
        try:
            start_ip = ipaddress.ip_address(start_s)
        except ValueError:
            raise argparse.ArgumentTypeError(f'Invalid start IP: {start_s}')

        if '.' in end_s:
            try:
                end_ip = ipaddress.ip_address(end_s)
            except ValueError:
                raise argparse.ArgumentTypeError(f'Invalid end IP: {end_s}')
        else:
            start_parts = start_s.split('.')
            if len(start_parts) != 4:
                raise argparse.ArgumentTypeError(f'Invalid start IP for shorthand range: {start_s}')
            end_parts = start_parts[:3] + [end_s]
            end_ip_str = '.'.join(end_parts)
            try:
                end_ip = ipaddress.ip_address(end_ip_str)
            except ValueError:
                raise argparse.ArgumentTypeError(f'Invalid shorthand end IP: {end_ip_str}')

        if start_ip.version != end_ip.version:
            raise argparse.ArgumentTypeError('Start and end IP versions differ')
        if int(end_ip) < int(start_ip):
            raise argparse.ArgumentTypeError('End IP must be >= start IP')

        count = int(end_ip) - int(start_ip) + 1
        if count > max_expand:
            raise argparse.ArgumentTypeError(f'Range too large ({count} addresses). Limit is {max_expand}.')
        return [str(ipaddress.ip_address(int(start_ip) + i)) for i in range(count)]

    try:
        ipaddress.ip_address(value)
        return [value]
    except ValueError:
        raise argparse.ArgumentTypeError(f'Invalid IP, network or range: {value}')
