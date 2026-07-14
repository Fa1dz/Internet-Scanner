CRITICAL_PORTS = {21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 5900}


def _assess_risk(ports):
    if not ports:
        return 'Low'
    open_ports = [p for p in ports if p.get('state') == 'open']
    if not open_ports:
        return 'Low'
    risky = [p for p in open_ports if int(p.get('port', 0)) in CRITICAL_PORTS]
    if len(open_ports) >= 12 or len(risky) >= 6:
        return 'Critical'
    if len(open_ports) >= 7 or len(risky) >= 4:
        return 'High'
    if len(open_ports) >= 3 or len(risky) >= 2:
        return 'Medium'
    return 'Low'


def _format_ports_summary(ports, limit=8):
    open_ports = [p for p in ports if p.get('state') == 'open']
    open_ports = sorted(open_ports, key=lambda x: int(x.get('port', 0)))
    samples = [f"{p.get('port')}/{p.get('proto')}:{p.get('service') or 'unknown'}" for p in open_ports[:limit]]
    more = '...' if len(open_ports) > limit else ''
    return ', '.join(samples) + more
