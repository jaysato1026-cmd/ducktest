"""Offline planner. Python 3.7+, standard library only. No network or firewall writes."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path


def build(policy):
    if policy.get('version') != 1 or policy.get('port') != 8080:
        raise ValueError('Only version 1 / TCP 8080 is supported')
    if not isinstance(policy.get('inventory_approved'), bool):
        raise ValueError('inventory_approved must be boolean')
    if not isinstance(policy.get('target_computer'), str):
        raise ValueError('target_computer must be a string')
    sources = policy.get('allowed_sources')
    if not isinstance(sources, list) or not sources:
        raise ValueError('A nonempty allowed_sources list is required')
    nets = []
    for source in sources:
        net = ipaddress.ip_network(source, strict=True)
        if net.prefixlen == 0:
            raise ValueError('All-address allow lists provide no protection')
        # IPv4-mapped IPv6 addresses are normalized by the connection guard.
        if net.version == 6 and net.overlaps(ipaddress.ip_network('::ffff:0:0/96')):
            raise ValueError('Use native IPv4 entries, not IPv4-mapped IPv6 sources')
        nets.append(net)
    nets += [ipaddress.ip_network('127.0.0.0/8'), ipaddress.ip_network('::1/128')]
    allowed, blocked = [], []
    for family in (4, 6):
        union = list(ipaddress.collapse_addresses(n for n in nets if n.version == family))
        allowed.extend(str(n) for n in union)
        remaining = [ipaddress.ip_network('0.0.0.0/0' if family == 4 else '::/0')]
        for net in union:
            next_ranges = []
            for candidate in remaining:
                if net.subnet_of(candidate):
                    next_ranges.extend(candidate.address_exclude(net))
                elif not candidate.subnet_of(net):
                    next_ranges.append(candidate)
            remaining = next_ranges
        blocked.extend(str(n) for n in remaining)
    ready = policy['inventory_approved'] and bool(policy['target_computer'].strip())
    return dict(version=1, port=8080, ready=ready,
                target_computer=policy['target_computer'], allowed=allowed, blocked=blocked,
                warning='Preview only until complete LAN, NAT, backup and IPv6 inventory is approved.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('policy', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    plan = build(json.loads(args.policy.read_text(encoding='utf-8-sig')))
    payload = (json.dumps(plan, indent=2, ensure_ascii=True) + '\n').encode('utf-8')
    args.output.write_bytes(payload)
    print('READY' if plan['ready'] else 'PREVIEW ONLY - apply will refuse')
    print('Plan SHA256:', hashlib.sha256(payload).hexdigest())
    print('Blocked CIDRs:', len(plan['blocked']))


if __name__ == '__main__':
    main()
