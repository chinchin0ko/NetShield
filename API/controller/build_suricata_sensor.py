#!/usr/bin/env python3
"""Build a bounded, alert-only Suricata configuration for the VPN sensor."""
import argparse
import re
from pathlib import Path
import yaml


def build(source_config, source_rules, output_dir, rule_limit=3000):
    config = yaml.safe_load(source_config.read_text())
    if not isinstance(config, dict) or not isinstance(config.get('outputs'), list):
        raise ValueError('invalid Suricata configuration')
    chosen = []
    signature = re.compile(r'\bmsg:\s*"([^"\\]*(?:\\.[^"\\]*)*)"', re.I)
    for rule in source_rules.read_text(errors='strict').splitlines():
        if not rule.startswith('alert '):
            continue
        match = signature.search(rule)
        if match and re.search(r'\b(MALWARE|TROJAN|EXPLOIT)\b', match.group(1), re.I):
            chosen.append(rule)
            if len(chosen) >= rule_limit:
                break
    if not chosen:
        raise ValueError('no matching rules')
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    chosen.append('alert dns any any -> any any (msg:"NETSHIELD MALWARE TEST simulated indicator"; dns.query; content:"netshield-sensor-test.invalid"; nocase; sid:9900099; rev:1;)')
    (output_dir / 'rules.rules').write_text('\n'.join(chosen) + '\n')
    config['outputs'] = [{'eve-log': {'enabled': True, 'filetype': 'regular',
                                      'filename': 'eve.json', 'types': [{'alert': {'payload': False, 'packet': False}}]}}]
    config['stats'] = {'enabled': False}
    config['threading'] = {'set-cpu-affinity': False}
    (output_dir / 'suricata.yaml').write_text('%YAML 1.1\n---\n' + yaml.safe_dump(config, sort_keys=False))
    return len(chosen) - 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('config', type=Path)
    parser.add_argument('rules', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print('Reglas seleccionadas:', build(args.config, args.rules, args.output))
