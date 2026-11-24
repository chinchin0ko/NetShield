#!/usr/bin/env python3
"""Build a bounded, balanced, alert-only Suricata configuration."""
import argparse
import hashlib
import re
from pathlib import Path
import yaml

CATEGORIES = ('MALWARE', 'TROJAN', 'EXPLOIT', 'CNC', 'PHISHING')
SIGNATURE = re.compile(r'\bmsg:\s*"([^"\\]*(?:\\.[^"\\]*)*)"', re.I)
SID = re.compile(r'\bsid:\s*(\d+)\s*;', re.I)
# Select rules that can be evaluated independently of rules outside this subset.
STATE_DEPENDENCY = re.compile(r'\b(?:flowbits|xbits):\s*(?:isset|isnotset)\b|\b(?:flowbits|xbits):\s*noalert\b', re.I)
TEST_RULE = 'alert dns any any -> any any (msg:"NETSHIELD MALWARE TEST simulated indicator"; dns.query; content:"netshield-sensor-test.invalid"; nocase; sid:9900099; rev:1;)'
# Documented Suricata test signature (GPL ATTACK_RESPONSE id check returned
# root, sid 2100498): a server response containing the output of `id`
# (uid=0(root)) triggers it. It verifies detection over plain-HTTP browser
# traffic through the tunnel. Appended unconditionally, like TEST_RULE,
# because its message carries no category keyword, so the selector above
# would otherwise drop it.
# NOTE: this is NOT verbatim ET Open text. The ET rule matches the raw TCP
# stream (alert ip + content), which only sees the plaintext response.
# Browsers send Accept-Encoding: gzip, so the server returns a gzipped body
# and the plaintext pattern is hidden inside compressed bytes — the sensor
# never fires for browser traffic. Using http.response_body makes Suricata
# inspect the decompressed HTTP response body, so the same pattern matches
# both plain (curl) and gzipped (browser) responses.
ID_CHECK_RULE = 'alert http any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; http.response_body; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7; metadata:created_at 2010_09_23, confidence Medium, signature_severity Informational, updated_at 2019_07_26;)'


def build(source_config, source_rules, output_dir, rule_limit=3000):
    if not 1 <= rule_limit <= 10000:
        raise ValueError('invalid rule limit')
    config = yaml.safe_load(source_config.read_text())
    if not isinstance(config, dict) or not isinstance(config.get('outputs'), list):
        raise ValueError('invalid Suricata configuration')
    categories = {name: [] for name in CATEGORIES}
    seen = set()
    for rule in source_rules.read_text(errors='strict').splitlines():
        if not rule.startswith('alert ') or STATE_DEPENDENCY.search(rule):
            continue
        message, sid = SIGNATURE.search(rule), SID.search(rule)
        if not message or not sid:
            continue
        match = re.search(r'\b(' + '|'.join(CATEGORIES) + r')\b', message.group(1), re.I)
        if not match:
            continue
        value = int(sid.group(1))
        if value == 9900099 or value in seen:
            raise ValueError('duplicate or reserved rule SID')
        seen.add(value)
        categories[match.group(1).upper()].append((hashlib.sha256(str(value).encode()).digest(), rule))
    for rules in categories.values():
        rules.sort(key=lambda item: item[0])
    chosen = []
    while len(chosen) < rule_limit:
        added = False
        for category in CATEGORIES:
            if categories[category] and len(chosen) < rule_limit:
                chosen.append(categories[category].pop()[1])
                added = True
        if not added:
            break
    if not chosen:
        raise ValueError('no matching rules')
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    (output_dir / 'rules.rules').write_text('\n'.join(chosen + [TEST_RULE, ID_CHECK_RULE]) + '\n')
    config['outputs'] = [{'eve-log': {'enabled': True, 'filetype': 'regular',
                                      'filename': 'eve.json', 'types': [{'alert': {'payload': False, 'packet': False}}, {'stats': {'totals': True, 'threads': False, 'deltas': False}}]}}]
    config['stats'] = {'enabled': True, 'interval': 30}
    config['threading'] = {'set-cpu-affinity': False}
    (output_dir / 'suricata.yaml').write_text('%YAML 1.1\n---\n' + yaml.safe_dump(config, sort_keys=False))
    return len(chosen)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('config', type=Path)
    parser.add_argument('rules', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print('Reglas seleccionadas:', build(args.config, args.rules, args.output))
