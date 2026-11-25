#!/usr/bin/env python3
"""Build a bounded, balanced, alert-only Suricata configuration."""
import argparse
import hashlib
import re
from pathlib import Path
import yaml

CATEGORIES = ('MALWARE', 'TROJAN', 'EXPLOIT', 'CNC', 'PHISHING',
              'SCAN', 'DOS', 'CURRENT_EVENTS')
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
# Curated ATTACK_RESPONSE rules appended verbatim (like TEST_RULE and
# ID_CHECK_RULE). The whole ATTACK_RESPONSE category cannot be selected:
# it breaks `suricata -T` (silent rc=1) when combined with the other
# categories, and even a 100-rule subset fails. A 20-rule subset of the
# simplest rules (no `bsize`, no `pcre`) validates fine, so these 20 are
# pinned by SID. If ET Open drops one, it is skipped silently.
EXTRA_SIDS = (2009245, 2000499, 2000500, 2000501, 2000502, 2000503,
              2000504, 2000505, 2000506, 2000507, 2000508, 2002809,
              2002810, 2002811, 2009210, 2009211, 2009579, 2006417,
              2007725, 2007726)


def build(source_config, source_rules, output_dir, rule_limit=6000,
          categories=CATEGORIES, exclude_sids=(), exclude_words=(),
          append_fixed=True):
    if not 1 <= rule_limit <= 10000:
        raise ValueError('invalid rule limit')
    config = yaml.safe_load(source_config.read_text())
    if not isinstance(config, dict) or not isinstance(config.get('outputs'), list):
        raise ValueError('invalid Suricata configuration')
    categories = {name: [] for name in categories}
    seen = set()
    exclude_sids = set(exclude_sids)
    exclude_words = set(exclude_words)
    extra_by_sid = {}
    for rule in source_rules.read_text(errors='strict').splitlines():
        if not rule.startswith('alert ') or STATE_DEPENDENCY.search(rule):
            continue
        message, sid = SIGNATURE.search(rule), SID.search(rule)
        if not message or not sid:
            continue
        value = int(sid.group(1))
        if value in exclude_sids:
            continue
        if append_fixed and value in EXTRA_SIDS and value not in extra_by_sid:
            extra_by_sid[value] = rule
        match = re.search(r'\b(' + '|'.join(categories) + r')\b', message.group(1), re.I)
        if not match:
            continue
        # A rule whose message also carries another instance's category word
        # would be selected by both sensors and alert twice for one event.
        if exclude_words and re.search(r'\b(' + '|'.join(exclude_words) + r')\b', message.group(1), re.I):
            continue
        if value == 9900099 or value in seen:
            raise ValueError('duplicate or reserved rule SID')
        seen.add(value)
        categories[match.group(1).upper()].append((hashlib.sha256(str(value).encode()).digest(), rule))
    for rules in categories.values():
        rules.sort(key=lambda item: item[0])
    chosen = []
    while len(chosen) < rule_limit:
        added = False
        for category in categories:
            if categories[category] and len(chosen) < rule_limit:
                chosen.append(categories[category].pop()[1])
                added = True
        if not added:
            break
    if not chosen:
        raise ValueError('no matching rules')
    extras = [extra_by_sid[sid] for sid in EXTRA_SIDS
              if sid in extra_by_sid and sid not in seen] if append_fixed else []
    fixed = [TEST_RULE, ID_CHECK_RULE] if append_fixed else []
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    (output_dir / 'rules.rules').write_text('\n'.join(chosen + extras + fixed) + '\n')
    config['outputs'] = [{'eve-log': {'enabled': True, 'filetype': 'regular',
                                      'filename': 'eve.json', 'types': [{'alert': {'payload': False, 'packet': False}}, {'stats': {'totals': True, 'threads': False, 'deltas': False}}]}}]
    config['stats'] = {'enabled': True, 'interval': 30}
    config['threading'] = {'set-cpu-affinity': False}
    (output_dir / 'suricata.yaml').write_text('%YAML 1.1\n---\n' + yaml.safe_dump(config, sort_keys=False))
    return len(chosen) + len(extras)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('config', type=Path)
    parser.add_argument('rules', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--limit', type=int, default=6000)
    parser.add_argument('--categories', nargs='*', default=list(CATEGORIES))
    parser.add_argument('--exclude-sids', nargs='*', type=int, default=[])
    parser.add_argument('--exclude-words', nargs='*', default=[])
    parser.add_argument('--no-fixed-rules', action='store_true')
    args = parser.parse_args()
    print('Reglas seleccionadas:', build(args.config, args.rules, args.output,
          rule_limit=args.limit, categories=tuple(args.categories),
          exclude_sids=set(args.exclude_sids),
          exclude_words=set(args.exclude_words),
          append_fixed=not args.no_fixed_rules))
