"""Exercise failed rule activation without touching system services or the network."""
from pathlib import Path
import os
import subprocess


def test_failed_sensor_restart_restores_last_rules(tmp_path):
    source = Path(__file__).parents[1] / 'controller/update_vpn_sensor_rules.sh'
    etc = tmp_path / 'etc'
    etc.mkdir()
    live = etc / 'rules.rules'
    live.write_text('previous working rules\n')
    (etc / 'suricata.yaml').write_text('outputs: []\n')
    fake_bin = tmp_path / 'bin'
    fake_bin.mkdir()
    log = tmp_path / 'systemctl.log'
    commands = {
        'suricata-update': 'exit 0',
        'suricata': 'exit 0',
        'python3': 'mkdir -p "$4"; for i in $(seq 1 1001); do echo "alert new $i"; done > "$4/rules.rules"',
        'systemctl': f'echo "$*" >> "{log}"; [[ $(wc -l < "{log}") -gt 1 ]]',
    }
    for name, body in commands.items():
        path = fake_bin / name
        path.write_text('#!/usr/bin/env bash\n' + body + '\n')
        path.chmod(0o755)
    script = source.read_text().replace('/var/lib/netshield-vpn-sensor/rule-updates', str(tmp_path / 'updates'))
    script = script.replace('/etc/netshield-vpn-sensor', str(etc))
    script = script.replace('/usr/local/lib/netshield/build_suricata_sensor.py', str(tmp_path / 'builder.py'))
    run = subprocess.run(['bash'], input=script, text=True, capture_output=True,
                         env={**os.environ, 'PATH': f'{fake_bin}:/usr/bin:/bin'}, timeout=15)
    assert run.returncode != 0
    assert live.read_text() == 'previous working rules\n'
    assert log.read_text().splitlines() == ['restart netshield-vpn-sensor.service'] * 2
