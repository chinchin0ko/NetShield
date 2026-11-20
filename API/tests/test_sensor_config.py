from pathlib import Path
import importlib.util
import sys
import pytest

yaml = pytest.importorskip('yaml')
spec = importlib.util.spec_from_file_location('sensor_config', Path(__file__).parents[1] / 'controller/build_suricata_sensor.py')
sensor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sensor)


def test_build_limits_rules_and_disables_other_logs(tmp_path):
    config = tmp_path / 'input.yaml'
    config.write_text('outputs:\n  - eve-log:\n      enabled: true\n  - fast:\n      enabled: true\n')
    rules = tmp_path / 'input.rules'
    rules.write_text('alert dns any any -> any any (msg:"ET MALWARE example"; sid:1;)\n'
                     'alert dns any any -> any any (msg:"ET TROJAN example"; sid:2;)\n'
                     'alert dns any any -> any any (msg:"other"; sid:3;)\n')
    output = tmp_path / 'out'
    assert sensor.build(config, rules, output, rule_limit=1) == 1
    settings = yaml.safe_load((output / 'suricata.yaml').read_text())
    assert len(settings['outputs']) == 1
    assert settings['outputs'][0]['eve-log']['types'] == [{'alert': {'payload': False, 'packet': False}}]
    assert 'sid:1' in (output / 'rules.rules').read_text()
    assert 'sid:2' not in (output / 'rules.rules').read_text()
