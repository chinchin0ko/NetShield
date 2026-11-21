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


def test_selection_balances_categories_ignores_stateful_dependencies_and_is_stable(tmp_path):
    config = tmp_path / 'input.yaml'
    config.write_text('outputs: []\n')
    rules = tmp_path / 'input.rules'
    lines = [f'alert dns any any -> any any (msg:"ET MALWARE {n}"; sid:{n};)' for n in range(1, 10)]
    lines += ['alert dns any any -> any any (msg:"ET PHISHING example"; sid:20;)',
              'alert dns any any -> any any (msg:"ET EXPLOIT example"; sid:21;)',
              'alert dns any any -> any any (msg:"ET MALWARE depends"; flowbits:isset,missing; sid:22;)']
    rules.write_text('\n'.join(lines))
    first = tmp_path / 'one'
    assert sensor.build(config, rules, first, rule_limit=3) == 3
    result = (first / 'rules.rules').read_text()
    assert all(category in result for category in ('ET MALWARE', 'ET PHISHING', 'ET EXPLOIT'))
    assert 'sid:22;' not in result
    rules.write_text('\n'.join(reversed(lines)))
    second = tmp_path / 'two'
    sensor.build(config, rules, second, rule_limit=3)
    assert (second / 'rules.rules').read_text() == result


def test_rejects_duplicate_or_reserved_sids(tmp_path):
    config, rules = tmp_path / 'in.yaml', tmp_path / 'rules'
    config.write_text('outputs: []\n')
    rules.write_text('alert dns any any -> any any (msg:"ET MALWARE example"; sid:9900099;)\n')
    with pytest.raises(ValueError):
        sensor.build(config, rules, tmp_path / 'out')
