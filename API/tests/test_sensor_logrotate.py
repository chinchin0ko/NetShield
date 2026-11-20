import importlib.util
from pathlib import Path
spec = importlib.util.spec_from_file_location('sensor_logrotate', Path(__file__).parents[1] / 'controller/vpn_sensor_logrotate.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_only_consumed_file_is_truncated(tmp_path):
    file = tmp_path / 'eve.json'
    file.write_text('123456')
    inode = file.stat().st_ino
    assert mod.truncate_consumed(file, {'inode': inode, 'offset': 3}, max_size=5)['offset'] == 3
    assert file.read_text() == '123456'
    result = mod.truncate_consumed(file, {'inode': inode, 'offset': 6}, max_size=5)
    assert result == {'inode': inode, 'offset': 0}
    assert file.read_text() == ''
