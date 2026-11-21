import importlib.util
import os
from pathlib import Path

spec = importlib.util.spec_from_file_location('sensor_logrotate', Path(__file__).parents[1] / 'controller/vpn_sensor_logrotate.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_rotation_keeps_appends_and_waits_for_writer(tmp_path, monkeypatch):
    path = tmp_path / 'eve.json'
    path.write_text('first\n')
    writer = path.open('a')
    monkeypatch.setattr(mod.os, 'kill', lambda pid, sig: None)
    archive = mod.rotate(path, os.getpid(), max_size=1)
    assert archive and not path.exists()
    writer.write('concurrent\n')
    writer.flush()
    cursor = {'inode': archive.stat().st_ino, 'offset': archive.stat().st_size}
    assert not mod.may_remove(archive, cursor, os.getpid(), path)
    assert archive.read_text() == 'first\nconcurrent\n'
    writer.close()
    path.write_text('')  # Suricata closes the old EVE before reopening this path.
    assert mod.may_remove(archive, cursor, os.getpid(), path)


def test_incomplete_or_unacknowledged_file_is_never_removed(tmp_path):
    path = tmp_path / 'eve.pending.00000000000000000001.999999999'
    path.write_text('data\n')
    inode = path.stat().st_ino
    assert not mod.may_remove(path, {'inode': inode, 'offset': 3}, None, tmp_path / 'eve.json')
    assert not mod.may_remove(path, {'inode': inode + 1, 'offset': 5}, None, tmp_path / 'eve.json')
    assert mod.pending_files(tmp_path) == [path]



def test_missing_reopen_or_sensor_blocks_removal(tmp_path):
    path = tmp_path / 'eve.pending.00000000000000000002.999999999'
    path.write_text('data\n')
    active = tmp_path / 'eve.json'
    cursor = {'inode': path.stat().st_ino, 'offset': path.stat().st_size}
    assert not mod.may_remove(path, cursor, os.getpid(), active)
    active.write_text('')
    assert not mod.may_remove(path, cursor, None, active)
    assert mod.may_remove(path, cursor, os.getpid(), active)
