#!/usr/bin/env python3
"""Rename sensor logs and retain each inode until delivery and writer closure."""
import os
import re
import signal
import time
from pathlib import Path

PENDING = re.compile(r'^eve\.pending\.(\d+)\.(\d+)$')


def pending_files(directory: Path):
    return sorted((p for p in directory.iterdir() if PENDING.fullmatch(p.name)), key=lambda p: p.name)


def rotate(path: Path, writer_pid: int, max_size=10 * 1024 * 1024):
    if writer_pid <= 0:
        raise ValueError('invalid writer pid')
    if path.stat().st_size < max_size:
        return None
    target = path.with_name(f'eve.pending.{time.time_ns():020d}.{writer_pid}')
    if target.exists():
        raise FileExistsError(target)
    os.rename(path, target)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    # Suricata reopens EVE on SIGHUP; the old file remains until the writer has
    # closed it and the collector has acknowledged every complete record.
    try:
        os.kill(writer_pid, signal.SIGHUP)
    except ProcessLookupError:
        pass  # A restarted sensor will open a new EVE path.
    return target


def may_remove(path: Path, cursor: dict, current_pid: int | None, active_path: Path):
    if not PENDING.fullmatch(path.name):
        raise ValueError('not a pending sensor file')
    if current_pid is None:
        return False
    stat = path.stat()
    if stat.st_ino != cursor['inode'] or stat.st_size != cursor['offset']:
        return False
    # Suricata's SIGHUP handler closes the old EVE before opening the new path.
    # The directory is private to the sensor/collector. A replacement process
    # also creates this path after the previous systemd service has stopped.
    try:
        active = active_path.stat()
    except FileNotFoundError:
        return False
    return (active.st_dev, active.st_ino) != (stat.st_dev, stat.st_ino)
