#!/usr/bin/env python3
"""Bound local sensor metadata if logrotate is unavailable.

Only truncate a fully-consumed regular file; a racing append may be lost, so
this sensor is best-effort rather than a complete audit log.
"""
import os
from pathlib import Path


def truncate_consumed(path: Path, cursor: dict, max_size=10 * 1024 * 1024):
    with path.open('r+b') as log:
        stat = os.fstat(log.fileno())
        if stat.st_ino != cursor['inode'] or stat.st_size != cursor['offset'] or stat.st_size < max_size:
            return cursor
        log.truncate(0)
        return {'inode': stat.st_ino, 'offset': 0}
