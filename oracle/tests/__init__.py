"""Test package initialization for Oracle DB-IDS unit, evasion, concurrency, and security tests."""

from __future__ import annotations

import os
import sys

try:
    from oracle import detector as _detector  # noqa: F401
except ImportError:
    _ORACLE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _ORACLE_DIR not in sys.path:
        sys.path.insert(0, _ORACLE_DIR)
