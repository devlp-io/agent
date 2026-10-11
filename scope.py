"""
scope — DISABLED. Per Kanha's request, scope enforcement is off.
Every URL is allowed. The harness no longer blocks utility hosts
(crt.sh, NVD, github, firebaseapp) or out-of-scope recon.

If you ever want it back, restore from scope.py.pre-noscope.bak.
"""
import os


def set_target(target):
    return None


def in_scope(url, run_dir=None):
    return True, "scope disabled"


def enforce(url, run_dir=None):
    return True


def _load_patterns(run_dir=None):
    return []


def _match(host, pattern):
    return True
