"""Antigravity Patch Manager - GUI Backend Adapter.

Delegates all target discovery, gate verification, binary patching, and file
restoration to the verified core engine in ``manager.py``.
"""
from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import threading
import time

import manager

PATCHED = "PATCHED"
UNPATCHED = "UNPATCHED"
NOT_FOUND = "NOT FOUND"
UNSUPPORTED = "UNSUPPORTED"
ERROR = "ERROR"
UNKNOWN = "UNKNOWN"

COMPONENTS = ("ide", "extension", "manager", "cli")

COMPONENT_NAMES = {
    "ide": "Antigravity IDE",
    "extension": "Antigravity IDE Extension",
    "manager": "Antigravity Manager",
    "cli": "Antigravity CLI",
}

PROCESS_HINTS = {
    "ide": ("Antigravity.exe", "Antigravity IDE.exe"),
    "extension": ("agy.exe",),
    "manager": ("language_server.exe",),
    "cli": ("agy.exe",),
}


class OperationError(Exception):
    """User-facing operation failure with a safe, secret-free message."""
    pass


class TargetLocks:
    """Thread-safe lock registry preventing concurrent operations on a target."""
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._busy: set[str] = set()

    def acquire(self, target: str) -> bool:
        with self._lock:
            if target in self._busy:
                return False
            self._busy.add(target)
            return True

    def release(self, target: str) -> None:
        with self._lock:
            self._busy.discard(target)

    def is_busy(self, target: str) -> bool:
        with self._lock:
            return target in self._busy


@contextlib.contextmanager
def _capture_output():
    """Capture stdout and stderr emitted by manager.py functions."""
    buf_out = io.StringIO()
    buf_err = io.StringIO()
    old_out = sys.stdout
    old_err = sys.stderr
    try:
        sys.stdout = buf_out
        sys.stderr = buf_err
        yield buf_out, buf_err
    finally:
        sys.stdout = old_out
        sys.stderr = old_err


def running_processes(names: tuple[str, ...]) -> list[str]:
    """Check whether any of the given process names are currently running on Windows."""
    if os.name != "nt" or not names:
        return []
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        res = subprocess.run(
            ["tasklist.exe", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            timeout=3,
        )
        if res.returncode != 0:
            return []
        lower_output = res.stdout.lower()
        found = []
        for name in names:
            if f'"{name.lower()}"' in lower_output or name.lower() in lower_output:
                found.append(name)
        return found
    except Exception:
        return []


def component_processes(target: str) -> list[str]:
    """Return process names currently running that may lock this component."""
    hints = PROCESS_HINTS.get(target, ())
    return running_processes(hints)


def discover(target: str, override: str | None = None) -> str | None:
    """Resolve target path without modifying any files."""
    if override:
        return os.path.abspath(override) if os.path.exists(override) else None
    return manager.resolve(target, override)


def check(target: str, override: str | None = None) -> dict[str, any]:
    """Inspect actual verified component state on disk using manager.SPEC."""
    name = COMPONENT_NAMES.get(target, target)
    path = discover(target, override=override)

    if not path or not os.path.exists(path):
        return {
            "target": target,
            "name": name,
            "path": None,
            "status": NOT_FOUND,
            "details": "not installed or not detected",
            "backup_present": False,
            "can_patch": False,
            "can_restore": False,
        }

    spec = manager.SPEC.get(target)
    if not spec:
        return {
            "target": target,
            "name": name,
            "path": path,
            "status": ERROR,
            "details": f"no specification found for target '{target}'",
            "backup_present": False,
            "can_patch": False,
            "can_restore": False,
        }

    bak_path = path + manager.BAK
    backup_present = os.path.isfile(bak_path)

    try:
        raw_result = spec["status"](path)
        raw_status = raw_result[0] if isinstance(raw_result, tuple) else raw_result
    except manager.SignatureNotFound:
        return {
            "target": target,
            "name": name,
            "path": path,
            "status": UNSUPPORTED,
            "details": "unrecognized signature or unsupported version",
            "backup_present": backup_present,
            "can_patch": False,
            "can_restore": backup_present,
        }
    except manager.SignatureAmbiguous:
        return {
            "target": target,
            "name": name,
            "path": path,
            "status": ERROR,
            "details": "ambiguous signature match (multiple locations detected)",
            "backup_present": backup_present,
            "can_patch": False,
            "can_restore": backup_present,
        }
    except Exception as e:
        return {
            "target": target,
            "name": name,
            "path": path,
            "status": ERROR,
            "details": f"status inspection error: {e}",
            "backup_present": backup_present,
            "can_patch": False,
            "can_restore": backup_present,
        }

    if raw_status == "patched":
        status_label = PATCHED
        details = "backup present | patch signature present" if backup_present else "patch signature present"
        can_patch = False
        can_restore = backup_present
    elif raw_status == "unpatched":
        status_label = UNPATCHED
        details = "backup present | original signature" if backup_present else "original signature"
        can_patch = True
        can_restore = backup_present
    elif raw_status == "unknown":
        status_label = UNSUPPORTED
        details = "unrecognized signature or unsupported version"
        can_patch = False
        can_restore = backup_present
    else:
        status_label = UNKNOWN
        details = f"unknown status '{raw_status}'"
        can_patch = False
        can_restore = backup_present

    return {
        "target": target,
        "name": name,
        "path": path,
        "status": status_label,
        "details": details,
        "backup_present": backup_present,
        "can_patch": can_patch,
        "can_restore": can_restore,
    }


def check_all(overrides: dict[str, str | None] | None = None) -> list[dict[str, any]]:
    """Check all four components in standard order."""
    results = []
    for t in COMPONENTS:
        ov = overrides.get(t) if overrides else None
        results.append(check(t, override=ov))
    return results


def patch(target: str, override: str | None = None) -> tuple[bool, list[str], dict[str, any]]:
    """Execute target patching through manager.SPEC[target]['patch']."""
    spec = manager.SPEC.get(target)
    if not spec:
        raise OperationError(f"Target '{target}' is not recognized.")

    path = discover(target, override=override)
    if not path or not os.path.exists(path):
        raise OperationError(f"Target '{COMPONENT_NAMES.get(target, target)}' executable not found.")

    if manager.is_locked(path, app=spec.get("name")):
        raise OperationError(f"Cannot write to '{os.path.basename(path)}': file is locked by a running process.")

    logs: list[str] = []
    with _capture_output() as (out, err):
        try:
            success = bool(spec["patch"](path))
        except Exception as e:
            logs.append(f"ERROR: {e}")
            success = False

    for line in out.getvalue().splitlines():
        clean = line.strip()
        if clean:
            logs.append(clean)
    for line in err.getvalue().splitlines():
        clean = line.strip()
        if clean:
            logs.append(f"STDERR: {clean}")

    # Immediately rescan affected component
    updated_record = check(target, override=override)
    return success, logs, updated_record


def restore(target: str, override: str | None = None) -> tuple[bool, list[str], dict[str, any]]:
    """Execute target restoration through manager.restore_file."""
    path = discover(target, override=override)
    if not path or not os.path.exists(path):
        raise OperationError(f"Target '{COMPONENT_NAMES.get(target, target)}' executable not found.")

    bak_path = path + manager.BAK
    if not os.path.isfile(bak_path):
        raise OperationError(f"No backup file found at '{os.path.basename(bak_path)}'.")

    logs: list[str] = []
    with _capture_output() as (out, err):
        try:
            success = bool(manager.restore_file(path))
        except Exception as e:
            logs.append(f"ERROR: {e}")
            success = False

    for line in out.getvalue().splitlines():
        clean = line.strip()
        if clean:
            logs.append(clean)
    for line in err.getvalue().splitlines():
        clean = line.strip()
        if clean:
            logs.append(f"STDERR: {clean}")

    # Immediately rescan affected component
    updated_record = check(target, override=override)
    return success, logs, updated_record
