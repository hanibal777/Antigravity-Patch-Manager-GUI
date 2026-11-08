"""Automated tests for Antigravity Patch Manager Tkinter GUI and Backend Adapter.

Strictly uses temporary synthetic files and mocks. Never touches real installed
applications or credentials.
"""
from __future__ import annotations

import os
import struct
import tempfile
import tkinter as tk
import unittest
from unittest import mock

import manager
from ag_gui import app, backend


def _make_mock_manager_pe(patch_state: str = "unpatched") -> bytes:
    """Create a minimal synthetic PE file with manager x64 signature."""
    image = bytearray(0x400)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", image, 0x84, 0x8664)  # x64
    struct.pack_into("<H", image, 0x86, 1)       # 1 section
    struct.pack_into("<H", image, 0x94, 0)
    section_table = 0x98
    image[section_table:section_table + 8] = b".text\0\0\0"
    struct.pack_into("<II", image, section_table + 16, 0x100, 0x200)
    struct.pack_into("<I", image, section_table + 36, 0x60000020)  # executable

    # Manager x64 gate signature
    # Pattern: \x80\x78\x08\x00\x74.\x48\x8b\x54\x24\x70\x48\x89\x50\x60
    if patch_state == "unpatched":
        gate_bytes = bytes.fromhex("80780800743b488b54247048895060")
    else:
        gate_bytes = bytes.fromhex("c64008019090488b54247048895060")

    image[0x200:0x200 + len(gate_bytes)] = gate_bytes
    return bytes(image)


class GuiBackendTests(unittest.TestCase):
    """Test backend adapter integration, path validation, and status derivation."""

    def test_missing_target_returns_not_found(self):
        rec = backend.check("cli", override=r"C:\nonexistent_path_12345\agy.exe")
        self.assertEqual(rec["status"], backend.NOT_FOUND)
        self.assertFalse(rec["can_patch"])
        self.assertFalse(rec["can_restore"])
        self.assertIn("not installed", rec["details"])

    def test_unsupported_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            dummy_bin = os.path.join(tmp, "language_server.exe")
            with open(dummy_bin, "wb") as f:
                f.write(b"NOT_A_PE_BINARY_JUST_GARBAGE")
            rec = backend.check("manager", override=dummy_bin)
            self.assertIn(rec["status"], (backend.UNSUPPORTED, backend.ERROR))
            self.assertFalse(rec["can_patch"])

    def test_synthetic_patch_and_restore_cycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            target_bin = os.path.join(tmp, "language_server.exe")
            with open(target_bin, "wb") as f:
                f.write(_make_mock_manager_pe("unpatched"))

            # 1. Check initial unpatched state
            rec1 = backend.check("manager", override=target_bin)
            self.assertEqual(rec1["status"], backend.UNPATCHED)
            self.assertTrue(rec1["can_patch"])
            self.assertFalse(rec1["can_restore"])

            # 2. Patch target
            success, logs, rec2 = backend.patch("manager", override=target_bin)
            self.assertTrue(success)
            self.assertEqual(rec2["status"], backend.PATCHED)
            self.assertFalse(rec2["can_patch"])
            self.assertTrue(rec2["can_restore"])
            self.assertTrue(rec2["backup_present"])

            # Verify backup exists
            bak_path = target_bin + manager.BAK
            self.assertTrue(os.path.isfile(bak_path))

            # 3. Restore target
            restore_ok, r_logs, rec3 = backend.restore("manager", override=target_bin)
            self.assertTrue(restore_ok)
            self.assertEqual(rec3["status"], backend.UNPATCHED)
            self.assertTrue(rec3["can_patch"])

    def test_target_locks_concurrency_prevention(self):
        locks = backend.TargetLocks()
        self.assertTrue(locks.acquire("ide"))
        self.assertTrue(locks.is_busy("ide"))
        self.assertFalse(locks.acquire("ide"))  # Cannot acquire twice
        locks.release("ide")
        self.assertFalse(locks.is_busy("ide"))
        self.assertTrue(locks.acquire("ide"))
        locks.release("ide")


class GuiAppTests(unittest.TestCase):
    """Test Tkinter UI components, layout, logging, and events queue."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.root = tk.Tk()
            cls.root.withdraw()  # Hide root window during testing
        except Exception:
            raise unittest.SkipTest("Tkinter display not available in environment")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.root.destroy()
        except Exception:
            pass

    def test_app_initialization_four_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            mock_overrides = {
                "ide": os.path.join(tmp, "main.js"),
                "extension": os.path.join(tmp, "agy.exe"),
                "manager": os.path.join(tmp, "language_server.exe"),
                "cli": os.path.join(tmp, "nonexistent.exe"),
            }
            # Create synthetic unpatched files
            with open(mock_overrides["manager"], "wb") as f:
                f.write(_make_mock_manager_pe("unpatched"))

            app_inst = app.PatchManagerApp(self.root, overrides=mock_overrides)

            # Verify exactly 4 component rows are present
            self.assertEqual(len(app_inst.rows), 4)
            for target in ("ide", "extension", "manager", "cli"):
                self.assertIn(target, app_inst.rows)

    def test_log_panel_copy_and_clear(self):
        app_inst = app.PatchManagerApp(self.root)
        app_inst.clear_log()
        self.assertEqual(app_inst.log_text.get("1.0", "end-1c"), "")

        app_inst.log("Test log entry 1", level="INFO")
        app_inst.log("Test log entry 2", level="OK")
        content = app_inst.log_text.get("1.0", "end-1c")
        self.assertIn("Test log entry 1", content)
        self.assertIn("Test log entry 2", content)

        # Test copy to clipboard
        app_inst.copy_log()
        clipboard_content = self.root.clipboard_get()
        self.assertIn("Test log entry 1", clipboard_content)

        # Test clear
        app_inst.clear_log()
        self.assertEqual(app_inst.log_text.get("1.0", "end-1c"), "")

    def test_summary_counter_formatting(self):
        app_inst = app.PatchManagerApp(self.root)
        app_inst.records = {
            "ide": {"status": backend.PATCHED},
            "extension": {"status": backend.PATCHED},
            "manager": {"status": backend.UNPATCHED},
            "cli": {"status": backend.NOT_FOUND},
        }
        app_inst.update_summary()
        summary = app_inst.summary_lbl.cget("text")
        self.assertIn("2 Patched", summary)
        self.assertIn("1 Unpatched", summary)
        self.assertIn("1 Not Found", summary)

    def test_no_credential_or_network_code_in_gui_package(self):
        import inspect
        backend_src = inspect.getsource(backend)
        app_src = inspect.getsource(app)
        combined = backend_src + app_src

        forbidden = [
            "advapi32", "CredRead", "CredWrite", "CredEnumerate", "sqlite3",
            "urllib", "requests", "socket", "oauthToken", "refreshToken"
        ]
        for term in forbidden:
            with self.subTest(forbidden_term=term):
                self.assertNotIn(term, combined, f"Forbidden term '{term}' found in GUI source!")


if __name__ == "__main__":
    unittest.main()
