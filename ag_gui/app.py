"""Tkinter desktop front end for the Antigravity Patch Manager.

Clean, modern, native Windows 10/11 x64 visual layout adhering strictly to
the reference design and threading safety requirements.
"""
from __future__ import annotations

import datetime
import os
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from ag_gui import backend

# Color palette
COLOR_BG = "#f4f5f7"
COLOR_CARD = "#ffffff"
COLOR_BORDER = "#dfe3e8"
COLOR_TEXT = "#1f2328"
COLOR_MUTED = "#6b7280"
COLOR_ACCENT = "#2563eb"

# Status badge colors (text, bg)
BADGE_COLORS = {
    backend.PATCHED: ("#15803d", "#e7f6ec"),
    backend.UNPATCHED: ("#b45309", "#fdf3e3"),
    backend.NOT_FOUND: ("#6b7280", "#f1f2f4"),
    backend.UNSUPPORTED: ("#b91c1c", "#fdeaea"),
    backend.ERROR: ("#b91c1c", "#fdeaea"),
    backend.UNKNOWN: ("#4b5563", "#f1f2f4"),
}


def _now() -> str:
    """Return current timestamp string."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class ComponentRow:
    """Represents a single component status card in the GUI."""

    def __init__(
        self,
        parent: tk.Widget,
        target: str,
        name: str,
        on_check: callable,
        on_patch: callable,
        on_restore: callable,
    ) -> None:
        self.target = target
        self.name = name
        self.on_check = on_check
        self.on_patch = on_patch
        self.on_restore = on_restore
        self.record: dict[str, any] = {}

        # Outer frame
        self.frame = tk.Frame(parent, bg=COLOR_CARD, highlightbackground=COLOR_BORDER, highlightthickness=1)
        self.frame.pack(fill="x", padx=16, pady=4)

        # Inner padding frame
        inner = tk.Frame(self.frame, bg=COLOR_CARD, padx=14, pady=10)
        inner.pack(fill="x")

        # Left info column
        info_col = tk.Frame(inner, bg=COLOR_CARD)
        info_col.pack(side="left", fill="x", expand=True)

        self.title_lbl = tk.Label(
            info_col,
            text=name,
            font=("Segoe UI", 11, "bold"),
            fg=COLOR_TEXT,
            bg=COLOR_CARD,
            anchor="w",
        )
        self.title_lbl.pack(fill="x")

        self.path_lbl = tk.Label(
            info_col,
            text="Checking status...",
            font=("Segoe UI", 9),
            fg=COLOR_MUTED,
            bg=COLOR_CARD,
            anchor="w",
        )
        self.path_lbl.pack(fill="x", pady=(1, 1))

        self.details_lbl = tk.Label(
            info_col,
            text="",
            font=("Segoe UI", 8),
            fg=COLOR_MUTED,
            bg=COLOR_CARD,
            anchor="w",
        )
        self.details_lbl.pack(fill="x")

        # Right actions column
        self.actions_col = tk.Frame(inner, bg=COLOR_CARD)
        self.actions_col.pack(side="right", padx=(8, 0))

        # Check button
        self.btn_check = tk.Button(
            self.actions_col,
            text="Check",
            font=("Segoe UI", 9),
            bg="#f3f4f6",
            fg=COLOR_TEXT,
            relief="flat",
            padx=10,
            pady=3,
            cursor="hand2",
            command=lambda: self.on_check(self.target),
        )
        self.btn_check.pack(side="left", padx=4)

        # Context action button (Patch / Restore)
        self.btn_action = tk.Button(
            self.actions_col,
            text="Action",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=3,
            cursor="hand2",
        )
        self.btn_action.pack(side="left", padx=4)

        # Status badge label
        self.badge_lbl = tk.Label(
            self.actions_col,
            text="...",
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=4,
            relief="flat",
        )
        self.badge_lbl.pack(side="left", padx=(4, 0))

    def update_record(self, record: dict[str, any]) -> None:
        """Update widget values from a backend check record."""
        self.record = record
        path_str = record.get("path") or "Not detected"
        details_str = record.get("details") or ""
        status = record.get("status") or backend.UNKNOWN

        self.path_lbl.config(text=path_str)
        self.details_lbl.config(text=details_str)

        # Update badge
        text_color, bg_color = BADGE_COLORS.get(status, ("#1f2328", "#f1f2f4"))
        self.badge_lbl.config(text=status, fg=text_color, bg=bg_color)

        # Contextual Action button configuration
        if status == backend.PATCHED:
            self.btn_action.config(
                text="Restore",
                bg="#fef3c7",
                fg="#b45309",
                state="normal" if record.get("can_restore") else "disabled",
                command=lambda: self.on_restore(self.target),
            )
            self.btn_action.pack(side="left", padx=4)
        elif status == backend.UNPATCHED:
            self.btn_action.config(
                text="Patch",
                bg="#e0f2fe",
                fg="#0369a1",
                state="normal" if record.get("can_patch") else "disabled",
                command=lambda: self.on_patch(self.target),
            )
            self.btn_action.pack(side="left", padx=4)
        elif record.get("can_restore"):
            self.btn_action.config(
                text="Restore",
                bg="#fef3c7",
                fg="#b45309",
                state="normal",
                command=lambda: self.on_restore(self.target),
            )
            self.btn_action.pack(side="left", padx=4)
        else:
            self.btn_action.config(text="", state="disabled")
            self.btn_action.pack_forget()

    def set_busy(self, busy: bool, busy_text: str = "") -> None:
        """Set row widgets into busy or active state."""
        if busy:
            self.btn_check.config(state="disabled")
            self.btn_action.config(state="disabled")
            if busy_text:
                self.badge_lbl.config(text=busy_text, fg="#4b5563", bg="#e5e7eb")
        else:
            self.btn_check.config(state="normal")
            if self.record:
                self.update_record(self.record)


class PatchManagerApp:
    """Main Application Controller and Tkinter View."""

    def __init__(self, root: tk.Tk, backend_module=backend, overrides: dict | None = None) -> None:
        self.root = root
        self.backend = backend_module
        self.overrides = overrides or {}
        self.locks = backend.TargetLocks()
        self.events_queue: queue.Queue = queue.Queue()
        self.records: dict[str, dict[str, any]] = {}
        self.rows: dict[str, ComponentRow] = {}

        self.root.title("Antigravity Patch Manager")
        self.root.geometry("780x620")
        self.root.minsize(700, 520)
        self.root.configure(bg=COLOR_BG)

        self._build_header()
        self._build_component_cards()
        self._build_log_panel()

        # Start background polling of UI events
        self.root.after(50, self._drain_queue)

        # Initial asynchronous status scan
        self.root.after(100, self.refresh_all)

    def _build_header(self) -> None:
        """Build top application title and dynamic summary bar."""
        header_frame = tk.Frame(self.root, bg=COLOR_BG, padx=16, pady=12)
        header_frame.pack(fill="x")

        # Left title
        title_lbl = tk.Label(
            header_frame,
            text="Antigravity Patch Manager",
            font=("Segoe UI", 16, "bold"),
            fg=COLOR_TEXT,
            bg=COLOR_BG,
        )
        title_lbl.pack(side="left")

        # Right side: summary and refresh
        right_frame = tk.Frame(header_frame, bg=COLOR_BG)
        right_frame.pack(side="right")

        self.summary_lbl = tk.Label(
            right_frame,
            text="Checking components...",
            font=("Segoe UI", 10, "bold"),
            fg=COLOR_MUTED,
            bg=COLOR_BG,
        )
        self.summary_lbl.pack(side="left", padx=(0, 12))

        self.btn_refresh_all = tk.Button(
            right_frame,
            text="Refresh All",
            font=("Segoe UI", 9),
            bg="#ffffff",
            fg=COLOR_TEXT,
            relief="solid",
            bd=1,
            padx=10,
            pady=3,
            cursor="hand2",
            command=self.refresh_all,
        )
        self.btn_refresh_all.pack(side="left")

    def _build_component_cards(self) -> None:
        """Build exactly four component rows matching the requirements."""
        cards_container = tk.Frame(self.root, bg=COLOR_BG)
        cards_container.pack(fill="x", pady=(0, 8))

        for target in backend.COMPONENTS:
            name = backend.COMPONENT_NAMES.get(target, target)
            row = ComponentRow(
                cards_container,
                target=target,
                name=name,
                on_check=self.check_component,
                on_patch=self.patch_component,
                on_restore=self.restore_component,
            )
            self.rows[target] = row

    def _build_log_panel(self) -> None:
        """Build the bottom Activity Log panel with Copy and Clear."""
        log_frame = tk.Frame(self.root, bg=COLOR_BG, padx=16, pady=6)
        log_frame.pack(fill="both", expand=True)

        header = tk.Frame(log_frame, bg=COLOR_BG)
        header.pack(fill="x", pady=(0, 4))

        title = tk.Label(
            header,
            text="Activity log",
            font=("Segoe UI", 10, "bold"),
            fg=COLOR_TEXT,
            bg=COLOR_BG,
        )
        title.pack(side="left")

        btn_copy = tk.Button(
            header,
            text="Copy",
            font=("Segoe UI", 9),
            bg=COLOR_BG,
            fg=COLOR_ACCENT,
            bd=0,
            cursor="hand2",
            command=self.copy_log,
        )
        btn_copy.pack(side="right", padx=(4, 0))

        btn_clear = tk.Button(
            header,
            text="Clear",
            font=("Segoe UI", 9),
            bg=COLOR_BG,
            fg=COLOR_MUTED,
            bd=0,
            cursor="hand2",
            command=self.clear_log,
        )
        btn_clear.pack(side="right", padx=4)

        # Scrolled Text Box
        self.log_text = tk.Text(
            log_frame,
            font=("Consolas", 9),
            bg="#ffffff",
            fg=COLOR_TEXT,
            highlightbackground=COLOR_BORDER,
            highlightthickness=1,
            bd=0,
            padx=8,
            pady=6,
            wrap="word",
        )
        self.log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=self.log_scroll.set)

        self.log_scroll.pack(side="right", fill="y")
        self.log_text.pack(side="left", fill="both", expand=True)

    def log(self, message: str, level: str = "INFO") -> None:
        """Append a clean, secret-free message to the activity log."""
        timestamp = _now()
        line = f"{timestamp} [{level}] {message}\n"
        self.log_text.insert("end", line)
        self.log_text.see("end")

    def copy_log(self) -> None:
        """Copy current log contents to Windows clipboard."""
        content = self.log_text.get("1.0", "end-1c")
        if not content:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.log("Activity log copied to clipboard.", level="INFO")

    def clear_log(self) -> None:
        """Clear displayed activity log entries."""
        self.log_text.delete("1.0", "end")

    def _drain_queue(self) -> None:
        """Poll background worker results and safely update UI on main thread."""
        try:
            while True:
                fn, args, kwargs = self.events_queue.get_nowait()
                fn(*args, **kwargs)
        except queue.Empty:
            pass
        finally:
            self.root.after(50, self._drain_queue)

    def _run_async(self, work_fn: callable, on_done_fn: callable) -> None:
        """Run work in background daemon thread and marshal result back to main thread."""
        def worker():
            try:
                result = work_fn()
                self.events_queue.put((on_done_fn, (result,), {}))
            except Exception as e:
                self.events_queue.put((self._on_worker_error, (e,), {}))

        threading.Thread(target=worker, daemon=True).start()

    def _on_worker_error(self, error: Exception) -> None:
        """Handle unhandled worker exception safely."""
        self.log(f"Background operation error: {error}", level="ERROR")
        messagebox.showerror("Operation Error", f"An unexpected error occurred:\n{error}")
        self.refresh_all()

    def update_summary(self) -> None:
        """Update header component states counter."""
        counts: dict[str, int] = {}
        for rec in self.records.values():
            st = rec.get("status", backend.UNKNOWN)
            counts[st] = counts.get(st, 0) + 1

        parts = []
        if counts.get(backend.PATCHED):
            parts.append(f"{counts[backend.PATCHED]} Patched")
        if counts.get(backend.UNPATCHED):
            parts.append(f"{counts[backend.UNPATCHED]} Unpatched")
        if counts.get(backend.NOT_FOUND):
            parts.append(f"{counts[backend.NOT_FOUND]} Not Found")
        if counts.get(backend.ERROR):
            parts.append(f"{counts[backend.ERROR]} Error")
        if counts.get(backend.UNSUPPORTED):
            parts.append(f"{counts[backend.UNSUPPORTED]} Unsupported")

        summary_text = "  ".join(parts) if parts else "No components detected"
        self.summary_lbl.config(text=summary_text)

    def refresh_all(self) -> None:
        """Check all four components asynchronously."""
        self.btn_refresh_all.config(state="disabled")
        for row in self.rows.values():
            row.set_busy(True, busy_text="CHECKING")

        def work():
            return self.backend.check_all(overrides=self.overrides)

        def on_done(results: list[dict[str, any]]):
            self.btn_refresh_all.config(state="normal")
            for rec in results:
                t = rec["target"]
                self.records[t] = rec
                if t in self.rows:
                    self.rows[t].update_record(rec)
                self.log(f"{rec['name']}: {rec['status']} - {rec.get('path') or 'Not found'}")
            self.update_summary()

        self._run_async(work, on_done)

    def check_component(self, target: str) -> None:
        """Check a single component independently."""
        row = self.rows.get(target)
        if not row or not self.locks.acquire(target):
            return
        row.set_busy(True, busy_text="CHECKING")

        ov = self.overrides.get(target)

        def work():
            return self.backend.check(target, override=ov)

        def on_done(rec: dict[str, any]):
            self.locks.release(target)
            self.records[target] = rec
            row.update_record(rec)
            self.update_summary()
            self.log(f"{rec['name']}: {rec['status']} - {rec.get('path') or 'Not found'}")

        self._run_async(work, on_done)

    def patch_component(self, target: str) -> None:
        """Prompt confirmation and execute target patch."""
        name = backend.COMPONENT_NAMES.get(target, target)
        row = self.rows.get(target)
        if not row:
            return

        # Check for running processes before prompting
        procs = self.backend.component_processes(target)
        if procs:
            msg = (
                f"{name} appears to be currently running ({', '.join(procs)}).\n"
                "Modifying an active executable may fail or cause instability.\n\n"
                "Please close the application first. Continue anyway?"
            )
            if not messagebox.askyesno("Process Running Warning", msg, icon="warning"):
                return

        if not messagebox.askyesno("Confirm Patch", f"Apply eligibility patch to {name}?"):
            return

        if not self.locks.acquire(target):
            return
        row.set_busy(True, busy_text="PATCHING")
        ov = self.overrides.get(target)

        def work():
            return self.backend.patch(target, override=ov)

        def on_done(result: tuple[bool, list[str], dict[str, any]]):
            self.locks.release(target)
            success, logs, updated_rec = result
            self.records[target] = updated_rec
            row.update_record(updated_rec)
            self.update_summary()

            for line in logs:
                self.log(f"{name}: {line}")

            if success and updated_rec["status"] == backend.PATCHED:
                self.log(f"{name} successfully patched.", level="OK")
                messagebox.showinfo("Success", f"{name} was patched successfully.")
            else:
                self.log(f"Patch operation failed for {name}.", level="ERROR")
                messagebox.showerror("Patch Failed", f"Could not patch {name}.\nSee Activity Log for details.")

        self._run_async(work, on_done)

    def restore_component(self, target: str) -> None:
        """Prompt confirmation and execute target restore."""
        name = backend.COMPONENT_NAMES.get(target, target)
        row = self.rows.get(target)
        if not row:
            return

        # Check for running processes before prompting
        procs = self.backend.component_processes(target)
        if procs:
            msg = (
                f"{name} appears to be currently running ({', '.join(procs)}).\n"
                "Restoring an active executable may fail.\n\n"
                "Please close the application first. Continue anyway?"
            )
            if not messagebox.askyesno("Process Running Warning", msg, icon="warning"):
                return

        if not messagebox.askyesno("Confirm Restore", f"Restore {name} from original backup?"):
            return

        if not self.locks.acquire(target):
            return
        row.set_busy(True, busy_text="RESTORING")
        ov = self.overrides.get(target)

        def work():
            return self.backend.restore(target, override=ov)

        def on_done(result: tuple[bool, list[str], dict[str, any]]):
            self.locks.release(target)
            success, logs, updated_rec = result
            self.records[target] = updated_rec
            row.update_record(updated_rec)
            self.update_summary()

            for line in logs:
                self.log(f"{name}: {line}")

            if success and updated_rec["status"] in (backend.UNPATCHED, backend.PATCHED):
                self.log(f"{name} restored from backup.", level="OK")
                messagebox.showinfo("Success", f"{name} restored from backup successfully.")
            else:
                self.log(f"Restore operation failed for {name}.", level="ERROR")
                messagebox.showerror("Restore Failed", f"Could not restore {name}.\nSee Activity Log for details.")

        self._run_async(work, on_done)


def run(overrides: dict | None = None) -> int:
    """Launch the Antigravity Patch Manager desktop GUI."""
    root = tk.Tk()
    app = PatchManagerApp(root, overrides=overrides)
    root.mainloop()
    return 0
