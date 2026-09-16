"""Minimal cross-platform GUI.

Two buttons only -- Import and Clean -- plus a drop target that also accepts
drag-and-drop when ``tkinterdnd2`` is installed. Built on tkinter (stdlib), so
it runs on macOS, Windows and Linux with no platform-specific code path; the
CLI (`cleaner inspect`/`scrub`/`text`) remains available independently of this
module, which is only imported when the GUI is actually launched.
"""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Iterable

from .files.base import Policy
from .pipeline import run

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False

_Base = TkinterDnD.Tk if HAS_DND else tk.Tk


def new_files(existing: list[Path], candidates: Iterable[Path]) -> list[Path]:
    """Candidates to add to the queue: existing files, not already queued.

    Kept separate from the widget code so the dedup/filter rule -- the only
    part of this module with a decision in it -- is testable without a
    display.
    """
    seen = set(existing)
    added = []
    for path in candidates:
        if path.is_file() and path not in seen:
            seen.add(path)
            added.append(path)
    return added


class App(_Base):
    def __init__(self) -> None:
        super().__init__()
        self.title("cleaner")
        self.geometry("440x360")
        self.minsize(360, 280)

        self.queued: list[Path] = []

        self.listbox = tk.Listbox(self, activestyle="none")
        self.listbox.pack(fill="both", expand=True, padx=12, pady=(12, 8))

        hint = "drag files here, or use Import" if HAS_DND else "use Import to add files"
        tk.Label(self, text=hint, fg="gray50").pack()

        buttons = tk.Frame(self)
        buttons.pack(fill="x", padx=12, pady=12)
        tk.Button(buttons, text="Import", command=self._import).pack(
            side="left", expand=True, fill="x", padx=(0, 6))
        tk.Button(buttons, text="Clean", command=self._clean).pack(
            side="left", expand=True, fill="x", padx=(6, 0))

        if HAS_DND:
            self.listbox.drop_target_register(DND_FILES)
            self.listbox.dnd_bind("<<Drop>>", self._on_drop)

    def _import(self) -> None:
        chosen = filedialog.askopenfilenames(title="Import files")
        self._queue(Path(p) for p in chosen)

    def _on_drop(self, event) -> None:
        self._queue(Path(p) for p in self.tk.splitlist(event.data))

    def _queue(self, candidates: Iterable[Path]) -> None:
        for path in new_files(self.queued, candidates):
            self.queued.append(path)
            self.listbox.insert("end", str(path))

    def _clean(self) -> None:
        if not self.queued:
            messagebox.showinfo("cleaner", "Import files first.")
            return
        out_dir = filedialog.askdirectory(title="Export cleaned files to")
        if not out_dir:
            return
        report = run(self.queued, Policy(), dry_run=False, output_dir=Path(out_dir))
        messagebox.showinfo("cleaner", report.to_text(verbose=False))
        self.queued.clear()
        self.listbox.delete(0, "end")


def main() -> int:
    App().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
