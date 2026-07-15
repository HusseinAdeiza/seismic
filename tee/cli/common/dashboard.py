"""Shared renderer for live multi-node command status."""

import shutil
import sys


class CohortDashboard:
    """Render named status lines in place on a TTY and on change elsewhere."""

    def __init__(self, labels: dict[str, str]) -> None:
        if not labels:
            raise ValueError("dashboard requires at least one status label")
        self.isatty = sys.stdout.isatty()
        self.order = list(labels)
        self.labels = labels
        self._width = max(len(label) for label in labels.values())
        self._painted = False
        self._last: dict[str, str] = {}

    def render(self, states: dict[str, str]) -> None:
        if self.isatty:
            cols = shutil.get_terminal_size((100, 24)).columns
            if self._painted:
                sys.stdout.write(f"\033[{len(self.order)}A")
            for name in self.order:
                text = (
                    f"{self.labels[name].rjust(self._width)}  {states.get(name, '…')}"
                )
                if len(text) >= cols:
                    text = text[: cols - 1] + "…"
                sys.stdout.write(f"\033[2K{text}\n")
            sys.stdout.flush()
            self._painted = True
            return

        for name in self.order:
            line = states.get(name, "…")
            if self._last.get(name) != line:
                print(f"{self.labels[name]}: {line}", flush=True)
                self._last[name] = line
