"""Shared renderer for live multi-node command status."""

import shutil
import sys


def _one_line(text: str) -> str:
    """Flatten a status string onto one line. A failure line can carry a
    subprocess's multi-line stderr, and the in-place TTY repaint moves the
    cursor up one row per node — so a newline in a status would tear the
    dashboard apart. Only line breaks are folded: the progress bar's column
    padding is significant."""
    return " ".join(text.splitlines())


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
                line = _one_line(states.get(name, "…"))
                text = f"{self.labels[name].rjust(self._width)}  {line}"
                if len(text) >= cols:
                    text = text[: cols - 1] + "…"
                sys.stdout.write(f"\033[2K{text}\n")
            sys.stdout.flush()
            self._painted = True
            return

        for name in self.order:
            line = _one_line(states.get(name, "…"))
            if self._last.get(name) != line:
                print(f"{self.labels[name]}: {line}", flush=True)
                self._last[name] = line
