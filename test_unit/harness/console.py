"""Bottom-pinned, apt-style progress bar + serialized log output.

One Console is shared by every parallel job. Log lines scroll ABOVE a status
bar that stays pinned to the last terminal row (the trick: after each log line
we clear + reprint the bar on the fresh bottom line — no scroll-region math,
resize-safe). The bar shows overall matrix progress (finished/total distros)
plus what each in-flight distro is doing right now, e.g.

  Progress [ 40%] ██████████░░░░░░░░░░░░  6/15   fedora-43·L2TP  arch·CORE

Falls back to plain sequential printing when stdout isn't a TTY (or NO_COLOR).
"""
from __future__ import annotations

import shutil
import signal
import sys
import threading
import time

from . import style

_FILL = "█"
_EMPTY = "░"

# Phase pipeline each job walks through, in order. Progress advances as a job
# moves along it (so the bar climbs during a run, not just at job completion).
_PIPE = ["VM", "CORE", "SETUP", "PREP", "OPENVPN", "L2TP", "PPTP"]


def _fmt_elapsed(secs: float) -> str:
    """Elapsed wall-clock as M:SS below an hour, H:MM:SS at/above it."""
    s = int(secs)
    h, rem = divmod(s, 3600)
    m, s = divmod(rem, 60)
    return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


class Console:
    def __init__(self, total_jobs: int):
        self.total = max(1, total_jobs)
        self.done = 0
        self.running: dict[str, str] = {}      # distro -> current phase label
        self._prog: dict[str, float] = {}      # distro -> completion 0..1 (persists)
        self._lock = threading.Lock()
        self._active = style.ENABLED            # TTY + color -> draw the bar
        self._bar_shown = False
        self._prev_winch = None
        self._start = time.monotonic()          # run start, for the elapsed timer
        self._stop_tick = threading.Event()
        # Redraw immediately on terminal resize (SIGWINCH) so the full-width bar
        # tracks the new width even while idle (e.g. long agent waits). Only the
        # main thread can install a handler, and only on platforms that have it.
        if self._active and hasattr(signal, "SIGWINCH"):
            try:
                self._prev_winch = signal.signal(signal.SIGWINCH, self._on_resize)
            except (ValueError, OSError):
                pass                            # not main thread / unsupported
        # Tick once a second so the elapsed timer advances even through long
        # phases with no log output (e.g. VM boot). Daemon thread, non-blocking
        # redraw — same safe pattern as the resize handler.
        if self._active:
            threading.Thread(target=self._tick_loop, daemon=True).start()

    # ---- public API (thread-safe) --------------------------------------
    def log(self, colored_line: str):
        with self._lock:
            if not self._active:
                print(colored_line, flush=True)
                return
            # clear the bar line, print the log, redraw the bar below it
            sys.stdout.write("\r\x1b[2K" + colored_line + "\n")
            self._draw_locked()

    def start_job(self, distro: str):
        with self._lock:
            # seed as VM (launch phase); the logger only calls set_phase on a
            # CHANGE, and a job's very first phase already is VM, so without this
            # the bar would show a placeholder until core-init.
            self.running.setdefault(distro, "VM")
            self._prog.setdefault(distro, 0.0)
            self._draw_locked()

    def set_phase(self, distro: str, phase: str):
        with self._lock:
            self.running[distro] = phase
            try:                                # advance completion along _PIPE
                frac = _PIPE.index(phase) / len(_PIPE)
                self._prog[distro] = max(self._prog.get(distro, 0.0), frac)
            except ValueError:
                pass
            self._draw_locked()

    def finish_job(self, distro: str):
        with self._lock:
            self.running.pop(distro, None)
            self._prog[distro] = 1.0
            self.done += 1
            self._draw_locked()

    def close(self):
        """Erase the bar so the final summary prints cleanly."""
        self._stop_tick.set()
        if self._prev_winch is not None:
            try:
                signal.signal(signal.SIGWINCH, self._prev_winch)
            except (ValueError, OSError):
                pass
            self._prev_winch = None
        with self._lock:
            if self._active and self._bar_shown:
                sys.stdout.write("\r\x1b[2K")
                sys.stdout.flush()
            self._bar_shown = False

    def _on_resize(self, signum, frame):
        """SIGWINCH: redraw the bar at the new width. Non-blocking lock — if a
        worker is mid-draw it will render the new size itself, so skipping is
        safe and can never deadlock the interrupted (main) thread."""
        if self._bar_shown and self._lock.acquire(blocking=False):
            try:
                self._draw_locked()
            finally:
                self._lock.release()

    def _tick_loop(self):
        """Once a second, redraw so the elapsed timer keeps counting during
        quiet phases. Non-blocking lock: if a worker holds it we skip this tick
        (it will redraw with the current time anyway), so we never contend."""
        while not self._stop_tick.wait(1.0):
            if self._bar_shown and self._lock.acquire(blocking=False):
                try:
                    self._draw_locked()
                finally:
                    self._lock.release()

    # ---- drawing (lock held) -------------------------------------------
    def _draw_locked(self):
        if not self._active:
            return
        sys.stdout.write("\r\x1b[2K" + self._bar_str())
        sys.stdout.flush()
        self._bar_shown = True

    def _bar_str(self) -> str:
        cols = shutil.get_terminal_size((100, 24)).columns
        # fill reflects phase-level progress across all jobs (climbs during the
        # run); the N/total text still counts fully-finished distros.
        pct = sum(self._prog.values()) / self.total
        head = f"Progress [{int(pct * 100):3d}%] "
        tail = f"  {self.done}/{self.total}"
        timer = _fmt_elapsed(time.monotonic() - self._start)
        gap = 3
        run = "   ".join(f"{d} -> {p}" for d, p in sorted(self.running.items()))

        # The bar spans the FULL terminal: it takes every column left after
        # head/tail, the elapsed timer (with its own gap on each side), and the
        # running list. The running list is capped to ~1/3 of the width so it can
        # never starve the bar, and the whole line is sized to exactly cols-1 so
        # it never wraps. Widths are measured on the plain strings; color is
        # applied only in the final return.
        avail = max(0, cols - len(head) - len(tail) - gap - len(timer) - gap - 1)
        if len(run) > cols // 3:
            run = run[:max(0, cols // 3 - 1)] + "…"
        bar_w = min(avail, max(8, avail - len(run)))
        run_room = avail - bar_w
        if len(run) > run_room:
            run = (run[:run_room - 1] + "…") if run_room > 1 else ""

        fill = round(pct * bar_w)
        bar = style.green(_FILL * fill) + style.dim(_EMPTY * (bar_w - fill))
        run_col = style.dim(run) if run else ""
        return (f"{style.bold(head)}{bar}{style.bold(tail)}"
                f"{' ' * gap}{style.cyan(timer)}{' ' * gap}{run_col}")
