"""docker_tui.py — Interactive TUI for docker_forensics.py"""

from __future__ import annotations

import curses
import io
import json
import shutil
import sys
import threading
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Optional, Callable

import docker_forensics as df


# ── Constants ─────────────────────────────────────────────────────────────────

CP_SELECTED   = 1   # black on cyan (selected row)
CP_IMAGE      = 2   # default (image layer)
CP_INIT       = 3   # yellow (init layer)
CP_UPPER      = 4   # green  (writable upper)
CP_STATUS_BAR = 5   # black on white
CP_HEADER     = 6   # white on blue
CP_MISSING    = 7   # red (layer not on disk)

BOX_DEFAULT_W = 56  # default inner box width for layer stack


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class LayerRecord:
    index: int               # 1-based for image layers; 0 for init/upper
    role: str                # "image" | "init" | "upper"
    cache_id: Optional[str]  # overlay2 directory name; None = not on disk
    diff_id: str             # sha256:... (empty for init/upper)
    size: int                # bytes
    on_disk: bool

    def label(self, width: int) -> str:
        """Return a string of exactly *width* chars for display inside the box."""
        if self.role == "upper":
            left = "UPPER  writable"
        elif self.role == "init":
            left = "INIT   docker-init"
        else:
            cid = df.short(self.cache_id or "?", 12)
            left = f"[{self.index:>2}] {cid}"

        size_str = "MISSING" if not self.on_disk else df.fmt_size(self.size)
        needed = len(left) + 1 + len(size_str)
        if needed >= width:
            # Truncate tag to fit size on the right
            left = left[:max(0, width - len(size_str) - 1)]
        spaces = max(1, width - len(left) - len(size_str))
        return (left + " " * spaces + size_str)[:width]


# ── AppState ──────────────────────────────────────────────────────────────────

class AppState(Enum):
    OVERVIEW      = auto()
    LAYER_STACK   = auto()
    LAYER_DETAIL  = auto()
    ACTION_DIALOG = auto()
    DIFF_VIEW     = auto()
    LOG_VIEW      = auto()
    QUIT          = auto()


# ── Module-level helpers ─────────────────────────────────────────────────────

def _prompt_line(stdscr, prompt: str) -> Optional[str]:
    """Inline single-line input. Returns text on Enter, None on Esc."""
    H, W = stdscr.getmaxyx()
    curses.curs_set(1)
    buf = ""
    y = H - 2
    while True:
        line = (prompt + buf).ljust(W)[:W]
        try:
            stdscr.addstr(y, 0, line, curses.color_pair(CP_STATUS_BAR))
        except curses.error:
            pass
        try:
            stdscr.move(y, min(len(prompt) + len(buf), W - 1))
        except curses.error:
            pass
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (curses.KEY_ENTER, 10, 13):
            break
        elif ch == 27:
            curses.curs_set(0)
            return None
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            buf = buf[:-1]
        elif 32 <= ch <= 126:
            buf += chr(ch)
    curses.curs_set(0)
    return buf


# ── Drawing helpers ───────────────────────────────────────────────────────────

def _safe(win, y: int, x: int, s: str, attr: int = 0) -> None:
    try:
        win.addstr(y, x, s, attr)
    except curses.error:
        pass


def _hline(win, y: int, x: int, inner_w: int, left: str, mid: str, right: str) -> None:
    _safe(win, y, x, left + mid * inner_w + right)


def _compute_row_heights(layers: list[LayerRecord], available: int) -> list[int]:
    """Return proportional row heights summing to *available*, min 1 per layer."""
    n = len(layers)
    if n == 0:
        return []
    if available <= n:
        return [1] * n

    total_size = sum(l.size for l in layers)
    if total_size == 0:
        base, rem = divmod(available, n)
        return [base + (1 if i < rem else 0) for i in range(n)]

    heights = [max(1, round(l.size / total_size * available)) for l in layers]

    # Fix rounding drift
    while sum(heights) > available:
        idx = max(range(n), key=lambda i: heights[i])
        heights[idx] -= 1
    while sum(heights) < available:
        idx = max(range(n), key=lambda i: layers[i].size / max(1, heights[i]))
        heights[idx] += 1

    return heights


# ── OverviewScreen ────────────────────────────────────────────────────────────

class OverviewScreen:
    PANE_IMG = 0
    PANE_CTR = 1

    def __init__(self, app: TuiApp):
        self.app = app
        self._images: list[dict] = []
        self._containers: list[dict] = []
        self._pane = self.PANE_IMG
        self._img_cur = 0
        self._ctr_cur = 0
        self._img_off = 0
        self._ctr_off = 0

    def on_enter(self):
        self._images     = self.app.docker.images()
        self._containers = self.app.docker.containers_list()
        self._img_cur = min(self._img_cur, max(0, len(self._images) - 1))
        self._ctr_cur = min(self._ctr_cur, max(0, len(self._containers) - 1))

    def draw(self):
        win = self.app.stdscr
        H, W = win.getmaxyx()

        header = (f" docker-examiner  {self.app.docker.root}  ")
        hint   = " Tab: switch pane "
        pad    = max(0, W - len(header) - len(hint))
        _safe(win, 0, 0, (header + " " * pad + hint)[:W], curses.color_pair(CP_HEADER))

        content_h = H - 2
        img_h = content_h // 2
        ctr_h = content_h - img_h
        self._draw_pane(win, 1,        img_h, self.PANE_IMG)
        self._draw_pane(win, 1 + img_h, ctr_h, self.PANE_CTR)

        keys = " ↑↓ navigate   Enter: view layers   Tab: switch pane   r: report   q: quit "
        _safe(win, H - 1, 0, keys.ljust(W)[:W], curses.color_pair(CP_STATUS_BAR))

    def _draw_pane(self, win, y0: int, height: int, pane: int):
        H, W = win.getmaxyx()
        active = (pane == self._pane)

        if pane == self.PANE_IMG:
            items, cur, off = self._images, self._img_cur, self._img_off
            title = f"── Images ({len(items)}) "
            col   = f"  {'ID':<14} {'CREATED':<20} {'OS/ARCH':<15} {'LYR':>4}  TAGS"
        else:
            items, cur, off = self._containers, self._ctr_cur, self._ctr_off
            title = f"── Containers ({len(items)}) "
            col   = f"  {'ID':<14} {'NAME':<22} {'IMAGE':<20} STATE"

        sep = title + "─" * max(0, W - len(title) - 1)
        _safe(win, y0, 0, sep[:W], curses.A_BOLD if active else curses.A_DIM)
        _safe(win, y0 + 1, 0, col[:W], curses.A_DIM)

        rows = height - 2
        for i, item in enumerate(items[off:off + rows]):
            real = off + i
            y = y0 + 2 + i
            if y >= H - 1:
                break

            line = self._fmt_image(item, W - 2) if pane == self.PANE_IMG \
                   else self._fmt_container(item, W - 2)
            marker = "▶" if (real == cur and active) else " "
            attr = curses.color_pair(CP_SELECTED) if (real == cur and active) else 0
            _safe(win, y, 0, (marker + line)[:W], attr)

        if not items:
            _safe(win, y0 + 2, 2, "(none)")

    def _fmt_image(self, img: dict, w: int) -> str:
        sid     = df.short(img["id"], 14)
        cfg     = img["config"]
        created = df.fmt_ts(cfg.get("created", ""))[:19]
        arch    = f"{cfg.get('os','?')}/{cfg.get('architecture','?')}"
        nlayers = len(cfg.get("rootfs", {}).get("diff_ids", []))
        tags    = ", ".join(img.get("tags", [])[:2]) or "(untagged)"
        return f" {sid:<14} {created:<20} {arch:<15} {nlayers:>4}  {tags}"[:w]

    def _fmt_container(self, c: dict, w: int) -> str:
        sid   = df.short(c["id"], 14)
        cfg   = c["config"]
        name  = cfg.get("Name", "").lstrip("/")[:20]
        image = (c.get("image_name") or "")[:18]
        st    = cfg.get("State", {})
        state = "running" if st.get("Running") \
                else ("exited" if st.get("ExitCode", -1) >= 0 else "unknown")
        return f" {sid:<14} {name:<22} {image:<20} {state}"[:w]

    def handle_key(self, ch: int) -> Optional[AppState]:
        if ch == curses.KEY_RESIZE:
            curses.update_lines_cols()
            return None
        if ch in (ord('q'), 27):
            return AppState.QUIT
        if ch == ord('\t'):
            self._pane = self.PANE_CTR if self._pane == self.PANE_IMG else self.PANE_IMG
            return None
        if ch == ord('r'):
            self._run_report()
            return None

        H, W = self.app.stdscr.getmaxyx()
        visible = (H - 2) // 2 - 2

        if self._pane == self.PANE_IMG:
            items, cur, off = self._images, self._img_cur, self._img_off
        else:
            items, cur, off = self._containers, self._ctr_cur, self._ctr_off

        if ch == curses.KEY_UP:
            cur = max(0, cur - 1)
        elif ch == curses.KEY_DOWN:
            cur = min(max(0, len(items) - 1), cur + 1)
        elif ch == curses.KEY_PPAGE:
            cur = max(0, cur - visible)
        elif ch == curses.KEY_NPAGE:
            cur = min(max(0, len(items) - 1), cur + visible)
        elif ch in (curses.KEY_ENTER, 10, 13):
            if not items:
                return None
            if self._pane == self.PANE_IMG:
                self.app.selected_image     = self._images[cur]
                self.app.selected_container = None
            else:
                self.app.selected_container = self._containers[cur]
                self.app.selected_image     = None
            return AppState.LAYER_STACK

        off = max(0, min(off, cur))
        if cur >= off + visible:
            off = cur - visible + 1

        if self._pane == self.PANE_IMG:
            self._img_cur, self._img_off = cur, off
        else:
            self._ctr_cur, self._ctr_off = cur, off
        return None

    def _run_report(self):
        import threading
        from pathlib import Path
        win = self.app.stdscr
        H, W = win.getmaxyx()

        out_str = _prompt_line(win, " Report output path: ")
        if out_str is None or not out_str.strip():
            return
        out_path = Path(out_str.strip())

        progress: dict = {"msg": "Starting…", "done": False, "error": None}

        def cb(msg: str):
            progress["msg"] = msg

        def worker():
            try:
                report = df.ReportBuilder(self.app.docker, progress_cb=cb).build()
                out_path.write_text(report, encoding="utf-8")
                progress["done"] = True
            except Exception as exc:
                progress["error"] = str(exc)
                progress["done"] = True

        threading.Thread(target=worker, daemon=True).start()
        win.timeout(200)
        while not progress["done"]:
            win.erase()
            self.draw()
            msg = f" {progress['msg']} "
            _safe(win, H // 2, max(0, (W - len(msg)) // 2), msg, curses.color_pair(CP_HEADER))
            win.refresh()
            win.getch()
        win.timeout(-1)

        if progress["error"]:
            self.app.status_msg = f"Report error: {progress['error'][:50]}"
        else:
            self.app.status_msg = f"Report written → {out_path}"


# ── LayerStackScreen ──────────────────────────────────────────────────────────

class LayerStackScreen:
    def __init__(self, app: TuiApp):
        self.app = app
        self._scroll = 0

    def on_enter(self):
        if self.app.selected_image:
            self.app.layers = self.app.build_layers_for_image(self.app.selected_image)
        elif self.app.selected_container:
            self.app.layers = self.app.build_layers_for_container(self.app.selected_container)
        else:
            self.app.layers = []
        self.app.selected_layer_idx = max(0, len(self.app.layers) - 1)
        self._scroll = 0

    def draw(self):
        win = self.app.stdscr
        H, W = win.getmaxyx()

        name = self._target_name()
        _safe(win, 0, 0, f" Layer Stack: {name} ".ljust(W)[:W], curses.color_pair(CP_HEADER))

        layers = self.app.layers
        if not layers:
            _safe(win, H // 2, 2, "No layers found.")
            self._status(H, W)
            return

        # Display order: top-to-bottom = upper → init → top image → … → base
        disp = list(reversed(layers))
        n = len(disp)
        sel_orig = self.app.selected_layer_idx  # index in `layers` (bottom-to-top)
        sel_disp = n - 1 - sel_orig             # index in `disp` (top-to-bottom)
        sel_disp = max(0, min(n - 1, sel_disp))

        box_inner = min(W - 6, BOX_DEFAULT_W)
        box_x = (W - box_inner - 2) // 2

        # Available rows for content (not counting separators)
        visible_h = H - 2  # header + status
        avail_content = max(n, visible_h - 2 - max(0, n - 1))
        heights = _compute_row_heights(disp, avail_content)

        # Build virtual rows
        vrows: list[tuple] = []
        starts: list[int] = []
        vrows.append((None, 'top', None))
        for i, (layer, h) in enumerate(zip(disp, heights)):
            starts.append(len(vrows))
            for r in range(h):
                vrows.append((i, 'content', r))
            if i < n - 1:
                vrows.append((None, 'sep', None))
        vrows.append((None, 'bottom', None))

        # Auto-scroll: keep label row of selected layer visible
        if sel_disp < len(starts):
            sel_row = starts[sel_disp]
            if sel_row < self._scroll:
                self._scroll = max(0, sel_row - 1)
            elif sel_row >= self._scroll + visible_h:
                self._scroll = sel_row - visible_h + 1
        self._scroll = max(0, min(self._scroll, max(0, len(vrows) - visible_h)))

        for sy, row in enumerate(vrows[self._scroll:self._scroll + visible_h]):
            y = 1 + sy
            layer_disp_idx, rtype, rdata = row

            if rtype == 'top':
                _hline(win, y, box_x, box_inner, '╔', '═', '╗')
            elif rtype == 'bottom':
                _hline(win, y, box_x, box_inner, '╚', '═', '╝')
            elif rtype == 'sep':
                _hline(win, y, box_x, box_inner, '╠', '═', '╣')
            elif rtype == 'content':
                layer = disp[layer_disp_idx]
                is_sel = (layer_disp_idx == sel_disp)
                if is_sel:
                    attr = curses.color_pair(CP_SELECTED)
                elif not layer.on_disk:
                    attr = curses.color_pair(CP_MISSING)
                elif layer.role == "upper":
                    attr = curses.color_pair(CP_UPPER) | curses.A_BOLD
                elif layer.role == "init":
                    attr = curses.color_pair(CP_INIT)
                else:
                    attr = curses.color_pair(CP_IMAGE)

                marker = "▶" if is_sel else " "
                if rdata == 0:
                    content = marker + layer.label(box_inner - 1)
                else:
                    content = " " * box_inner
                _safe(win, y, box_x, f"║{content}║", attr)

        # Scroll indicators
        if self._scroll > 0:
            more = len([r for r in vrows[:self._scroll] if r[1] == 'content' and r[2] == 0])
            _safe(win, 1, box_x + 2, f" ↑ {more} layer(s) above ", curses.A_DIM)
        total_rows = len(vrows)
        below_start = self._scroll + visible_h
        if below_start < total_rows:
            more = len([r for r in vrows[below_start:] if r[1] == 'content' and r[2] == 0])
            if more:
                _safe(win, H - 2, box_x + 2, f" ↓ {more} layer(s) below ", curses.A_DIM)

        self._status(H, W)

    def _target_name(self) -> str:
        if self.app.selected_image:
            img = self.app.selected_image
            return (img.get("tags") or [None])[0] or df.short(img["id"])
        if self.app.selected_container:
            c = self.app.selected_container
            return c["config"].get("Name", "").lstrip("/") or df.short(c["id"])
        return "?"

    def _status(self, H: int, W: int):
        extra = "   d: diff   l: log" if self.app.selected_container else ""
        keys = f" ↑↓ select   Enter: detail   a: action{extra}   b: back   q: quit "
        _safe(self.app.stdscr, H - 1, 0, keys.ljust(W)[:W], curses.color_pair(CP_STATUS_BAR))

    def handle_key(self, ch: int) -> Optional[AppState]:
        if ch == curses.KEY_RESIZE:
            curses.update_lines_cols()
            return None
        if ch in (ord('q'), 27):
            return AppState.QUIT
        if ch == ord('b'):
            return AppState.OVERVIEW

        n = len(self.app.layers)
        if n == 0:
            return None

        sel = self.app.selected_layer_idx
        if ch == curses.KEY_UP:
            self.app.selected_layer_idx = min(n - 1, sel + 1)
        elif ch == curses.KEY_DOWN:
            self.app.selected_layer_idx = max(0, sel - 1)
        elif ch in (curses.KEY_ENTER, 10, 13):
            return AppState.LAYER_DETAIL
        elif ch == ord('a'):
            return AppState.ACTION_DIALOG
        elif ch == ord('d') and self.app.selected_container:
            return AppState.DIFF_VIEW
        elif ch == ord('l') and self.app.selected_container:
            return AppState.LOG_VIEW
        return None


# ── LayerDetailScreen ─────────────────────────────────────────────────────────

class LayerDetailScreen:
    def __init__(self, app: TuiApp):
        self.app = app
        self._lines: list[str] = []
        self._scroll = 0

    def on_enter(self):
        self._lines  = self._build()
        self._scroll = 0

    def _build(self) -> list[str]:
        if not self.app.layers:
            return ["  No layer selected."]
        layer = self.app.layers[self.app.selected_layer_idx]
        L: list[str] = []

        def row(k: str, v: str):
            L.append(f"  {k:<12}: {v}")

        row("Role", layer.role)
        if layer.role == "image":
            n_img = sum(1 for l in self.app.layers if l.role == "image")
            row("Layer", f"{layer.index} of {n_img}")
        row("Cache ID", layer.cache_id or "(not on disk)")
        if layer.diff_id:
            row("Diff ID", layer.diff_id)
        row("Size", df.fmt_size(layer.size))
        row("On disk", "yes" if layer.on_disk else "NO — layer missing")

        if layer.on_disk and layer.cache_id:
            diff = self.app.docker.layer_diff_dir(layer.cache_id)
            if diff:
                row("Path", str(diff))
                L.append("")
                L.append("  Top-level entries:")
                try:
                    entries = sorted(diff.iterdir())
                    for e in entries[:40]:
                        kind = "dir" if (e.is_dir() and not e.is_symlink()) else \
                               "lnk" if e.is_symlink() else "file"
                        L.append(f"    /{e.name:<30} ({kind})")
                    if len(entries) > 40:
                        L.append(f"    ... ({len(entries) - 40} more)")
                except OSError as exc:
                    L.append(f"    (error: {exc})")

        if layer.role == "upper" and self.app.selected_container:
            c   = self.app.selected_container
            cfg = c["config"]
            L.append("")
            L.append("  Container info:")
            row("  Name", cfg.get("Name", "").lstrip("/"))
            st  = cfg.get("State", {})
            row("  State", "running" if st.get("Running")
                else f"exited ({st.get('ExitCode', '?')})")
            env = cfg.get("Config", {}).get("Env") or []
            if env:
                row("  Env vars", str(len(env)))

        return L

    def draw(self):
        win = self.app.stdscr
        H, W = win.getmaxyx()

        if self.app.layers:
            layer = self.app.layers[self.app.selected_layer_idx]
            tag = ("UPPER" if layer.role == "upper" else
                   "INIT"  if layer.role == "init" else
                   f"[{layer.index}] {df.short(layer.cache_id or '?')}")
            title = f" Layer Detail: {tag} ({layer.role}) "
        else:
            title = " Layer Detail "
        _safe(win, 0, 0, title.ljust(W)[:W], curses.color_pair(CP_HEADER))

        visible = H - 2
        for i, line in enumerate(self._lines[self._scroll:self._scroll + visible]):
            _safe(win, 1 + i, 0, line[:W])

        max_scroll = max(0, len(self._lines) - visible)
        if self._scroll < max_scroll:
            _safe(win, H - 2, 0, "  [↓ more below]", curses.A_DIM)

        keys = " ↑↓/PgUp/PgDn scroll   a: action   b: back   q: quit "
        _safe(win, H - 1, 0, keys.ljust(W)[:W], curses.color_pair(CP_STATUS_BAR))

    def handle_key(self, ch: int) -> Optional[AppState]:
        if ch == curses.KEY_RESIZE:
            curses.update_lines_cols()
            return None
        if ch in (ord('q'), 27):
            return AppState.QUIT
        if ch == ord('b'):
            return AppState.LAYER_STACK
        if ch == ord('a'):
            return AppState.ACTION_DIALOG

        H, _ = self.app.stdscr.getmaxyx()
        visible   = H - 2
        max_scroll = max(0, len(self._lines) - visible)

        if ch == curses.KEY_UP:
            self._scroll = max(0, self._scroll - 1)
        elif ch == curses.KEY_DOWN:
            self._scroll = min(max_scroll, self._scroll + 1)
        elif ch == curses.KEY_PPAGE:
            self._scroll = max(0, self._scroll - visible)
        elif ch == curses.KEY_NPAGE:
            self._scroll = min(max_scroll, self._scroll + visible)
        return None


# ── ActionDialog ──────────────────────────────────────────────────────────────

class ActionDialog:
    _ACTIONS = [
        "Export merged FS up to this layer",
        "Export this layer's diff directory",
    ]

    def __init__(self, app: TuiApp):
        self.app = app
        self.parent_screen: Optional[object] = None
        self._cursor = 0
        self._msg = ""

    def on_enter(self):
        self._cursor = 0
        self._msg = ""

    def draw(self):
        win = self.app.stdscr
        H, W = win.getmaxyx()

        dw = min(W - 8, 58)
        n  = len(self._ACTIONS)
        dh = n + 6
        dx = (W - dw) // 2
        dy = max(1, (H - dh) // 2)

        _hline(win, dy,     dx, dw, '┌', '─', '┐')
        title = " Layer Actions "
        _safe(win, dy, dx + (dw - len(title)) // 2, title)

        if self.app.layers:
            layer = self.app.layers[self.app.selected_layer_idx]
            role_tag = ("UPPER" if layer.role == "upper" else
                        "INIT"  if layer.role == "init" else
                        f"[{layer.index}] {df.short(layer.cache_id or '?', 10)}")
            info = f" {role_tag}  {df.fmt_size(layer.size)} "
            _safe(win, dy + 1, dx, f"│{info[:dw].ljust(dw)}│")
        _safe(win, dy + 2, dx, f"│{'─' * dw}│")

        for i, action in enumerate(self._ACTIONS):
            marker = "▶ " if i == self._cursor else "  "
            line = f"│  {marker}{action}"
            line = line[:dw + 1].ljust(dw + 1) + "│"
            attr = curses.color_pair(CP_SELECTED) if i == self._cursor else 0
            _safe(win, dy + 3 + i, dx, line, attr)

        _safe(win, dy + 3 + n, dx, f"│{'─' * dw}│")
        hint = " Enter: confirm   Esc: cancel "
        _safe(win, dy + 4 + n, dx, f"│{hint.center(dw)}│")
        _hline(win, dy + 5 + n, dx, dw, '└', '─', '┘')

        if self._msg:
            _safe(win, dy + 6 + n, dx + 1, self._msg[:dw], curses.A_DIM)

    def handle_key(self, ch: int) -> Optional[AppState]:
        if ch == curses.KEY_RESIZE:
            curses.update_lines_cols()
            return None
        if ch == 27:
            return AppState.LAYER_STACK
        if ch == curses.KEY_UP:
            self._cursor = max(0, self._cursor - 1)
        elif ch == curses.KEY_DOWN:
            self._cursor = min(len(self._ACTIONS) - 1, self._cursor + 1)
        elif ch in (curses.KEY_ENTER, 10, 13):
            return self._execute()
        return None

    def _execute(self) -> Optional[AppState]:
        if not self.app.layers:
            return None
        layer = self.app.layers[self.app.selected_layer_idx]
        if not layer.on_disk or not layer.cache_id:
            self._msg = "Layer is not on disk — cannot export."
            return None

        out_str = self._prompt(" Output directory: ")
        if out_str is None or not out_str.strip():
            return None
        out = Path(out_str.strip())

        if self._cursor == 0:
            layers_up = self.app.layers[:self.app.selected_layer_idx + 1]
            cache_ids = [l.cache_id for l in layers_up]
            self._run_merge(cache_ids, out)
        else:
            diff = self.app.docker.layer_diff_dir(layer.cache_id)
            if diff:
                self._copy_diff(diff, out)
            else:
                self._msg = "diff/ directory not found."

        return AppState.LAYER_STACK

    def _prompt(self, prompt: str) -> Optional[str]:
        return _prompt_line(self.app.stdscr, prompt)

    def _run_merge(self, cache_ids: list, output: Path):
        win = self.app.stdscr
        H, W = win.getmaxyx()
        progress: dict = {"msg": "Starting…", "done": False, "error": None}

        def cb(msg: str):
            progress["msg"] = msg

        def worker():
            try:
                _TuiMerger(self.app.docker, cb).merge(cache_ids, output)
                progress["done"] = True
            except Exception as exc:
                progress["error"] = str(exc)
                progress["done"] = True

        threading.Thread(target=worker, daemon=True).start()
        win.timeout(200)
        while not progress["done"]:
            win.erase()
            if self.parent_screen:
                self.parent_screen.draw()
            self.draw()
            msg = f" {progress['msg']} "
            _safe(win, H // 2, max(0, (W - len(msg)) // 2), msg,
                  curses.color_pair(CP_HEADER))
            win.refresh()
            win.getch()
        win.timeout(-1)

        if progress["error"]:
            self._msg = f"Error: {progress['error'][:50]}"
        else:
            self.app.status_msg = f"Done → {output}"

    def _copy_diff(self, diff_dir: Path, output: Path):
        win = self.app.stdscr
        H, W = win.getmaxyx()
        _safe(win, H // 2, 2, " Copying diff… ", curses.color_pair(CP_HEADER))
        win.refresh()
        try:
            shutil.copytree(str(diff_dir), str(output), symlinks=True,
                            dirs_exist_ok=True)
            self.app.status_msg = f"Diff copied → {output}"
        except Exception as exc:
            self._msg = f"Error: {exc}"[:60]


# ── TuiOverlayMerger ─────────────────────────────────────────────────────────

class _TuiMerger(df.OverlayMerger):
    def __init__(self, docker: df.DockerRoot, cb: Callable[[str], None]):
        super().__init__(docker, verbose=False)
        self._cb = cb

    def merge(self, cache_ids, output: Path):
        output.mkdir(parents=True, exist_ok=True)
        total = len(cache_ids)
        for i, cid in enumerate(cache_ids):
            if cid is None:
                self.stats["missing_layers"] += 1
                self._cb(f"Layer {i+1}/{total}: missing (skipped)")
                continue
            diff = self.docker.layer_diff_dir(cid)
            if diff is None:
                self.stats["missing_layers"] += 1
                self._cb(f"Layer {i+1}/{total}: diff/ missing for {df.short(cid)}")
                continue
            self._cb(f"Applying layer {i+1}/{total}: {df.short(cid)}…")
            self._apply_layer(diff, output)
        s = self.stats
        self._cb(f"Done: {s['added']} added, {s['overwritten']} overwritten, "
                 f"{s['deleted']} deleted, {s['missing_layers']} missing")


# ── DiffViewScreen ────────────────────────────────────────────────────────────

class DiffViewScreen:
    def __init__(self, app: TuiApp):
        self.app = app
        self._lines: list[str] = []
        self._scroll = 0
        self._filter = ""     # 'A', 'M', 'D', or '' for all

    def on_enter(self):
        self._lines  = self._build()
        self._scroll = 0

    def _build(self) -> list[str]:
        c = self.app.selected_container
        if not c:
            return ["  No container selected."]
        docker = self.app.docker
        cfg      = c["config"]
        image_id = cfg.get("Image", "").removeprefix("sha256:")
        upper_id = docker.container_upper_id(c["id"])
        if not upper_id:
            return ["  No upper layer found for this container."]
        diff = docker.overlay2 / upper_id / "diff"
        if not diff.exists():
            return [f"  Upper layer diff/ not found: {diff}"]
        try:
            img_cache = docker.image_cache_ids(image_id) if image_id else []
            init_id   = docker.container_init_id(c["id"])
            lower_ids = img_cache + ([init_id] if init_id else [])
            img_paths = df._build_path_set(docker, lower_ids)
            changes   = df._collect_diff(diff, img_paths)
        except Exception as exc:
            return [f"  Error computing diff: {exc}"]

        sid  = df.short(c["id"])
        name = cfg.get("Name", "").lstrip("/") or sid
        added = sum(1 for ch in changes if ch["change"] == "A")
        modf  = sum(1 for ch in changes if ch["change"] == "M")
        deld  = sum(1 for ch in changes if ch["change"] == "D")

        L = [f"  Container diff: {sid}  name={name}",
             f"  {added} added  {modf} modified  {deld} deleted",
             f"  Filter: [a]dded  [m]odified  [d]eleted  [c]lear — current: '{self._filter or 'all'}'",
             ""]

        for ch in changes:
            if self._filter and ch["change"] != self._filter.upper():
                continue
            sym   = ch["change"]
            ftype = ch["type"]
            path  = ch["path"]
            note  = ch.get("note", "")
            size_s = df.fmt_size(ch["size_bytes"]) if ch.get("size_bytes") else ""
            if sym == "D":
                extra = f"  ({note})" if note else ""
                L.append(f"  {sym}  {ftype:<4}  {path}{extra}")
            elif ftype == "sym":
                L.append(f"  {sym}  {ftype:<4}  {path}  → {note}")
            else:
                size_part = f"  {size_s}" if size_s else ""
                L.append(f"  {sym}  {ftype:<4}  {path}{size_part}")
        if not changes:
            L.append("  (no changes in upper layer)")
        return L

    def draw(self):
        win = self.app.stdscr
        H, W = win.getmaxyx()
        c = self.app.selected_container
        name = c["config"].get("Name", "").lstrip("/") if c else "?"
        _safe(win, 0, 0, f" Diff View: {name} ".ljust(W)[:W], curses.color_pair(CP_HEADER))

        visible = H - 2
        for i, line in enumerate(self._lines[self._scroll:self._scroll + visible]):
            _safe(win, 1 + i, 0, line[:W])

        max_scroll = max(0, len(self._lines) - visible)
        if self._scroll < max_scroll:
            _safe(win, H - 2, 0, "  [↓ more below]", curses.A_DIM)

        keys = " ↑↓/PgUp/PgDn scroll   a/m/d: filter   c: clear filter   b: back   q: quit "
        _safe(win, H - 1, 0, keys.ljust(W)[:W], curses.color_pair(CP_STATUS_BAR))

    def handle_key(self, ch: int) -> Optional[AppState]:
        if ch == curses.KEY_RESIZE:
            curses.update_lines_cols()
            return None
        if ch in (ord('q'), 27):
            return AppState.QUIT
        if ch == ord('b'):
            return AppState.LAYER_STACK

        H, _ = self.app.stdscr.getmaxyx()
        visible    = H - 2
        max_scroll = max(0, len(self._lines) - visible)

        if ch == curses.KEY_UP:
            self._scroll = max(0, self._scroll - 1)
        elif ch == curses.KEY_DOWN:
            self._scroll = min(max_scroll, self._scroll + 1)
        elif ch == curses.KEY_PPAGE:
            self._scroll = max(0, self._scroll - visible)
        elif ch == curses.KEY_NPAGE:
            self._scroll = min(max_scroll, self._scroll + visible)
        elif ch in (ord('a'), ord('A')):
            self._filter = "A"
            self._lines  = self._build()
            self._scroll = 0
        elif ch in (ord('m'), ord('M')):
            self._filter = "M"
            self._lines  = self._build()
            self._scroll = 0
        elif ch in (ord('d'), ord('D')):
            self._filter = "D"
            self._lines  = self._build()
            self._scroll = 0
        elif ch in (ord('c'), ord('C')):
            self._filter = ""
            self._lines  = self._build()
            self._scroll = 0
        return None


# ── LogViewScreen ─────────────────────────────────────────────────────────────

class LogViewScreen:
    def __init__(self, app: TuiApp):
        self.app = app
        self._lines: list[str] = []
        self._scroll = 0
        self._filter = ""   # 'stdout', 'stderr', or '' for all

    def on_enter(self):
        self._lines  = self._build()
        self._scroll = 0

    def _build(self) -> list[str]:
        c = self.app.selected_container
        if not c:
            return ["  No container selected."]
        docker   = self.app.docker
        log_path = docker.container_log_path(c["id"])
        if not log_path:
            driver = (c["config"].get("HostConfig") or {}).get("LogConfig", {}).get("Type", "")
            note   = f" (log driver: {driver})" if driver and driver != "json-file" else ""
            return [f"  No log file found{note}."]

        sid  = df.short(c["id"])
        name = c["config"].get("Name", "").lstrip("/") or sid
        L = [f"  Log: {name} ({sid})  ←  {log_path}",
             f"  Filter: [s]tdout  [e]rr  [c]lear — current: '{self._filter or 'all'}'",
             ""]
        errors = 0
        try:
            with open(log_path, "r", errors="replace") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        entry = json.loads(raw)
                    except json.JSONDecodeError:
                        errors += 1
                        continue
                    stream = entry.get("stream", "")
                    if self._filter and stream != self._filter:
                        continue
                    ts     = entry.get("time", "")[:19].replace("T", " ")
                    marker = "E" if stream == "stderr" else " "
                    text   = entry.get("log", "").rstrip("\n")
                    L.append(f"  {ts}  {marker}  {text}")
        except OSError as exc:
            L.append(f"  Error reading log: {exc}")
        if errors:
            L.append(f"  [{errors} unparseable line(s) skipped]")
        if len(L) == 3:
            L.append("  (no log entries)")
        return L

    def draw(self):
        win = self.app.stdscr
        H, W = win.getmaxyx()
        c = self.app.selected_container
        name = c["config"].get("Name", "").lstrip("/") if c else "?"
        _safe(win, 0, 0, f" Log View: {name} ".ljust(W)[:W], curses.color_pair(CP_HEADER))

        visible = H - 2
        for i, line in enumerate(self._lines[self._scroll:self._scroll + visible]):
            _safe(win, 1 + i, 0, line[:W])

        max_scroll = max(0, len(self._lines) - visible)
        if self._scroll < max_scroll:
            _safe(win, H - 2, 0, "  [↓ more below]", curses.A_DIM)

        keys = " ↑↓/PgUp/PgDn scroll   s: stdout   e: stderr   c: all   b: back   q: quit "
        _safe(win, H - 1, 0, keys.ljust(W)[:W], curses.color_pair(CP_STATUS_BAR))

    def handle_key(self, ch: int) -> Optional[AppState]:
        if ch == curses.KEY_RESIZE:
            curses.update_lines_cols()
            return None
        if ch in (ord('q'), 27):
            return AppState.QUIT
        if ch == ord('b'):
            return AppState.LAYER_STACK

        H, _ = self.app.stdscr.getmaxyx()
        visible    = H - 2
        max_scroll = max(0, len(self._lines) - visible)

        if ch == curses.KEY_UP:
            self._scroll = max(0, self._scroll - 1)
        elif ch == curses.KEY_DOWN:
            self._scroll = min(max_scroll, self._scroll + 1)
        elif ch == curses.KEY_PPAGE:
            self._scroll = max(0, self._scroll - visible)
        elif ch == curses.KEY_NPAGE:
            self._scroll = min(max_scroll, self._scroll + visible)
        elif ch in (ord('s'), ord('S')):
            self._filter = "stdout"
            self._lines  = self._build()
            self._scroll = 0
        elif ch in (ord('e'), ord('E')):
            self._filter = "stderr"
            self._lines  = self._build()
            self._scroll = 0
        elif ch in (ord('c'), ord('C')):
            self._filter = ""
            self._lines  = self._build()
            self._scroll = 0
        return None


# ── TuiApp ────────────────────────────────────────────────────────────────────

class TuiApp:
    def __init__(self, docker: df.DockerRoot):
        self.docker = docker
        self.stdscr = None
        self.selected_image: Optional[dict] = None
        self.selected_container: Optional[dict] = None
        self.layers: list[LayerRecord] = []
        self.selected_layer_idx: int = 0
        self.status_msg: str = ""

    def run(self, stdscr):
        self.stdscr = stdscr
        curses.curs_set(0)
        stdscr.keypad(True)
        self._init_colors()

        overview = OverviewScreen(self)
        stk      = LayerStackScreen(self)
        det      = LayerDetailScreen(self)
        dlg      = ActionDialog(self)
        diffview = DiffViewScreen(self)
        logview  = LogViewScreen(self)

        screens = {
            AppState.OVERVIEW:      overview,
            AppState.LAYER_STACK:   stk,
            AppState.LAYER_DETAIL:  det,
            AppState.ACTION_DIALOG: dlg,
            AppState.DIFF_VIEW:     diffview,
            AppState.LOG_VIEW:      logview,
        }

        state = AppState.OVERVIEW
        screens[state].on_enter()

        while True:
            H, W = stdscr.getmaxyx()
            stdscr.erase()

            if H < 24 or W < 80:
                msg = "Terminal too small (min 80×24)"
                _safe(stdscr, H // 2, max(0, (W - len(msg)) // 2), msg)
                stdscr.refresh()
                ch = stdscr.getch()
                if ch in (ord('q'), 27):
                    break
                if ch == curses.KEY_RESIZE:
                    curses.update_lines_cols()
                continue

            # ActionDialog draws over the previous screen
            if state == AppState.ACTION_DIALOG and dlg.parent_screen:
                dlg.parent_screen.draw()
            screens[state].draw()

            # Status message overlay (bottom-right)
            if self.status_msg:
                msg = f" {self.status_msg} "
                _safe(stdscr, H - 1, max(0, W - len(msg) - 1), msg[:W],
                      curses.color_pair(CP_HEADER))

            stdscr.refresh()
            ch = stdscr.getch()
            next_state = screens[state].handle_key(ch)

            if next_state == AppState.QUIT:
                break
            if next_state is not None and next_state != state:
                if next_state == AppState.ACTION_DIALOG:
                    dlg.parent_screen = screens[state]
                self.status_msg = ""
                state = next_state
                screens[state].on_enter()

    def _init_colors(self):
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(CP_SELECTED,   curses.COLOR_BLACK,  curses.COLOR_CYAN)
        curses.init_pair(CP_IMAGE,      -1,                  -1)
        curses.init_pair(CP_INIT,       curses.COLOR_YELLOW, -1)
        curses.init_pair(CP_UPPER,      curses.COLOR_GREEN,  -1)
        curses.init_pair(CP_STATUS_BAR, curses.COLOR_BLACK,  curses.COLOR_WHITE)
        curses.init_pair(CP_HEADER,     curses.COLOR_WHITE,  curses.COLOR_BLUE)
        curses.init_pair(CP_MISSING,    curses.COLOR_RED,    -1)

    def build_layers_for_image(self, img: dict) -> list[LayerRecord]:
        image_id = img["id"]
        diff_ids = img["config"].get("rootfs", {}).get("diff_ids", [])
        try:
            cache_ids = self.docker.image_cache_ids(image_id)
        except Exception:
            cache_ids = []
        while len(cache_ids) < len(diff_ids):
            cache_ids.append(None)

        layers = []
        for i, (did, cid) in enumerate(zip(diff_ids, cache_ids)):
            diff_dir = self.docker.layer_diff_dir(cid) if cid else None
            on_disk  = diff_dir is not None
            size     = df._dir_size(diff_dir) if on_disk else 0
            layers.append(LayerRecord(
                index=i + 1, role="image",
                cache_id=cid, diff_id=did,
                size=size, on_disk=on_disk,
            ))
        return layers

    def build_layers_for_container(self, c: dict) -> list[LayerRecord]:
        cid      = c["id"]
        image_id = c["config"].get("Image", "").removeprefix("sha256:")
        layers: list[LayerRecord] = []

        try:
            img    = self.docker.resolve_image(image_id)
            layers = self.build_layers_for_image(img)
        except Exception:
            pass

        def _add_special(role: str, cache_id: Optional[str]):
            if not cache_id:
                return
            diff_dir = self.docker.layer_diff_dir(cache_id)
            on_disk  = diff_dir is not None
            size     = df._dir_size(diff_dir) if on_disk else 0
            layers.append(LayerRecord(
                index=0, role=role,
                cache_id=cache_id, diff_id="",
                size=size, on_disk=on_disk,
            ))

        _add_special("init",  self.docker.container_init_id(cid))
        _add_special("upper", self.docker.container_upper_id(cid))
        return layers


# ── Entry point ───────────────────────────────────────────────────────────────

def run_tui(docker: df.DockerRoot) -> None:
    app = TuiApp(docker)
    stderr_buf = io.StringIO()
    old_stderr = sys.stderr
    sys.stderr = stderr_buf
    try:
        curses.wrapper(app.run)
    finally:
        sys.stderr = old_stderr
    captured = stderr_buf.getvalue().strip()
    if captured:
        print(captured, file=sys.stderr)
