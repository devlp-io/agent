"""
tui.py — Terminal UI for SOM-SCAN.
Inspired by OpenAI Codex CLI and OpenCode:
- Near-black background (#070c14)
- Compact header: [>_] SOM-SCAN (left) and active model (right)
- Visual animated loading spinner (⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏) for thinking, running commands, and scans
- Real-time live token streaming for conversational replies
- 100% responsive layout for all terminal sizes
- Non-blocking typing box: never locks during active runs; permits immediate commands
  (/copy, /cancel, /pause, /status) and mid-scan operator directive injection
- Interactive Ctrl+C / Pause Menu: arrow-navigable modal screen offering Continue, Chat,
  Focus/Status, Copy, Stop, and Quit (Ctrl+C never accidentally terminates the app)
- Slash Command Auto-complete Popup: typing '/' displays a floating suggestions list with
  descriptions; filterable in real time, navigable with Up/Down arrows, auto-completable with Tab/Enter
- Rich cards for: user messages, assistant responses, command runs, redteam findings, and tasks
- Comprehensive shortcuts and native clipboard copying across Windows, macOS, and Linux
"""
import os
import sys
import re
import time
import signal
import pathlib
import threading
import subprocess
from typing import Optional, List, Tuple, Dict, Any

from rich.markdown import Markdown as RichMarkdown
from rich.text import Text
from rich.markup import escape
from textual.app import App, ComposeResult
from textual.screen import ModalScreen
from textual.containers import Vertical, Horizontal, VerticalScroll
from textual.widgets import Static, Input, Label
from textual.binding import Binding
from textual.timer import Timer

from core.events import (
    AgentEvent, UserMessageEvent, AssistantChunkEvent, AssistantMessageEvent,
    ThinkingStartEvent, ThinkingStopEvent, CommandStartEvent, CommandOutputEvent,
    CommandFinishEvent, FindingEvent, StatusChangeEvent, TaskCompleteEvent,
    TaskCancelledEvent, ErrorEvent
)
from core.model_manager import ModelManager
from core.agent_router import AgentRouter, strip_directives
from core.version import __version__, get_version_string

SPINNER_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")

SLASH_COMMANDS: List[Tuple[str, str]] = [
    ("/new", "Start fresh assessment session, archive previous scan & clear chat"),
    ("/scan <target>", "Launch autonomous security assessment on domain or URL"),
    ("/resume [target]", "Resume previous assessment from last saved state"),
    ("/attack [target]", "Launch post-scan exploit/attack phase on findings"),
    ("/copy", "Copy entire session (chat, commands, findings) to clipboard"),
    ("/cancel", "Interrupt active task, scan, or command"),
    ("/pause", "Pause running scan and open operator control menu"),
    ("/status", "Inspect active scan phase, findings, and live statistics"),
    ("/tools [status|install]", "Inspect installed and missing security tools"),
    ("/install <tool>", "Platform-aware security tool installer"),
    ("/model [name]", "Switch or view active AI model profile"),
    ("/key [key]", "Configure API keys in memory and save to .env"),
    ("/env", "Inspect environment and API key configuration"),
    ("/file <cmd> <path>", "File operations: create, view, edit, list, delete"),
    ("/focus", "Scroll to latest output and focus composer"),
    ("/clear", "Clear conversation viewport scrollback"),
    ("/long", "Expand full command stdout/stderr cards"),
    ("/short", "Collapse command output cards to preview"),
    ("/help", "Display full command reference"),
    ("/quit", "Cleanly exit SOM-SCAN application"),
]


def copy_to_system_clipboard(text: str) -> bool:
    """Copy text to system clipboard across Windows, macOS, and Linux with full Unicode support."""
    # 1. Native Windows Win32 API via ctypes (zero dependencies, instant, 100% Unicode)
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32

            kernel32.GlobalAlloc.restype = ctypes.c_void_p
            kernel32.GlobalLock.restype = ctypes.c_void_p
            kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
            kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
            user32.SetClipboardData.argtypes = [wintypes.UINT, ctypes.c_void_p]

            GMEM_MOVEABLE = 0x0002
            CF_UNICODETEXT = 13

            data = text.encode("utf-16le") + b"\x00\x00"
            h_mem = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data))
            if h_mem:
                ptr = kernel32.GlobalLock(h_mem)
                if ptr:
                    ctypes.memmove(ptr, data, len(data))
                    kernel32.GlobalUnlock(h_mem)
                    if user32.OpenClipboard(None):
                        user32.EmptyClipboard()
                        user32.SetClipboardData(CF_UNICODETEXT, h_mem)
                        user32.CloseClipboard()
                        return True
        except Exception:
            pass

        # Windows clip.exe fallback
        try:
            subprocess.run(
                ["clip"],
                input=text.encode("utf-8", errors="replace"),
                check=True,
                creationflags=0x08000000 if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            )
            return True
        except Exception:
            pass

    # 2. Try pyperclip if installed
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except Exception:
        pass

    # 3. macOS pbcopy
    if sys.platform == "darwin":
        try:
            subprocess.run(["pbcopy"], input=text.encode("utf-8"), check=True)
            return True
        except Exception:
            pass

    # 4. Linux xclip / wl-copy / xsel
    if sys.platform.startswith("linux"):
        for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]):
            try:
                subprocess.run(cmd, input=text.encode("utf-8"), check=True)
                return True
            except Exception:
                continue

    return False


TUI_CSS = """
Screen {
    background: #070c14;
    color: #e2e8f0;
}

#header-bar {
    dock: top;
    height: 3;
    width: 100%;
    background: #070c14;
    border-bottom: solid #1e293b;
    padding: 0 1;
    layout: horizontal;
    align: left middle;
}

#brand-label {
    width: auto;
    color: #f8fafc;
    text-style: bold;
}

#model-badge {
    width: 1fr;
    color: #38bdf8;
    text-style: italic;
    content-align: right middle;
}

#chat-scroll {
    width: 100%;
    height: 1fr;
    background: #070c14;
    padding: 0 1;
    margin-bottom: 1;
    overflow-y: scroll;
    overflow-x: hidden;
    scrollbar-color: #38bdf8 #0f172a;
    scrollbar-size: 1 1;
}

/* User Message Card */
.user-box {
    width: 100%;
    height: auto;
    margin: 1 0 0 0;
    padding: 0;
}

.user-marker {
    width: 100%;
    color: #38bdf8;
    text-style: bold;
    margin-bottom: 0;
}

.user-text {
    width: 100%;
    height: auto;
    color: #f1f5f9;
    padding-left: 2;
    margin-top: 0;
    text-wrap: wrap;
}

/* Assistant Message Card */
.assistant-box {
    width: 100%;
    height: auto;
    margin: 1 0 0 0;
    padding: 0;
}

.assistant-marker {
    width: 100%;
    color: #38bdf8;
    text-style: bold;
    margin-bottom: 0;
}

.assistant-text {
    width: 100%;
    height: auto;
    color: #e2e8f0;
    padding-left: 2;
    margin-top: 0;
    text-wrap: wrap;
}

/* Thinking Indicator */
.thinking-box {
    width: 100%;
    height: auto;
    margin: 1 0 0 0;
    padding-left: 2;
}

.thinking-text {
    color: #c084fc;
    text-style: italic;
}

/* Command Card — Neon Cyan & Pink */
.command-card {
    width: 100%;
    height: auto;
    background: #080c16;
    border: round #ec4899;
    margin: 1 0 0 0;
    padding: 0 1;
}

.command-card:hover {
    border: round #38bdf8;
}

.command-header {
    width: 100%;
    color: #f472b6;
    text-style: bold;
}

.command-line {
    width: 100%;
    color: #38bdf8;
    text-style: bold;
}

.command-output-success {
    width: 100%;
    height: auto;
    color: #a5f3fc;
    text-wrap: wrap;
}

.command-output-fail {
    width: 100%;
    height: auto;
    color: #fb7185;
    text-wrap: wrap;
}

/* Code Bubble — Plain Code Container with Cyan & Pink Palette */
.code-bubble {
    width: 100%;
    height: auto;
    background: #070913;
    border: round #38bdf8;
    margin: 1 0 0 0;
    padding: 0 1;
}

.code-bubble:hover {
    border: round #ec4899;
}

.code-bubble-header {
    width: 100%;
    color: #ec4899;
    text-style: bold;
    border-bottom: solid #1e293b;
    margin-bottom: 0;
}

.code-bubble-content {
    width: 100%;
    height: auto;
    color: #38bdf8;
    text-wrap: wrap;
    padding: 0 1;
}

/* Finding Card */
.finding-card {
    width: 100%;
    height: auto;
    background: #140d1f;
    border: solid #a855f7;
    margin: 1 0 0 0;
    padding: 0 1;
}

.finding-title {
    width: 100%;
    color: #c084fc;
    text-style: bold;
    text-wrap: wrap;
}

.finding-evidence {
    width: 100%;
    color: #cbd5e1;
    text-wrap: wrap;
}

/* Task Status */
.task-status-box {
    width: 100%;
    height: auto;
    margin: 1 0 0 0;
    padding: 0 1;
}

.task-complete {
    width: 100%;
    color: #22c55e;
    text-style: bold;
    text-wrap: wrap;
}

.task-cancelled {
    width: 100%;
    color: #eab308;
    text-style: bold;
    text-wrap: wrap;
}

.task-failed {
    width: 100%;
    color: #ef4444;
    text-style: bold;
    text-wrap: wrap;
}

/* Error Boundary Card */
.error-boundary-card {
    width: 100%;
    height: auto;
    background: #160a12;
    border: solid #ef4444;
    margin: 1 0 0 0;
    padding: 0 1;
}

.error-boundary-title {
    width: 100%;
    color: #ef4444;
    text-style: bold;
}

.error-boundary-msg {
    width: 100%;
    color: #fca5a5;
    text-wrap: wrap;
    margin-top: 0;
}

.error-boundary-trace {
    width: 100%;
    color: #94a3b8;
    text-wrap: wrap;
    margin-top: 0;
}


/* Fixed Bottom Composer with margin and top border divider */
#composer-container {
    dock: bottom;
    width: 100%;
    height: auto;
    background: #070c14;
    border-top: solid #1e293b;
    padding: 1 1 0 1;
}

/* Slash Command Suggestions Popup */
#suggestions-box {
    width: 100%;
    height: auto;
    max-height: 8;
    background: #0a1120;
    border: solid #0284c7;
    margin-bottom: 0;
    padding: 0 1;
    display: none;
    overflow-y: auto;
}

.sugg-item {
    width: 100%;
    height: 1;
    color: #94a3b8;
    text-wrap: nowrap;
}

.sugg-item-selected {
    width: 100%;
    height: 1;
    background: #0284c7;
    color: #ffffff;
    text-style: bold;
    text-wrap: nowrap;
}

#input-box {
    width: 100%;
    height: 3;
    background: #070c14;
    border: round #38bdf8;
    color: #f8fafc;
    padding: 0 1;
}

#input-box:focus {
    border: round #00d2ff;
}

#footer-bar {
    width: 100%;
    height: 1;
    layout: horizontal;
    align: left middle;
    padding: 0;
}

#shortcut-hints {
    width: 1fr;
    color: #64748b;
    text-wrap: nowrap;
}

#version-pill {
    width: auto;
    min-width: 8;
    color: #38bdf8;
    text-style: bold;
    content-align: center middle;
    padding: 0 1;
}

#status-pill {
    width: auto;
    min-width: 8;
    color: #22c55e;
    text-style: bold;
    content-align: right middle;
}

/* Pause Modal Screen */
PauseMenuScreen {
    align: center middle;
    background: rgba(0, 0, 0, 0.75);
}

#pause-dialog {
    width: 68;
    height: auto;
    background: #091322;
    border: thick #0284c7;
    padding: 1 2;
}

#pause-title {
    width: 100%;
    color: #38bdf8;
    text-style: bold;
    content-align: center middle;
    margin-bottom: 1;
}

#pause-meta {
    width: 100%;
    color: #94a3b8;
    content-align: center middle;
    margin-bottom: 1;
    border-bottom: solid #1e293b;
    padding-bottom: 1;
}

.pause-option-row {
    width: 100%;
    height: 1;
    color: #cbd5e1;
    padding: 0 1;
}

.pause-option-active {
    width: 100%;
    height: 1;
    background: #0284c7;
    color: #ffffff;
    text-style: bold;
}

#pause-footer {
    width: 100%;
    color: #64748b;
    content-align: center middle;
    margin-top: 1;
    border-top: solid #1e293b;
    padding-top: 1;
}
"""


class CommandCard(Static):
    """Visual card for command execution with live spinner and collapsible output."""

    def __init__(self, command: str, **kwargs):
        super().__init__(classes="command-card", **kwargs)
        self.command = command
        self.output = ""
        self.returncode: Optional[int] = None
        self.expanded = False
        self._header_label = Label("[>_] Running command...", classes="command-header", markup=False)
        self._cmd_label = Label(f"$ {self.command}", classes="command-line", markup=False)
        self._out_label = Label("Executing...", classes="command-output-success", markup=False)

    def compose(self) -> ComposeResult:
        yield self._header_label
        yield self._cmd_label
        yield self._out_label

    def tick_spinner(self, frame: str):
        try:
            if self.returncode is None:
                self._header_label.update(f"[>_] {frame} Running command...")
        except Exception:
            pass

    def update_result(self, returncode: int, output: str):
        self.returncode = returncode
        self.output = output
        self._header_label.update("[>_] Command finished")

        lines = output.strip().splitlines()
        if not self.expanded and len(lines) > 6:
            display_text = "\n".join(lines[:5]) + f"\n... ({len(lines)-5} more lines — type /long to expand)"
        else:
            display_text = output.strip() if output.strip() else "(no output)"
        self.display_text = display_text

        if returncode == 0:
            self._out_label.update(f"✓ {display_text}")
            self._out_label.remove_class("command-output-fail")
            self._out_label.add_class("command-output-success")
        else:
            self._out_label.update(f"✗ {display_text}")
            self._out_label.remove_class("command-output-success")
            self._out_label.add_class("command-output-fail")

    def toggle_expand(self, expand: bool):
        self.expanded = expand
        if self.returncode is not None:
            self.update_result(self.returncode, self.output)


class CodeBubble(Static):
    """
    Visual bubble for plain codes, scripts, and syntax blocks.
    Styled with vivid Neon Cyan (#38bdf8) and Hot Pink (#ec4899 / #f472b6).
    Supports collapsible short view (default: 5 lines) and full expansion via /long.
    """

    def __init__(self, code: str, language: str = "text", title: Optional[str] = None, **kwargs):
        super().__init__(classes="code-bubble", **kwargs)
        self.code = code.strip()
        self.language = (language or "code").strip()
        self.title = title or f"◈ {self.language.upper()} CODE BUBBLE"
        self.expanded = False
        self._header_label = Label(self._header_text(), classes="code-bubble-header")
        self._content_static = Static(self._format_highlighted_code(), classes="code-bubble-content")

    def compose(self) -> ComposeResult:
        yield self._header_label
        yield self._content_static

    def _header_text(self) -> str:
        lines = self.code.splitlines()
        count = len(lines)
        return (
            f"[bold #ec4899]{self.title}[/]  "
            f"[dim #38bdf8]── plain code ──[/]  "
            f"[dim #64748b]({count} line{'s' if count != 1 else ''})[/]"
        )

    def _format_highlighted_code(self) -> str:
        lines = self.code.splitlines()
        if not lines:
            return "[dim #64748b](empty code block)[/]"

        formatted: List[str] = []
        if not self.expanded and len(lines) > 6:
            for i, line in enumerate(lines[:5], start=1):
                safe_line = line.replace("[", "\\[")
                formatted.append(f"[dim #f472b6]{i:3d} │[/] [bold #38bdf8]{safe_line}[/]")
            hidden = len(lines) - 5
            formatted.append(
                f"[dim #64748b]... ({hidden} more line{'s' if hidden != 1 else ''} — type [/][bold #38bdf8]/long[/][dim #64748b] to expand, [/][bold #ec4899]/short[/][dim #64748b] to collapse)[/]"
            )
        else:
            for i, line in enumerate(lines, start=1):
                safe_line = line.replace("[", "\\[")
                formatted.append(f"[dim #f472b6]{i:3d} │[/] [bold #38bdf8]{safe_line}[/]")
            if len(lines) > 6:
                formatted.append(
                    f"[dim #64748b](all {len(lines)} lines displayed — type [/][bold #ec4899]/short[/][dim #64748b] to collapse)[/]"
                )
        return "\n".join(formatted)

    def toggle_expand(self, expand: bool):
        self.expanded = expand
        try:
            self._content_static.update(self._format_highlighted_code())
        except Exception:
            pass


class SafeMarkdown(Static):
    """Crash-immune Markdown widget with fallback to styled Text."""

    def __init__(self, content: str = "", **kwargs):
        super().__init__(**kwargs)
        self._content = content

    def update_content(self, text: str):
        self._content = text
        self.refresh()

    def render(self):
        if not self._content:
            return Text("")
        try:
            return RichMarkdown(self._content, code_theme="monokai")
        except Exception:
            return Text(self._content)



class CommandInput(Input):
    """Custom input box with unblocked scrolling, command history, and suggestions navigation."""

    def on_key(self, event) -> None:
        try:
            app: "SomScanApp" = self.app  # type: ignore
            if event.key == "ctrl+c":
                # If text is selected, let native copy handle it
                if getattr(self, "selection", None):
                    self.action_copy()
                    event.prevent_default()
                    event.stop()
                    return
                # If operator typed text in the box and task is idle: clear the line (standard CLI ^C)
                if self.value and not app.router.is_busy:
                    self.value = ""
                    event.prevent_default()
                    event.stop()
                    return
                app.action_interrupt_task()
                event.prevent_default()
                event.stop()
                return

            # Unblocked keyboard scrolling directly from the typing area
            try:
                scroll = app.query_one("#chat-scroll", VerticalScroll)
            except Exception:
                scroll = None

            if scroll is not None:
                if event.key == "pageup":
                    app._auto_scroll = False
                    scroll.scroll_page_up(animate=False)
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key == "pagedown":
                    scroll.scroll_page_down(animate=False)
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key in ("shift+up", "ctrl+up"):
                    app._auto_scroll = False
                    scroll.scroll_up(y=4, animate=False)
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key in ("shift+down", "ctrl+down"):
                    scroll.scroll_down(y=4, animate=False)
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key == "ctrl+home":
                    app._auto_scroll = False
                    scroll.scroll_home(animate=False)
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key == "ctrl+end":
                    app._auto_scroll = True
                    scroll.scroll_end(animate=False)
                    event.prevent_default()
                    event.stop()
                    return

            # Autocomplete suggestions navigation
            if app.suggestions_visible:
                if event.key == "up":
                    app.suggestion_prev()
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key == "down":
                    app.suggestion_next()
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key == "tab":
                    app.suggestion_accept()
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key == "escape":
                    app.hide_suggestions()
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key == "enter" and app.suggestion_selected_index >= 0:
                    app.suggestion_accept()
                    event.prevent_default()
                    event.stop()
                    return
            else:
                # Command history navigation when suggestions popup is not visible
                if event.key == "up":
                    if app.history_prev(self):
                        event.prevent_default()
                        event.stop()
                        return
                elif event.key == "down":
                    if app.history_next(self):
                        event.prevent_default()
                        event.stop()
                        return
        except Exception:
            pass


class PauseMenuScreen(ModalScreen[Optional[str]]):
    """
    Interactive arrow-navigable Pause Menu triggered by Ctrl+C or /pause.
    Allows stopping immediately, continuing, chatting/injecting directive, viewing status, copying logs, or quitting.
    """
    BINDINGS = [
        Binding("escape", "dismiss_continue", "Continue", show=False),
        Binding("ctrl+c", "dismiss_continue", "Continue", show=False),
        Binding("up", "nav_up", "Up", show=False),
        Binding("down", "nav_down", "Down", show=False),
        Binding("enter", "select_current", "Select", show=False),
        Binding("1", "select_1", "1", show=False),
        Binding("2", "select_2", "2", show=False),
        Binding("3", "select_3", "3", show=False),
        Binding("4", "select_4", "4", show=False),
        Binding("5", "select_5", "5", show=False),
        Binding("6", "select_6", "6", show=False),
        Binding("7", "select_7", "7", show=False),
    ]

    OPTIONS = [
        ("stop",     "1. ⏹  Stop / Cancel Active Task",    "Immediately halt the running command or chat (keeps full history)"),
        ("continue", "2. ▶  Continue / Resume",            "Resume task execution without interruption"),
        ("message",  "3. 💬 Message / Directive <MSG>",    "Inject live steering instruction or prompt mid-loop"),
        ("focus",    "4. 🔍 Focus / Active Status",        "Inspect live task state, active command, endpoints & findings"),
        ("copy",     "5. 📋 Copy Session History",         "Export all chat and command outputs to clipboard & log"),
        ("new",      "6. 🔄 New Session (/new)",           "Archive current session and start a clean slate"),
        ("quit",     "7. 🚪 Quit SOM-SCAN (/quit)",        "Cleanly exit SOM-SCAN application"),
    ]

    def __init__(self, summary: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.summary = summary
        self.selected_idx = 0
        self._labels: List[Label] = []

    def compose(self) -> ComposeResult:
        tgt = self.summary.get("target", "None")
        phase = self.summary.get("phase", "Idle")
        turns = self.summary.get("turn", 0)
        findings = self.summary.get("findings", 0)

        with Vertical(id="pause-dialog"):
            yield Label("⏸️  [bold #38bdf8]SOM-SCAN OPERATOR PAUSE MENU[/]", id="pause-title")
            yield Label(
                f"Target: [white]{tgt}[/]  ·  Phase: [cyan]{phase}[/]  ·  Turn: [yellow]{turns}[/]  ·  Findings: [purple]{findings}[/]",
                id="pause-meta"
            )
            for idx, (code, title, desc) in enumerate(self.OPTIONS):
                lbl = Label(f"  {title} — {desc}", classes="pause-option-row", markup=False)
                self._labels.append(lbl)
                yield lbl
            yield Label("Use ↑ / ↓ arrow keys or [1-7], Enter to select, Esc to continue", id="pause-footer")

    def on_mount(self):
        self._update_highlight()

    def _update_highlight(self):
        for i, lbl in enumerate(self._labels):
            code, title, desc = self.OPTIONS[i]
            if i == self.selected_idx:
                lbl.update(f"> {title} — {desc}")
                lbl.add_class("pause-option-active")
                lbl.remove_class("pause-option-row")
            else:
                lbl.update(f"  {title} — {desc}")
                lbl.add_class("pause-option-row")
                lbl.remove_class("pause-option-active")

    def action_nav_up(self):
        self.selected_idx = (self.selected_idx - 1) % len(self.OPTIONS)
        self._update_highlight()

    def action_nav_down(self):
        self.selected_idx = (self.selected_idx + 1) % len(self.OPTIONS)
        self._update_highlight()

    def action_select_current(self):
        action_code = self.OPTIONS[self.selected_idx][0]
        self.dismiss(action_code)

    def action_select_1(self): self.dismiss(self.OPTIONS[0][0])
    def action_select_2(self): self.dismiss(self.OPTIONS[1][0])
    def action_select_3(self): self.dismiss(self.OPTIONS[2][0])
    def action_select_4(self): self.dismiss(self.OPTIONS[3][0])
    def action_select_5(self): self.dismiss(self.OPTIONS[4][0])
    def action_select_6(self): self.dismiss(self.OPTIONS[5][0])
    def action_select_7(self): self.dismiss(self.OPTIONS[6][0])

    def action_dismiss_continue(self):
        self.dismiss("continue")


class SomScanApp(App):
    """SOM-SCAN Dedicated Agentic Terminal CLI Application."""

    CSS = TUI_CSS
    TITLE = "SOM-SCAN"

    BINDINGS = [
        Binding("ctrl+c", "interrupt_task", "Pause/Menu", priority=True, show=False),
        Binding("ctrl+q", "quit_app", "Quit", show=False),
    ]

    def __init__(
        self,
        preserved_history: Optional[List[str]] = None,
        preserved_router: Optional[AgentRouter] = None,
        preserved_model_manager: Optional[ModelManager] = None,
        initial_trapped_error: Optional[Tuple[str, str]] = None,
        initial_input: Optional[str] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self._initial_input = initial_input or os.environ.pop("AG_SCAN_TARGET", None)
        self.model_manager = preserved_model_manager or ModelManager()
        if preserved_router is not None:
            self.router = preserved_router
            self.router.emit = self._on_agent_event
        else:
            self.router = AgentRouter(
                event_callback=self._on_agent_event,
                model_manager=self.model_manager,
            )
        self._initial_trapped_error = initial_trapped_error
        self._preserved_history = list(preserved_history or [])
        self._current_command_card: Optional[CommandCard] = None
        self._thinking_widget: Optional[Label] = None
        self._command_cards: List[CommandCard] = []
        self._code_bubbles: List[CodeBubble] = []
        self._input_history: List[str] = []
        self._input_history_idx: int = -1
        self._in_pause_menu: bool = False
        self._auto_scroll = True
        self._conversation_history: List[str] = list(self._preserved_history)
        self._explicit_quit = False

        # Animated Spinner state
        self._spinner_idx = 0
        self._spinner_timer: Optional[Timer] = None
        self._current_status_text = "READY"
        self._current_status_color = "green"
        self._thinking_label = "Thinking…"

        # Live token streaming state
        self._streaming_box: Optional[Vertical] = None
        self._streaming_text_widget: Optional[Static] = None
        self._streaming_accumulated_text = ""

        # Slash Command Autocomplete state
        self.suggestions_visible = False
        self.suggestion_selected_index = -1
        self._matching_suggestions: List[Tuple[str, str]] = []

    def compose(self) -> ComposeResult:
        with Horizontal(id="header-bar"):
            yield Label(f"[bold #38bdf8][>_][/]  [bold white]SOM-SCAN[/]  [dim #64748b]v{__version__}[/]", id="brand-label")
            yield Label(f"[#38bdf8]{self.model_manager.display_name}[/]", id="model-badge")

        yield VerticalScroll(id="chat-scroll")

        with Vertical(id="composer-container"):
            yield Vertical(id="suggestions-box")
            yield CommandInput(
                placeholder="> Ask SOM-SCAN anything, run $ cmd, /scan target, /help...",
                id="input-box"
            )
            with Horizontal(id="footer-bar"):
                yield Label("/help · /resume · /scan · /tools · /new · /copy · /focus · /quit", id="shortcut-hints")
                yield Label(f"[bold #0284c7]v{__version__}[/]", id="version-pill")
                yield Label("READY", id="status-pill")

    def on_mount(self):
        try:
            inp = self.query_one("#input-box", CommandInput)
            inp.focus()
        except Exception:
            pass
        self._spinner_timer = self.set_interval(0.08, self._tick_spinner)

        # Restore preserved conversation items if recovering from a trapped exception
        if self._preserved_history:
            try:
                scroll = self.query_one("#chat-scroll", VerticalScroll)
                for item in self._preserved_history:
                    if item.startswith("> You\n"):
                        u_text = item[6:].strip()
                        u_box = Vertical(
                            Label("> You", classes="user-marker", markup=False),
                            Static(u_text, classes="user-text", markup=False),
                            classes="user-box",
                        )
                        scroll.mount(u_box)
                    elif item.startswith("[*] SOM-SCAN\n"):
                        a_text = item[13:].strip()
                        self._mount_formatted_assistant_message(scroll, a_text)
                    elif item.startswith("[Command] $ "):
                        parts = item.split("\n", 2)
                        cmd_line = parts[0][12:].strip()
                        out_line = parts[2] if len(parts) > 2 else ""
                        card = CommandCard(cmd_line)
                        card.update_result(0, out_line)
                        self._command_cards.append(card)
                        scroll.mount(card)
                    elif item.startswith("[Error Boundary:"):
                        err_card = Vertical(
                            Label("⚠️ [bold #ef4444]PREVIOUS SESSION TRAPPED EXCEPTION[/]", classes="error-boundary-title"),
                            Static(item, classes="error-boundary-msg", markup=False),
                            classes="error-boundary-card"
                        )
                        scroll.mount(err_card)
                scroll.scroll_end(animate=False)
            except Exception:
                pass

        if self._initial_trapped_error:
            err_title, err_tb = self._initial_trapped_error
            self._initial_trapped_error = None
            self.set_timer(0.1, lambda: self._show_error_boundary_str(err_title, err_tb))

        if self._initial_input:
            init_cmd = self._initial_input
            self._initial_input = None
            if not init_cmd.startswith("/") and not init_cmd.startswith("$") and not init_cmd.startswith("run ") and not init_cmd.startswith("http") and "." in init_cmd and " " not in init_cmd:
                init_cmd = f"/scan {init_cmd}"
            self.set_timer(0.2, lambda: self.submit_text(init_cmd))

    def on_resize(self, event):
        """Keep layout responsive across all terminal dimensions and window resizes."""
        try:
            scroll = self.query_one("#chat-scroll", VerticalScroll)
            if self._auto_scroll:
                scroll.scroll_end(animate=False)
        except Exception:
            pass

    def _tick_spinner(self):
        try:
            self._spinner_idx = (self._spinner_idx + 1) % len(SPINNER_FRAMES)
            frame = SPINNER_FRAMES[self._spinner_idx]

            if self._thinking_widget is not None:
                self._thinking_widget.update(f"{frame} {self._thinking_label}")

            if self._current_command_card is not None and self._current_command_card.returncode is None:
                self._current_command_card.tick_spinner(frame)

            if self._current_status_text in ("THINKING…", "RUNNING…", "SCANNING…", "PAUSED"):
                pill = self.query_one("#status-pill", Label)
                color_map = {
                    "green": "#22c55e",
                    "purple": "#c084fc",
                    "cyan": "#38bdf8",
                    "yellow": "#eab308",
                    "red": "#ef4444"
                }
                c = color_map.get(self._current_status_color, "#38bdf8")
                pill.update(f"[{c}]{frame} {self._current_status_text}[/]")
        except Exception:
            pass


    # ────────────────────────────────────────────────────────────────
    # Slash Command Suggestions Autocomplete Engine
    # ────────────────────────────────────────────────────────────────

    def on_input_changed(self, event: Input.Changed):
        val = event.value
        if val.startswith("/") and " " not in val:
            prefix = val.lower()
            matches = [item for item in SLASH_COMMANDS if item[0].lower().startswith(prefix)]
            if matches:
                self._show_suggestions(matches)
                return
        self.hide_suggestions()

    def _show_suggestions(self, matches: List[Tuple[str, str]]):
        self._matching_suggestions = matches
        self.suggestions_visible = True
        self.suggestion_selected_index = 0
        try:
            box = self.query_one("#suggestions-box", Vertical)
            box.styles.display = "block"
            self._render_suggestions()
        except Exception:
            pass

    def _render_suggestions(self):
        try:
            box = self.query_one("#suggestions-box", Vertical)
        except Exception:
            return
        box.remove_children()
        for idx, (cmd, desc) in enumerate(self._matching_suggestions[:7]):
            line_text = f"{cmd.split()[0]:<16}  {desc}"
            if idx == self.suggestion_selected_index:
                lbl = Label(f"▸ {line_text}", classes="sugg-item-selected", markup=False)
            else:
                lbl = Label(f"  {line_text}", classes="sugg-item", markup=False)
            box.mount(lbl)

    def hide_suggestions(self):
        self.suggestions_visible = False
        self.suggestion_selected_index = -1
        self._matching_suggestions = []
        try:
            box = self.query_one("#suggestions-box", Vertical)
            box.styles.display = "none"
            box.remove_children()
        except Exception:
            pass

    def suggestion_prev(self):
        if self._matching_suggestions:
            self.suggestion_selected_index = (self.suggestion_selected_index - 1) % len(self._matching_suggestions[:7])
            self._render_suggestions()

    def suggestion_next(self):
        if self._matching_suggestions:
            self.suggestion_selected_index = (self.suggestion_selected_index + 1) % len(self._matching_suggestions[:7])
            self._render_suggestions()

    def suggestion_accept(self):
        if self._matching_suggestions and 0 <= self.suggestion_selected_index < len(self._matching_suggestions):
            chosen = self._matching_suggestions[self.suggestion_selected_index][0].split()[0]
            inp = self.query_one("#input-box", CommandInput)
            inp.value = chosen + " "
            inp.cursor_position = len(inp.value)
            self.hide_suggestions()

    def history_prev(self, inp: CommandInput) -> bool:
        """Recall previous command from history (Up arrow)."""
        if not self._input_history:
            return False
        if self._input_history_idx == -1:
            self._input_history_idx = len(self._input_history) - 1
        elif self._input_history_idx > 0:
            self._input_history_idx -= 1
        else:
            return True
        val = self._input_history[self._input_history_idx]
        inp.value = val
        inp.cursor_position = len(val)
        return True

    def history_next(self, inp: CommandInput) -> bool:
        """Recall next command from history (Down arrow)."""
        if not self._input_history or self._input_history_idx == -1:
            return False
        if self._input_history_idx < len(self._input_history) - 1:
            self._input_history_idx += 1
            val = self._input_history[self._input_history_idx]
            inp.value = val
            inp.cursor_position = len(val)
        else:
            self._input_history_idx = -1
            inp.value = ""
            inp.cursor_position = 0
        return True

    @property
    def _is_in_pause_screen(self) -> bool:
        if getattr(self, "_in_pause_menu", False):
            return True
        try:
            return isinstance(self.screen, PauseMenuScreen)
        except Exception:
            return False

    def on_click(self, event) -> None:
        """Guarantee typing area is focused whenever the operator clicks anywhere in the window."""
        try:
            if not self._is_in_pause_screen:
                inp = self.query_one("#input-box", CommandInput)
                inp.focus()
        except Exception:
            pass

    def on_key(self, event) -> None:
        """
        Guarantee keyboard typing is never blocked:
        If operator presses any printable key or backspace while #input-box is unfocused,
        immediately refocus #input-box and forward the keystroke.
        """
        try:
            if self._is_in_pause_screen:
                return

            focused = self.focused
            inp = self.query_one("#input-box", CommandInput)
            if focused is inp:
                return

            if event.character and event.character.isprintable():
                inp.focus()
                inp.value = inp.value + event.character
                inp.cursor_position = len(inp.value)
                event.prevent_default()
                event.stop()
            elif event.key == "backspace":
                inp.focus()
                if inp.value:
                    inp.value = inp.value[:-1]
                    inp.cursor_position = len(inp.value)
                event.prevent_default()
                event.stop()
            elif event.key == "enter":
                inp.focus()
        except Exception:
            pass

    # ────────────────────────────────────────────────────────────────
    # Application-Wide Error Boundary
    # ────────────────────────────────────────────────────────────────

    def _handle_exception(self, error: Exception) -> None:
        """Application-Wide Error Boundary: Catch unhandled UI, event, or syntax exceptions
        and render them clearly in the chat stream instead of crashing the CLI."""
        import traceback
        tb = traceback.format_exc()
        self._show_error_boundary(error, tb)

    def _show_error_boundary(self, error: Exception, tb_str: str):
        """Render a dedicated, styled error card inside the chat stream without terminating."""
        err_type = type(error).__name__
        err_msg = str(error) or "(no error message)"
        self._show_error_boundary_str(f"{err_type}: {err_msg}", tb_str)

    def _show_error_boundary_str(self, err_title: str, tb_str: str):
        """Render trapped error card with CodeBubble traceback directly in the chat scroll."""
        lines = [l.strip() for l in tb_str.strip().splitlines() if l.strip()]
        relevant_trace = "\n".join(lines[-6:]) if len(lines) > 6 else tb_str

        # Reset dangling UI states
        if self._thinking_widget is not None:
            try:
                p = self._thinking_widget.parent
                if p:
                    p.remove()
            except Exception:
                pass
            self._thinking_widget = None

        if self._streaming_box is not None:
            try:
                self._streaming_box.remove()
            except Exception:
                pass
            self._streaming_box = None
            self._streaming_text_widget = None
            self._streaming_accumulated_text = ""

        try:
            scroll = self.query_one("#chat-scroll", VerticalScroll)
            tb_bubble = CodeBubble(code=relevant_trace, language="traceback", title="◈ TRACEBACK EXCEPTION LOG")
            self._code_bubbles.append(tb_bubble)
            err_card = Vertical(
                Label(f"⚠️ [bold #ef4444]ERROR BOUNDARY TRAPPED EXCEPTION[/] · [white]{err_title}[/]", classes="error-boundary-title"),
                Static(f"**Error Details:** `{err_title}`", classes="error-boundary-msg"),
                tb_bubble,
                Label("Session state preserved. You can continue typing commands, chatting, or troubleshooting.", classes="command-header"),
                classes="error-boundary-card"
            )
            scroll.mount(err_card)
            scroll.scroll_end(animate=False)
        except Exception:
            pass

        self._conversation_history.append(f"[Error Boundary: {err_title}]")
        self._safe_handle_event(StatusChangeEvent("READY", "yellow"))

    def _mount_formatted_assistant_message(self, scroll: Optional[VerticalScroll], text: str):
        """Render assistant message with narrative text and dedicated Cyan & Pink CodeBubbles."""
        if scroll is None or not text.strip():
            return

        # 1. Parse fenced code blocks ```lang ... ```
        if "```" in text:
            parts = re.split(r"(```[a-zA-Z0-9_\-]*\n.*?```)", text, flags=re.DOTALL)
            for part in parts:
                p = part.strip()
                if not p:
                    continue
                if p.startswith("```") and p.endswith("```"):
                    lines = p.splitlines()
                    lang = lines[0][3:].strip() or "code"
                    code_body = "\n".join(lines[1:-1])
                    bubble = CodeBubble(code=code_body, language=lang)
                    self._code_bubbles.append(bubble)
                    scroll.mount(bubble)
                else:
                    a_box = Vertical(
                        Label("[*] SOM-SCAN", classes="assistant-marker", markup=False),
                        SafeMarkdown(p, classes="assistant-text"),
                        classes="assistant-box",
                    )
                    scroll.mount(a_box)
            return

        # 2. Plain code detection (multi-line scripts without markdown fences)
        code_markers = (
            "import ", "from ", "def ", "class ", "#!/", "curl ",
            "$ ", "function ", "const ", "let ", "var ", "select ", "SELECT "
        )
        lines = text.strip().splitlines()
        first_line = lines[0].strip() if lines else ""
        if len(lines) >= 3 and any(first_line.startswith(m) for m in code_markers):
            bubble = CodeBubble(code=text, language="code", title="◈ PLAIN CODE BUBBLE")
            self._code_bubbles.append(bubble)
            scroll.mount(bubble)
            return

        # 3. Standard narrative message
        a_box = Vertical(
            Label("[*] SOM-SCAN", classes="assistant-marker", markup=False),
            SafeMarkdown(text, classes="assistant-text"),
            classes="assistant-box",
        )
        scroll.mount(a_box)


    # ────────────────────────────────────────────────────────────────
    # Event Bridge
    # ────────────────────────────────────────────────────────────────

    def _on_agent_event(self, event: AgentEvent):
        # Prevent "RuntimeError: The 'call_from_thread' method must run in a different thread from the app"
        thread_id = getattr(self, "_thread_id", None)
        if thread_id is not None and threading.get_ident() == thread_id:
            self._handle_event(event)
        elif getattr(self, "_running", False):
            try:
                self.call_from_thread(self._handle_event, event)
            except RuntimeError:
                self._handle_event(event)
        else:
            self._handle_event(event)

    def _handle_event(self, event: AgentEvent):
        try:
            self._safe_handle_event(event)
        except Exception as e:
            import traceback
            self._show_error_boundary(e, traceback.format_exc())

    def _safe_handle_event(self, event: AgentEvent):
        try:
            scroll = self.query_one("#chat-scroll", VerticalScroll)
        except Exception:
            scroll = None

        if isinstance(event, UserMessageEvent):
            u_box = Vertical(
                Label("> You", classes="user-marker", markup=False),
                Static(event.text, classes="user-text", markup=False),
                classes="user-box",
            )
            if scroll is not None:
                scroll.mount(u_box)
            self._conversation_history.append(f"> You\n{event.text}")

        elif isinstance(event, ThinkingStartEvent):
            self._thinking_label = event.label or "Thinking…"
            if self._thinking_widget is None:
                self._thinking_widget = Label(
                    f"{SPINNER_FRAMES[self._spinner_idx]} {self._thinking_label}",
                    classes="thinking-text",
                    markup=False,
                )
                t_box = Vertical(self._thinking_widget, classes="thinking-box")
                if scroll is not None:
                    scroll.mount(t_box)

        elif isinstance(event, ThinkingStopEvent):
            if self._thinking_widget is not None:
                try:
                    p = self._thinking_widget.parent
                    if p:
                        p.remove()
                except Exception:
                    pass
                self._thinking_widget = None

        elif isinstance(event, AssistantChunkEvent):
            if self._thinking_widget is not None:
                self._handle_event(ThinkingStopEvent())

            self._streaming_accumulated_text += event.chunk
            clean_chunk_text = strip_directives(self._streaming_accumulated_text)

            if clean_chunk_text:
                if self._streaming_box is None:
                    self._streaming_text_widget = Static("", classes="assistant-text", markup=False)
                    self._streaming_box = Vertical(
                        Label("[*] SOM-SCAN", classes="assistant-marker", markup=False),
                        self._streaming_text_widget,
                        classes="assistant-box",
                    )
                    if scroll is not None:
                        scroll.mount(self._streaming_box)

                if self._streaming_text_widget:
                    self._streaming_text_widget.update(clean_chunk_text)

        elif isinstance(event, AssistantMessageEvent):
            self._handle_event(ThinkingStopEvent())
            raw_text = event.text or self._streaming_accumulated_text
            clean_text = strip_directives(raw_text)

            if self._streaming_box is not None:
                try:
                    self._streaming_box.remove()
                except Exception:
                    pass
                self._streaming_box = None
                self._streaming_text_widget = None
                self._streaming_accumulated_text = ""

            if clean_text.strip():
                self._mount_formatted_assistant_message(scroll, clean_text)
                self._conversation_history.append(f"[*] SOM-SCAN\n{clean_text}")


        elif isinstance(event, CommandStartEvent):
            self._handle_event(ThinkingStopEvent())
            card = CommandCard(event.command)
            self._current_command_card = card
            self._command_cards.append(card)
            if scroll is not None:
                scroll.mount(card)

        elif isinstance(event, CommandFinishEvent):
            if self._current_command_card:
                self._current_command_card.update_result(event.returncode, event.output)
                self._conversation_history.append(
                    f"[Command] $ {event.command}\n[Exit {event.returncode}]\n{event.output}"
                )
                self._current_command_card = None

        elif isinstance(event, FindingEvent):
            sev_prefix = f"[{event.severity.upper()} FINDING]"
            title_text = f"{sev_prefix} {event.title or 'Finding'}"
            children = [Label(title_text, classes="finding-title", markup=False)]
            finding_log = title_text
            if event.evidence:
                children.append(Static(event.evidence, classes="finding-evidence", markup=False))
                finding_log += f"\nEvidence: {event.evidence}"
            f_box = Vertical(*children, classes="finding-card")
            if scroll is not None:
                scroll.mount(f_box)
            self._conversation_history.append(finding_log)

        elif isinstance(event, TaskCompleteEvent):
            self._handle_event(ThinkingStopEvent())
            clean_status = event.status or "Task completed"
            while clean_status.startswith("✓") or clean_status.startswith("✗") or clean_status.startswith("●"):
                clean_status = clean_status[1:].strip()
            mark = "✓" if event.success else "✗"
            status_text = f"{mark} {clean_status}"
            if event.success:
                status_lbl = Label(status_text, classes="task-complete", markup=False)
            else:
                status_lbl = Label(status_text, classes="task-failed", markup=False)
            status_box = Vertical(status_lbl, classes="task-status-box")
            if scroll is not None:
                scroll.mount(status_box)
            self._conversation_history.append(f"[{status_text}]")
            try:
                self.query_one("#input-box", CommandInput).focus()
            except Exception:
                pass

        elif isinstance(event, TaskCancelledEvent):
            self._handle_event(ThinkingStopEvent())
            cancel_text = f"⚠ {event.message or 'Task cancelled'}"
            cancel_lbl = Label(cancel_text, classes="task-cancelled", markup=False)
            status_box = Vertical(cancel_lbl, classes="task-status-box")
            if scroll is not None:
                scroll.mount(status_box)
            self._conversation_history.append(f"[{cancel_text}]")
            try:
                self.query_one("#input-box", CommandInput).focus()
            except Exception:
                pass

        elif isinstance(event, ErrorEvent):
            self._handle_event(ThinkingStopEvent())
            err_text = f"✗ Error: {event.error or 'Unknown error'}"
            err_lbl = Label(err_text, classes="task-failed", markup=False)
            status_box = Vertical(err_lbl, classes="task-status-box")
            if scroll is not None:
                scroll.mount(status_box)
            self._conversation_history.append(f"[{err_text}]")
            try:
                self.query_one("#input-box", CommandInput).focus()
            except Exception:
                pass

        elif isinstance(event, StatusChangeEvent):
            self._current_status_text = event.status
            self._current_status_color = event.color
            try:
                pill = self.query_one("#status-pill", Label)
                color_map = {
                    "green": "#22c55e",
                    "purple": "#c084fc",
                    "cyan": "#38bdf8",
                    "yellow": "#eab308",
                    "red": "#ef4444"
                }
                c = color_map.get(event.color, "#22c55e")
                pill.update(f"[{c}]{event.status}[/]")
            except Exception:
                pass

        try:
            model_badge = self.query_one("#model-badge", Label)
            model_badge.update(f"[#38bdf8]{self.model_manager.display_name}[/]")
        except Exception:
            pass

        if scroll is not None and self._auto_scroll:
            scroll.scroll_end(animate=False)

    # ────────────────────────────────────────────────────────────────
    # Input Submission & Live Steering
    # ────────────────────────────────────────────────────────────────

    def on_input_submitted(self, event: Input.Submitted):
        try:
            self._safe_input_submitted(event)
        except Exception as e:
            import traceback
            self._show_error_boundary(e, traceback.format_exc())

    def _safe_input_submitted(self, event: Input.Submitted):
        self.submit_text(event.value)

    def submit_text(self, text: str):
        text = (text or "").strip()
        self.hide_suggestions()
        if not text:
            return

        inp = None
        try:
            inp = self.query_one("#input-box", CommandInput)
            inp.value = ""
        except Exception:
            pass

        if text:
            if not self._input_history or self._input_history[-1] != text:
                self._input_history.append(text)
            self._input_history_idx = -1

        # 1. Local Immediate Commands (always execute, never blocked)
        if text in ("/new", "/reset", "/fresh"):
            self._archive_and_reset_session()
            return

        if text in ("/clear", "/cls"):
            try:
                scroll = self.query_one("#chat-scroll", VerticalScroll)
                scroll.remove_children()
            except Exception:
                pass
            self._conversation_history.clear()
            self._command_cards.clear()
            self._code_bubbles.clear()
            return

        if text in ("/quit", "/q"):
            self._explicit_quit = True
            self.exit()
            return

        if text in ("/focus", "/f"):
            self._auto_scroll = True
            if inp:
                inp.focus()
            try:
                scroll = self.query_one("#chat-scroll", VerticalScroll)
                scroll.scroll_end(animate=False)
            except Exception:
                pass
            self._handle_event(StatusChangeEvent("READY", "green"))
            return

        if text == "/long":
            for c in self._command_cards:
                c.toggle_expand(True)
            for b in self._code_bubbles:
                b.toggle_expand(True)
            self._handle_event(StatusChangeEvent("READY", "green"))
            return

        if text == "/short":
            for c in self._command_cards:
                c.toggle_expand(False)
            for b in self._code_bubbles:
                b.toggle_expand(False)
            self._handle_event(StatusChangeEvent("READY", "green"))
            return

        if text in ("/copy", "/c", "/export"):
            self._copy_conversation()
            return

        if text in ("/pause", "/p"):
            self.action_interrupt_task()
            return

        if text in ("/cancel", "/stop"):
            self.router.cancel()
            return

        if text in ("/status", "/stats"):
            self._show_active_status()
            return

        # 2. Mid-Scan Live Operator Directive Injection (Typing box never locks!)
        if self.router.is_busy:
            self._handle_event(UserMessageEvent(text=f"[Injected Directive]: {text}"))
            self.router.inject_operator_message(text)
            return

        # 3. Normal Dispatch when idle
        self._handle_event(UserMessageEvent(text=text))
        self.router.dispatch(text)

    def _archive_and_reset_session(self):
        """Archive current assessment, save chat history, and reset UI & router to fresh state."""
        self._copy_conversation()
        try:
            scroll = self.query_one("#chat-scroll", VerticalScroll)
            scroll.remove_children()
        except Exception:
            pass
        self._conversation_history.clear()
        self._command_cards.clear()
        self._code_bubbles.clear()
        archived = self.router.reset_session()
        greeting = (
            f"🔄 **Fresh Assessment Session Started**\n\n"
            f"- Previous session saved to: `somscan_session.log`\n"
            f"- Assessment state archived: `{archived}`\n"
            f"- Workspace and target reset. Ready for an authorized assessment, exploit chain, or dev task.\n\n"
            f"Type `/scan <target>` to begin an assessment, or enter your objective directly."
        )
        self._handle_event(AssistantMessageEvent(greeting))
        self._handle_event(StatusChangeEvent("READY", "green"))

    def _show_active_status(self):
        summary = self.router.get_active_summary()
        tgt = summary.get("target", "None")
        phase = summary.get("phase", "Idle")
        turns = summary.get("turn", 0)
        endpoints = summary.get("endpoints", 0)
        findings = summary.get("findings", 0)
        busy = "Running" if summary.get("is_busy") else "Idle"
        paused = " [PAUSED]" if summary.get("is_paused") else ""

        status_card = (
            f"**SOM-SCAN Status Overview{paused}**\n\n"
            f"- **Target:** `{tgt}`\n"
            f"- **State:** `{busy}`\n"
            f"- **Phase:** `{phase}`\n"
            f"- **Turn:** `{turns}`\n"
            f"- **Mapped Endpoints:** `{endpoints}`\n"
            f"- **Confirmed Findings:** `{findings}`\n"
            f"- **Active Model:** `{self.model_manager.display_name}`"
        )
        self._handle_event(AssistantMessageEvent(status_card))

    def _copy_conversation(self):
        items = list(self._conversation_history)
        if self._current_command_card and self._current_command_card.returncode is None:
            items.append(f"[Command] $ {self._current_command_card.command}\n[Running...]")

        if not items:
            self._handle_event(AssistantMessageEvent("Chat area is empty — nothing to copy."))
            return

        full_text = "\n\n".join(items)
        export_file = pathlib.Path.cwd() / "somscan_session.log"
        file_saved = False
        try:
            export_file.write_text(full_text, encoding="utf-8")
            file_saved = True
        except Exception:
            pass

        copied = copy_to_system_clipboard(full_text)
        lines_count = len(full_text.splitlines())
        chars_count = len(full_text)

        if copied and file_saved:
            msg = f"✓ Copied entire chat area ({lines_count} lines, {chars_count} chars) to clipboard & saved to `{export_file.name}`"
        elif copied:
            msg = f"✓ Copied entire chat area ({lines_count} lines, {chars_count} chars) to clipboard."
        elif file_saved:
            msg = f"⚠ Clipboard unavailable. Saved entire chat history ({lines_count} lines) to `{export_file.resolve()}`"
        else:
            msg = "✗ Failed to copy chat history to clipboard or file."

        self._handle_event(AssistantMessageEvent(msg))

    # ────────────────────────────────────────────────────────────────
    # Ctrl+C Pause Menu Modal
    # ────────────────────────────────────────────────────────────────

    def action_interrupt_task(self):
        """Ctrl+C handler: pauses active task & opens pause menu, or cleanly notifies when idle; NEVER kills CLI."""
        if self._is_in_pause_screen:
            return

        # If no task or command is active, clear composer if populated or provide a clean toast notification
        if not self.router.is_busy:
            try:
                inp = self.query_one("#input-box", CommandInput)
                if inp.value:
                    inp.value = ""
            except Exception:
                pass
            try:
                if self.is_running:
                    self.notify("No active task. Press Ctrl+Q or type /quit to exit.", title="SOM-SCAN", timeout=3)
            except Exception:
                pass
            return

        self._in_pause_menu = True
        try:
            self.router.pause()
            summary = self.router.get_active_summary()
            self.push_screen(PauseMenuScreen(summary=summary), self._on_pause_menu_result)
        except Exception:
            self._in_pause_menu = False

    def _on_pause_menu_result(self, action: Optional[str]):
        self._in_pause_menu = False
        try:
            inp = self.query_one("#input-box", CommandInput)
            inp.focus()
        except Exception:
            pass

        if not action or action == "continue":
            if self.router.is_busy:
                self.router.resume()
            else:
                self._handle_event(StatusChangeEvent("READY", "green"))
            return

        if action == "stop":
            self.router.cancel()
            return

        if action == "message":
            if self.router.is_busy:
                self.router.resume()
            self._handle_event(AssistantMessageEvent(
                "💬 **Message / Directive Mode:** Enter steering instructions or message in the composer below."
            ))
            return

        if action == "focus":
            self._show_active_status()
            try:
                scroll = self.query_one("#chat-scroll", VerticalScroll)
                scroll.scroll_end(animate=False)
            except Exception:
                pass
            return

        if action == "copy":
            self._copy_conversation()
            return

        if action == "new":
            self._archive_and_reset_session()
            return

        if action == "quit":
            self._explicit_quit = True
            self.exit()

    def action_quit_app(self):
        """Ctrl+Q handler: cleanly exit application."""
        self._explicit_quit = True
        self.exit()


# ────────────────────────────────────────────────────────────────────
# OS-Level Ctrl+C Signal Guard & Terminal State Management
# ────────────────────────────────────────────────────────────────────

_ACTIVE_APP: Optional["SomScanApp"] = None
_CTRL_HANDLER_INSTALLED = False
_CONSOLE_CTRL_HANDLER_REF: Any = None
_ORIGINAL_CONSOLE_MODE_IN: Optional[int] = None
_ORIGINAL_CONSOLE_MODE_OUT: Optional[int] = None


def _save_original_console_modes():
    """Capture initial console modes before any TUI modifications."""
    global _ORIGINAL_CONSOLE_MODE_IN, _ORIGINAL_CONSOLE_MODE_OUT
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes
            kernel32 = ctypes.windll.kernel32
            hIn = kernel32.GetStdHandle(-10)   # STD_INPUT_HANDLE
            hOut = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mIn = wintypes.DWORD()
            mOut = wintypes.DWORD()
            if kernel32.GetConsoleMode(hIn, ctypes.byref(mIn)):
                _ORIGINAL_CONSOLE_MODE_IN = mIn.value
            if kernel32.GetConsoleMode(hOut, ctypes.byref(mOut)):
                _ORIGINAL_CONSOLE_MODE_OUT = mOut.value
        except Exception:
            pass


def _setup_console_ctrl_c_guard(app: "SomScanApp"):
    global _ACTIVE_APP, _CTRL_HANDLER_INSTALLED, _CONSOLE_CTRL_HANDLER_REF
    _ACTIVE_APP = app

    # 1. Ignore Python SIGINT so KeyboardInterrupt never escapes app.run() on main thread
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except Exception:
        pass

    if _CTRL_HANDLER_INSTALLED:
        return

    # 2. Native Windows Console Handler (Kernel32)
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            HandlerRoutine = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)

            def _console_ctrl_handler(ctrl_type: int) -> bool:
                # 0 = CTRL_C_EVENT, 1 = CTRL_BREAK_EVENT
                if ctrl_type in (0, 1):
                    target_app = _ACTIVE_APP
                    if target_app is not None and getattr(target_app, "is_running", False):
                        loop = getattr(target_app, "_loop", None)
                        if loop is not None and loop.is_running():
                            try:
                                loop.call_soon_threadsafe(target_app.action_interrupt_task)
                            except Exception:
                                pass
                    return True  # Handled! Prevents Windows OS from terminating CLI process
                return False

            # Keep a permanent module-level reference to the C callback function pointer
            # so that Python GC NEVER deallocates the callback thunk!
            _CONSOLE_CTRL_HANDLER_REF = HandlerRoutine(_console_ctrl_handler)
            ctypes.windll.kernel32.SetConsoleCtrlHandler(_CONSOLE_CTRL_HANDLER_REF, True)
        except Exception:
            pass

    _CTRL_HANDLER_INSTALLED = True


def _reset_terminal_state():
    """Ensure terminal mouse tracking, screen buffer, and cursor modes are completely reset to normal."""
    # 1. Output comprehensive reset ANSI sequence to sys.__stdout__ (bypassing any Python redirection)
    try:
        out = sys.__stdout__
        if out is not None and not getattr(out, "closed", False):
            # Disable mouse tracking (1000, 1002, 1003, 1004, 1006, 1015), bracketed paste (2004),
            # kitty keyboard protocol (<u), leave alternate screen (1049l), show cursor (25h), reset color (0m)
            out.write("\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1004l\x1b[?1006l\x1b[?1015l\x1b[?2004l\x1b[<u\x1b[?1049l\x1b[?25h\x1b[0m\r\n")
            out.flush()
    except Exception:
        pass

    # 2. Restore native Windows Console modes
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            hIn = kernel32.GetStdHandle(-10)
            hOut = kernel32.GetStdHandle(-11)
            if _ORIGINAL_CONSOLE_MODE_IN is not None:
                kernel32.SetConsoleMode(hIn, _ORIGINAL_CONSOLE_MODE_IN)
            else:
                # Fallback to standard console input flags: PROCESSED | LINE | ECHO | QUICK_EDIT (0x01f7 / 0x0007)
                kernel32.SetConsoleMode(hIn, 0x0007)

            if _ORIGINAL_CONSOLE_MODE_OUT is not None:
                kernel32.SetConsoleMode(hOut, _ORIGINAL_CONSOLE_MODE_OUT)
            else:
                # Fallback to standard console output flags: PROCESSED | WRAP_AT_EOL (0x0003)
                kernel32.SetConsoleMode(hOut, 0x0003)
        except Exception:
            pass


def run_tui(initial_input: Optional[str] = None):
    """Main entrypoint to run SOM-SCAN Terminal UI with total crash immunity."""
    global _ACTIVE_APP
    import atexit
    _save_original_console_modes()
    atexit.register(_reset_terminal_state)

    last_history: List[str] = []
    saved_router: Optional[AgentRouter] = None
    saved_model_manager: Optional[ModelManager] = None
    pending_error: Optional[Tuple[str, str]] = None

    app = SomScanApp(initial_input=initial_input)
    _ACTIVE_APP = app
    _setup_console_ctrl_c_guard(app)

    while True:
        try:
            app.run()
            # If app exited normally via explicit quit (/quit or modal Quit or Ctrl+Q)
            if getattr(app, "_explicit_quit", False):
                _reset_terminal_state()
                break
            # If app stopped unexpectedly without explicit quit, restore state & recreate
            _reset_terminal_state()
            try:
                last_history = list(getattr(app, "_conversation_history", []))
                saved_router = getattr(app, "router", None)
                saved_model_manager = getattr(app, "model_manager", None)
                app = SomScanApp(
                    preserved_history=last_history,
                    preserved_router=saved_router,
                    preserved_model_manager=saved_model_manager,
                )
                _ACTIVE_APP = app
                _setup_console_ctrl_c_guard(app)
                continue
            except Exception:
                break
        except KeyboardInterrupt:
            # Under NO circumstance does Ctrl+C terminate the CLI!
            # The only way to exit is /quit (or selecting Quit in modal / Ctrl+Q).
            _reset_terminal_state()
            if getattr(app, "_explicit_quit", False):
                break
            # Recreate fresh app with preserved state — NEVER call app.run() again on the same app instance!
            try:
                last_history = list(getattr(app, "_conversation_history", []))
                saved_router = getattr(app, "router", None)
                saved_model_manager = getattr(app, "model_manager", None)
                app = SomScanApp(
                    preserved_history=last_history,
                    preserved_router=saved_router,
                    preserved_model_manager=saved_model_manager,
                )
                _ACTIVE_APP = app
                _setup_console_ctrl_c_guard(app)
                continue
            except Exception:
                break
        except Exception as e:
            # TOTAL CRASH IMMUNITY: Trapped unhandled exception outside or inside app.run()!
            import traceback
            tb = traceback.format_exc()
            _reset_terminal_state()

            # Preserve conversation history and router state
            try:
                last_history = list(getattr(app, "_conversation_history", []))
                saved_router = getattr(app, "router", None)
                saved_model_manager = getattr(app, "model_manager", None)
            except Exception:
                pass

            pending_error = (f"{type(e).__name__}: {e}", tb)

            # Recreate app instance with preserved state and show error card in chat
            try:
                time.sleep(0.15)
                app = SomScanApp(
                    preserved_history=last_history,
                    preserved_router=saved_router,
                    preserved_model_manager=saved_model_manager,
                    initial_trapped_error=pending_error,
                )
                _ACTIVE_APP = app
                _setup_console_ctrl_c_guard(app)
                pending_error = None
                continue
            except Exception:
                _reset_terminal_state()
                break



if __name__ == "__main__":
    run_tui()
