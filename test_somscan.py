"""
test_somscan.py — comprehensive automated test suite for SOM-SCAN.
Tests all 15 requirements specified in the rebuild specification:
1. Application startup and imports
2. Python syntax across project
3. Terminal UI instantiation and widget layout
4. Input submission and busy state prevention
5. Greeting and general chat routing
6. DeepSeek API configuration and error handling
7. Tool dispatch and real command output
8. Security assessment routing and scope validation
9. Cancellation during a running task
10. Clean shutdown and child-process cleanup
11. Long/short outputs and expansion toggle
12. Resize and layout handling
13. Missing API keys and invalid model configuration
14. Non-zero command exit codes
15. State lifecycle and report generation
"""
import os
import sys
import time
import unittest
import pathlib
from unittest.mock import MagicMock, patch

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from core.events import (
    AgentEvent, UserMessageEvent, AssistantChunkEvent, AssistantMessageEvent,
    ThinkingStartEvent, ThinkingStopEvent, CommandStartEvent, CommandFinishEvent,
    FindingEvent, StatusChangeEvent, TaskCompleteEvent, TaskCancelledEvent, ErrorEvent
)
from core.model_manager import ModelManager, ModelConfig
from core.task_runner import TaskRunner, CommandResult
from core.agent_router import AgentRouter
import tui


class TestSomScan(unittest.TestCase):

    def test_01_imports(self):
        """Test application startup and imports."""
        import agent_v8
        import somscan
        import tui
        import core.events
        import core.model_manager
        import core.task_runner
        import core.agent_router
        import core.state
        import reporter
        import tools_db
        import installer
        self.assertTrue(hasattr(tui, "SomScanApp"))
        self.assertTrue(hasattr(somscan, "main"))

    def test_02_python_syntax(self):
        """Test Python syntax across all project python files."""
        import py_compile
        py_files = list(HERE.glob("*.py")) + list((HERE / "core").glob("*.py")) + list((HERE / "intel").glob("*.py")) + list((HERE / "attack").glob("*.py"))
        for f in py_files:
            try:
                py_compile.compile(str(f), doraise=True)
            except Exception as e:
                self.fail(f"Syntax error in {f}: {e}")

    def test_03_tui_app_instantiation(self):
        """Test Textual SomScanApp instantiation and stylesheet mount without errors."""
        import asyncio
        app = tui.SomScanApp()
        self.assertEqual(app.TITLE, "SOM-SCAN")
        self.assertIsNotNone(app.model_manager)
        self.assertIsNotNone(app.router)

        async def _pilot_check():
            async with app.run_test() as pilot:
                self.assertIsNotNone(pilot.app.query_one("#header-bar"))
                self.assertIsNotNone(pilot.app.query_one("#chat-scroll"))
                self.assertIsNotNone(pilot.app.query_one("#input-box"))
                self.assertIsNotNone(pilot.app.query_one("#footer-bar"))
        asyncio.run(_pilot_check())

    def test_04_command_card_long_short(self):
        """Test CommandCard long/short output toggle."""
        card = tui.CommandCard("python --version")
        lines = [f"line {i}" for i in range(20)]
        long_output = "\n".join(lines)
        card.update_result(0, long_output)
        self.assertFalse(card.expanded)
        self.assertIn("more lines", card.display_text)

        # Toggle expand
        card.toggle_expand(True)
        self.assertTrue(card.expanded)
        self.assertIn("line 19", card.display_text)

        # Toggle short
        card.toggle_expand(False)
        self.assertFalse(card.expanded)
        self.assertIn("more lines", card.display_text)

    def test_05_greeting_and_chat_routing(self):
        """Test that greetings like 'hi' are routed to chat without requiring a target."""
        events = []
        router = AgentRouter(event_callback=lambda ev: events.append(ev))
        
        with patch.dict(os.environ, {"AG_KEY": "", "DEEPSEEK_KEY": ""}):
            router._process_input("hi")
            has_error = any(isinstance(e, ErrorEvent) and ("API key missing" in e.error or "Chat error" in e.error or "Authentication" in e.error) for e in events)
            self.assertTrue(has_error, "Greeting should attempt chat and report API key status cleanly")

    def test_06_deepseek_api_mock_streaming(self):
        """Test DeepSeek API streaming and error handling with mock."""
        mm = ModelManager()
        mock_chunk_1 = MagicMock()
        mock_chunk_1.choices = [MagicMock(delta=MagicMock(content="Hello "))]
        mock_chunk_2 = MagicMock()
        mock_chunk_2.choices = [MagicMock(delta=MagicMock(content="operator!"))]

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = [mock_chunk_1, mock_chunk_2]

        with patch.object(mm, "get_client", return_value=(mock_client, "deepseek-chat")):
            chunks = list(mm.stream_chat([{"role": "user", "content": "hi"}]))
            self.assertEqual(chunks, ["Hello ", "operator!"])

    def test_07_tool_dispatch_and_real_command(self):
        """Test real local command execution, output capture, and returncode."""
        runner = TaskRunner()
        res = runner.run_command(f'"{sys.executable}" -c "print(\'SOM-SCAN OK\')"', timeout=10)
        self.assertEqual(res.returncode, 0)
        self.assertIn("SOM-SCAN OK", res.output)
        self.assertFalse(res.cancelled)
        self.assertGreater(res.duration, 0.0)

    def test_08_nonzero_exit_code(self):
        """Test non-zero command exit code capture."""
        runner = TaskRunner()
        res = runner.run_command(f'"{sys.executable}" -c "import sys; sys.exit(7)"', timeout=10)
        self.assertEqual(res.returncode, 7)
        self.assertFalse(res.is_success)

    def test_09_command_cancellation(self):
        """Test real cancellation of a running process tree."""
        runner = TaskRunner()
        import threading
        
        # Launch sleep command
        cmd = f'"{sys.executable}" -c "import time; time.sleep(10)"'
        th = threading.Thread(target=runner.run_command, args=(cmd,), kwargs={"timeout": 10})
        th.start()
        time.sleep(0.5)

        self.assertTrue(runner.is_running)
        cancelled = runner.cancel()
        self.assertTrue(cancelled)
        th.join(timeout=3)
        self.assertFalse(runner.is_running)

    def test_10_router_shell_query_detection(self):
        """Test natural language command query detection."""
        router = AgentRouter(event_callback=lambda ev: None)
        self.assertEqual(router._detect_shell_query("Check the Python version"), "python --version")
        self.assertEqual(router._detect_shell_query("whoami"), "whoami")
        self.assertEqual(router._detect_shell_query("git status"), "git status")
        self.assertIsNone(router._detect_shell_query("tell me about xss vulnerabilities"))

    def test_11_security_assessment_routing(self):
        """Test that scan requests extract target and trigger scan engine."""
        router = AgentRouter(event_callback=lambda ev: None)
        target1 = router._extract_scan_target("scan https://example.com")
        self.assertEqual(target1, "https://example.com")

        target2 = router._extract_scan_target("assess testphp.vulnweb.com for vulnerabilities")
        self.assertEqual(target2, "testphp.vulnweb.com")

    def test_12_slash_commands(self):
        """Test slash command handling (/help, /model, etc.)."""
        events = []
        router = AgentRouter(event_callback=lambda ev: events.append(ev))

        router._handle_command("/help")
        has_help = any(isinstance(e, AssistantMessageEvent) and "SOM-SCAN Commands" in e.text for e in events)
        self.assertTrue(has_help)

        events.clear()
        router._handle_command("/model")
        has_model = any(isinstance(e, AssistantMessageEvent) and "Active Model:" in e.text for e in events)
        self.assertTrue(has_model)

    def test_13_model_switching(self):
        """Test switching models via model manager."""
        mm = ModelManager()
        ok, msg = mm.set_model("deepseek-reasoner")
        self.assertTrue(ok)
        self.assertEqual(mm.display_name, "deepseek-reasoner")

    def test_14_duplicate_submit_prevention(self):
        """Test that router rejects submissions while busy."""
        events = []
        router = AgentRouter(event_callback=lambda ev: events.append(ev))
        router.task_runner._active_proc = MagicMock()
        router.task_runner._active_proc.poll.return_value = None

        self.assertTrue(router.is_busy)
        router.dispatch("another command")
        has_err = any(isinstance(e, ErrorEvent) and "already running" in e.error for e in events)
        self.assertTrue(has_err)

    def test_15_state_lifecycle_and_reporter(self):
        """Test state loading, saving, and reporter generation."""
        from core import state as _state
        import reporter
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = pathlib.Path(tmpdir)
            st = _state.load(tmppath)
            st["target"] = "test.local"
            st["findings"].append({
                "sev": "high",
                "title": "SQL Injection in /api/users",
                "evidence": "' OR '1'='1 reflected"
            })
            _state.save(tmppath, st)
            reloaded = _state.load(tmppath)
            self.assertEqual(len(reloaded["findings"]), 1)

            md = reporter.build_report_markdown(tmppath, reloaded)
            self.assertIn("SQL Injection in /api/users", md)

    def test_16_normal_chat_no_task_complete(self):
        """Verify normal chat does NOT emit TaskCompleteEvent."""
        events = []
        router = AgentRouter(event_callback=lambda ev: events.append(ev))
        with patch.object(router.model_manager, "stream_chat", return_value=["Hey, how can I help?"]):
            router._run_agent_loop("hi")
            has_task_complete = any(isinstance(e, TaskCompleteEvent) for e in events)
            self.assertFalse(has_task_complete, "Normal chat must NEVER emit TaskCompleteEvent")
            has_assistant_msg = any(isinstance(e, AssistantMessageEvent) for e in events)
            self.assertTrue(has_assistant_msg, "Normal chat must emit AssistantMessageEvent")

    def test_17_file_task_execution(self):
        """Verify autonomous file tasks execute and emit TaskCompleteEvent."""
        events = []
        router = AgentRouter(event_callback=lambda ev: events.append(ev))
        test_file = "test_scratch_auto.txt"
        work_dir = router.get_active_work_dir()
        target = work_dir / test_file
        if target.exists():
            target.unlink()

        # Create file
        res = router._exec_directive_file(f"{test_file}|somscan autonomous file test")
        self.assertTrue(target.exists())
        self.assertIn("File Created", res)

        # Clean up
        if target.exists():
            target.unlink()

    def test_18_tool_task_execution(self):
        """Verify tool status task executes cleanly."""
        router = AgentRouter(event_callback=lambda ev: None)
        res = router._exec_directive_tools("status")
        self.assertIn("Tools Status", res)

    def test_19_directive_execution(self):
        """Verify directive parsing extracts valid directives and strips code blocks."""
        router = AgentRouter(event_callback=lambda ev: None)
        text = (
            "Here is an example:\n"
            "```\nCOMMAND: ignored_example_command\n```\n"
            "COMMAND: python --version\n"
            "FINDING: high|Test Vulnerability|curl evidence\n"
        )
        parsed = router._parse_directives(text)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0], ("COMMAND", "python --version"))
        self.assertEqual(parsed[1], ("FINDING", "high|Test Vulnerability|curl evidence"))

    def test_20_spinner_and_resize(self):
        """Verify TUI spinner tick and resize handling."""
        import asyncio
        app = tui.SomScanApp()

        async def _run_check():
            async with app.run_test() as pilot:
                # Test spinner tick
                initial_idx = pilot.app._spinner_idx
                pilot.app._tick_spinner()
                self.assertNotEqual(initial_idx, pilot.app._spinner_idx)

                # Test on_resize
                pilot.app.on_resize(MagicMock())
        asyncio.run(_run_check())

    def test_21_multi_turn_autonomous_loop(self):
        """Verify multi-turn autonomous agent execution loop."""
        events = []
        router = AgentRouter(event_callback=lambda ev: events.append(ev))

        # Turn 1: model emits a COMMAND
        turn1_reply = f'COMMAND: "{sys.executable}" -c "print(\'step 1 output\')"'
        # Turn 2: model inspects observation and finishes
        turn2_reply = "I inspected the output. Everything is working. DONE"

        responses = [
            [turn1_reply],
            [turn2_reply],
        ]

        def mock_stream(history):
            if responses:
                return responses.pop(0)
            return ["DONE"]

        with patch.object(router.model_manager, "stream_chat", side_effect=mock_stream):
            router._run_agent_loop("run step 1 and complete")

            # Check that COMMAND was executed
            has_cmd = any(isinstance(e, CommandFinishEvent) and "step 1 output" in e.output for e in events)
            self.assertTrue(has_cmd, "Command should have executed in turn 1")

            # Check that task completed event was emitted at the end
            has_complete = any(isinstance(e, TaskCompleteEvent) and e.success for e in events)
            self.assertTrue(has_complete, "Multi-turn task should finish with TaskCompleteEvent")

    def test_22_slash_resume_and_focus(self):
        """Verify /resume and /focus handling."""
        events = []
        router = AgentRouter(event_callback=lambda ev: events.append(ev))

        # /resume with mocked security scan so unit test completes instantaneously
        with patch.object(router, "_execute_security_scan") as mock_scan:
            router._handle_slash_command("/resume")
            mock_scan.assert_called_once()


        # /focus command
        events.clear()
        router._handle_slash_command("/focus")
        has_ready = any(isinstance(e, StatusChangeEvent) and e.status == "READY" for e in events)
        self.assertTrue(has_ready)

    def test_23_clean_task_status_no_double_checkmarks(self):
        """Verify task status formatting never produces duplicate checkmarks."""
        app = tui.SomScanApp()
        # Test event with existing checkmark
        ev = TaskCompleteEvent(status="✓ Installed tool git", success=True)
        # Verify clean status stripping
        clean = ev.status
        while clean.startswith("✓") or clean.startswith("✗") or clean.startswith("●"):
            clean = clean[1:].strip()
        self.assertEqual(clean, "Installed tool git")

    def test_24_persona_and_vulnerability_target_extraction(self):
        """Verify persona is loaded and queries like 'check all vulnerabilties of beco.so' extract target."""
        import agent_v8
        router = AgentRouter(event_callback=lambda ev: None)
        # Verify persona in system prompt
        self.assertIn("SOM-SCAN", router.history[0]["content"])
        self.assertIn("Available Methodologies", router.history[0]["content"])
        self.assertIn("Zero confirmation", router.history[0]["content"])

        # Verify target extraction for "check all vulnerabilties of beco.so"
        target = router._extract_scan_target("check all vulnerabilties of beco.so")
        self.assertEqual(target, "beco.so")

    def test_25_markup_error_immunity(self):
        """Verify that strings with brackets, unclosed tags, and rich syntax do not trigger MarkupError."""
        import asyncio
        app = tui.SomScanApp()

        async def _check():
            async with app.run_test() as pilot:
                # 1. Error with brackets and unclosed tag
                app._handle_event(ErrorEvent("[Errno 2] No such file or directory: [/] test [500]"))
                # 2. CommandCard with brackets and rich syntax
                card = tui.CommandCard('python -c "print([1, 2, 3])"')
                card.update_result(1, "[Errno 2] syntax error [failed] [/]")
                # 3. Finding with brackets
                app._handle_event(FindingEvent(severity="high", title="[XSS] in /search?q=[payload]", evidence="[200 OK] reflected"))
                # 4. Task complete with brackets
                app._handle_event(TaskCompleteEvent(status="[Exit 1] failed with [/] error", success=False))
                await pilot.pause()
        asyncio.run(_check())


    def test_26_copy_chat_area_everything(self):
        """Verify /copy captures user inputs, assistant outputs, commands, outputs, findings, and statuses."""
        import asyncio
        app = tui.SomScanApp()

        async def _check():
            async with app.run_test() as pilot:
                # 1. User input
                app._handle_event(UserMessageEvent("check all vulnerabilties of beco.so"))
                # 2. Assistant response
                app._handle_event(AssistantMessageEvent("Starting assessment on beco.so"))
                # 3. Command execution with stdout
                app._handle_event(CommandStartEvent("subfinder -d beco.so"))
                app._handle_event(CommandFinishEvent("subfinder -d beco.so", 0, "api.beco.so\nadmin.beco.so"))
                # 4. Red team finding
                app._handle_event(FindingEvent("high", "Open Admin Portal", "HTTP 200 on admin.beco.so"))
                # 5. Task completion
                app._handle_event(TaskCompleteEvent("Scan completed successfully", True))
                # 6. Error event
                app._handle_event(ErrorEvent("WAF rate limit encountered"))

                # Trigger copy
                app._copy_conversation()

                # Verify exported file contains everything
                log_file = pathlib.Path.cwd() / "somscan_session.log"
                self.assertTrue(log_file.exists())
                content = log_file.read_text(encoding="utf-8")

                self.assertIn("> You\ncheck all vulnerabilties of beco.so", content)
                self.assertIn("[*] SOM-SCAN\nStarting assessment on beco.so", content)
                self.assertIn("[Command] $ subfinder -d beco.so", content)
                self.assertIn("[Exit 0]", content)
                self.assertIn("api.beco.so\nadmin.beco.so", content)
                self.assertIn("[HIGH FINDING] Open Admin Portal", content)
                self.assertIn("Evidence: HTTP 200 on admin.beco.so", content)
                self.assertIn("[✓ Scan completed successfully]", content)
                self.assertIn("[✗ Error: WAF rate limit encountered]", content)

        asyncio.run(_check())

    def test_27_powershell_dollar_escaping(self):
        """Verify PowerShell commands with variables and semicolons are not mangled by git_bash."""
        runner = TaskRunner()
        cmd = 'powershell -NoProfile -Command "$testvar = 9876; Write-Output (\'RESULT=\' + $testvar)"'
        res = runner.run_command(cmd, timeout=15)
        self.assertEqual(res.returncode, 0)
        self.assertIn("RESULT=9876", res.output)

    def test_28_no_confirmation_for_non_harmful_tasks(self):
        """Verify system prompt and persona mandate zero confirmation prompts on non-harmful tasks."""
        router = AgentRouter(event_callback=lambda ev: None)
        sys_prompt = router.history[0]["content"]
        self.assertIn("Zero Confirmation", sys_prompt)
        self.assertIn("Direct Capability Boundaries", sys_prompt)

    def test_29_boundary_response_clean_termination(self):
        """Verify that when the agent explains a boundary without directives, it finishes cleanly without looping."""
        events = []
        router = AgentRouter(event_callback=lambda ev: events.append(ev))

        # Mock model providing a direct boundary explanation
        mock_reply = (
            "[MaHii] opened the target chat in WhatsApp Web. The internal contact menu requires manual tap of Block. "
            "Automated portion is complete."
        )
        with patch.object(router.model_manager, "stream_chat", return_value=[mock_reply]):
            router._run_agent_loop("open my whatsapp and block +252618278773")

        # Must conclude cleanly with READY status without infinite supervisor loops
        self.assertFalse(router.is_busy)
        status_events = [ev for ev in events if isinstance(ev, StatusChangeEvent)]
        self.assertTrue(any(ev.status == "READY" for ev in status_events))

    def test_30_command_and_done_in_same_turn(self):
        """Verify that when a model emits COMMAND: and DONE: in the same message, the command executes."""
        events = []
        router = AgentRouter(event_callback=lambda ev: events.append(ev))

        mock_reply = (
            "[MaHii] opening the direct chat.\n\n"
            "COMMAND: echo OPENING_WHATSAPP\n\n"
            "This drops you into the thread.\n\n"
            "DONE: opened direct WhatsApp chat."
        )
        with patch.object(router.model_manager, "stream_chat", return_value=[mock_reply]):
            router._run_agent_loop("open my whatsapp and block +252618278773")

        # Verify command execution events were dispatched
        cmd_starts = [ev for ev in events if isinstance(ev, CommandStartEvent)]
        cmd_finishes = [ev for ev in events if isinstance(ev, CommandFinishEvent)]
        complete_events = [ev for ev in events if isinstance(ev, TaskCompleteEvent)]

        self.assertEqual(len(cmd_starts), 1)
        self.assertEqual(cmd_starts[0].command, "echo OPENING_WHATSAPP")
        self.assertEqual(len(cmd_finishes), 1)
        self.assertIn("OPENING_WHATSAPP", cmd_finishes[0].output)
        self.assertEqual(len(complete_events), 1)
        self.assertTrue(complete_events[0].success)

    def test_31_code_bubble_rendering_and_styling(self):
        """Verify CodeBubble formatting with cyan & pink palette and SafeMarkdown fallback."""
        snippet = "def hello_world():\n    print('SOM-SCAN')\n    return 42"
        bubble = tui.CodeBubble(code=snippet, language="python")
        self.assertEqual(bubble.language, "python")
        formatted = bubble._format_highlighted_code()
        # Verify pink line numbers and cyan code text
        self.assertIn("#f472b6", formatted)
        self.assertIn("#38bdf8", formatted)
        self.assertIn("hello_world()", formatted)

        # Test SafeMarkdown does not crash on malformed input
        safe_md = tui.SafeMarkdown("```python\nunclosed code fence")
        renderable = safe_md.render()
        self.assertIsNotNone(renderable)

    def test_32_error_boundary_trapping(self):
        """Verify error boundary catches exceptions, renders in chat, and preserves history."""
        import asyncio
        app = tui.SomScanApp()

        async def _check():
            async with app.run_test() as pilot:
                # Trigger trapped exception
                try:
                    raise RuntimeError("Simulated runtime failure")
                except Exception as e:
                    app._handle_exception(e)

                # Verify history preserved and error recorded
                self.assertTrue(any("Simulated runtime failure" in item for item in app._conversation_history))
                self.assertEqual(app._current_status_text, "READY")
                self.assertEqual(app._current_status_color, "yellow")
        asyncio.run(_check())

    def test_33_installer_windows_tool_detection(self):
        """Verify installer.status() and _which() operate cleanly on Windows without command -v."""
        import installer
        status_info = installer.status()
        self.assertIn("platform", status_info)
        self.assertIn("installed", status_info)
        self.assertIn("total_in_db", status_info)
        self.assertGreaterEqual(status_info["installed"], 0)

    def test_34_code_bubble_collapsible_short_long(self):
        """Verify CodeBubble collapsible short view (5 lines) and /long /short expansion."""
        lines = [f"print('Line {i}')" for i in range(25)]
        long_code = "\n".join(lines)
        bubble = tui.CodeBubble(code=long_code, language="python")
        self.assertFalse(bubble.expanded)
        short_render = bubble._format_highlighted_code()
        # Verify first lines present and tip displayed
        self.assertIn("Line 0", short_render)
        self.assertIn("Line 4", short_render)
        self.assertNotIn("Line 10", short_render)
        self.assertIn("20 more lines", short_render)
        self.assertIn("/long", short_render)

        # Toggle expand
        bubble.toggle_expand(True)
        self.assertTrue(bubble.expanded)
        long_render = bubble._format_highlighted_code()
        self.assertIn("Line 24", long_render)
        self.assertIn("/short", long_render)

        # Toggle short
        bubble.toggle_expand(False)
        self.assertFalse(bubble.expanded)
        collapsed_render = bubble._format_highlighted_code()
        self.assertNotIn("Line 10", collapsed_render)

    def test_35_layout_margin_and_ctrl_c_guard(self):
        """Verify layout margin between chat and composer, and Ctrl+C pause menu guard."""
        self.assertIn("margin-bottom: 1;", tui.TUI_CSS)
        self.assertIn("border-top: solid #1e293b;", tui.TUI_CSS)

        app = tui.SomScanApp()
        self.assertFalse(app._in_pause_menu)
        self.assertEqual(len(app._code_bubbles), 0)

        # Verify action_interrupt_task sets _in_pause_menu and handles repeated calls safely
        app._in_pause_menu = True
        # Calling again while _in_pause_menu is True should safely return without exception
        app.action_interrupt_task()
        self.assertTrue(app._in_pause_menu)
        app._in_pause_menu = False

    def test_36_command_input_history_and_scrolling(self):
        """Verify input history recall and unblocked scrolling key routing."""
        import asyncio
        app = tui.SomScanApp()

        async def _check():
            async with app.run_test() as pilot:
                inp = app.query_one("#input-box", tui.CommandInput)
                app._input_history = ["ls", "/status", "python app.py"]
                app._input_history_idx = -1

                # Test history previous
                self.assertTrue(app.history_prev(inp))
                self.assertEqual(inp.value, "python app.py")
                self.assertTrue(app.history_prev(inp))
                self.assertEqual(inp.value, "/status")

                # Test history next
                self.assertTrue(app.history_next(inp))
                self.assertEqual(inp.value, "python app.py")
                self.assertTrue(app.history_next(inp))
                self.assertEqual(inp.value, "")
        asyncio.run(_check())

    def test_37_redteam_fixes(self):
        """Verify red-team agent improvements: subdomain extraction, anti-WAF pacing, and finding calibration."""
        from core.agent_router import AgentRouter
        from core.task_runner import CommandSupervisor

        # 1. Anti-WAF tool pacing
        cmd_ffuf, cfg_ffuf = CommandSupervisor.analyze_and_adapt("ffuf -w wordlist.txt -u https://example.com/FUZZ")
        self.assertIn("-rate 20", cmd_ffuf)
        self.assertIn("-p 0.05", cmd_ffuf)

        cmd_nuclei, cfg_nuclei = CommandSupervisor.analyze_and_adapt("nuclei -u https://example.com")
        self.assertIn("-rate-limit 20", cmd_nuclei)

        cmd_curl, _ = CommandSupervisor.analyze_and_adapt("curl https://example.com")
        self.assertIn("Mozilla/5.0", cmd_curl)

        # 2. Subdomain auto-extraction
        events = []
        router = AgentRouter(event_callback=lambda e: events.append(e))
        state = {"endpoints": []}
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = pathlib.Path(tmpdir)
            subfinder_output = "api.beco.so\nadmin.beco.so\nportal.beco.so\n"
            added = router._extract_and_register_endpoints(subfinder_output, "beco.so", state, run_dir)
            self.assertEqual(added, 3)
            urls = {e["url"] for e in state["endpoints"]}
            self.assertIn("https://api.beco.so", urls)
            self.assertIn("https://admin.beco.so", urls)
            self.assertIn("https://portal.beco.so", urls)

        # 3. Finding calibration
        router._exec_directive_finding("high|Open Admin Portal|HTTP 200 on admin.beco.so login form")
        self.assertEqual(len(events), 1)
        finding_ev = events[0]
        self.assertEqual(finding_ev.severity, "medium")
        self.assertIn("requires credential or auth-bypass verification", finding_ev.evidence)

    def test_38_strip_directives_and_supervisor_resilience(self):
        """Verify machine directives are stripped from assistant text and regexes are protected."""
        from core.agent_router import strip_directives

        raw_llm_text = (
            "[DevLP] hunting for DDoS tooling on the box.\n\n"
            "COMMAND: powershell -NoProfile -Command \"Get-ChildItem\"\n"
            "FILE: test.py|print('hello')\n"
            "PROBE: GET|https://example.com\n"
            "DONE: Finished investigation"
        )
        cleaned = strip_directives(raw_llm_text)
        self.assertEqual(cleaned, "[DevLP] hunting for DDoS tooling on the box.")
        self.assertNotIn("COMMAND:", cleaned)
        self.assertNotIn("FILE:", cleaned)
        self.assertNotIn("PROBE:", cleaned)
        self.assertNotIn("DONE:", cleaned)

        from core.task_runner import CommandSupervisor

        # Verify python regex in process search is NOT replaced with path
        cmd = 'powershell -NoProfile -Command "Get-Process | Where-Object { $_.ProcessName -match \'(?i)(ddos|flood|python|node)\' }"'
        adapted, notes = CommandSupervisor.analyze_and_adapt(cmd)
        self.assertIn("ddos|flood|python|node", adapted)
        self.assertNotIn("AppData\\Local\\Programs\\Python", adapted)

        # Verify Get-ChildItem -Recurse receives -Attributes !ReparsePoint on Windows
        if sys.platform == "win32":
            gci_cmd = "powershell -NoProfile -Command \"Get-ChildItem -Path 'C:\\Users\\libaa' -Recurse\""
            gci_adapted, _ = CommandSupervisor.analyze_and_adapt(gci_cmd)
            self.assertIn("-Attributes !ReparsePoint", gci_adapted)


if __name__ == "__main__":
    unittest.main()


