"""
core.events — structured agent event bus for SOM-SCAN.
Decouples agent execution, tool runs, model streaming, and TUI updates.
Uses explicit classes with keyword-friendly constructors to avoid dataclass inheritance ordering pitfalls.
"""
import time
from typing import Any, Dict, List, Optional


class AgentEvent:
    def __init__(self, timestamp: Optional[float] = None):
        self.timestamp = timestamp if timestamp is not None else time.time()


class UserMessageEvent(AgentEvent):
    def __init__(self, text: str = "", timestamp: Optional[float] = None):
        super().__init__(timestamp)
        self.text = text


class AssistantChunkEvent(AgentEvent):
    def __init__(self, chunk: str = "", timestamp: Optional[float] = None):
        super().__init__(timestamp)
        self.chunk = chunk


class AssistantMessageEvent(AgentEvent):
    def __init__(self, text: str = "", timestamp: Optional[float] = None):
        super().__init__(timestamp)
        self.text = text


class ThinkingStartEvent(AgentEvent):
    def __init__(self, label: str = "Thinking…", timestamp: Optional[float] = None):
        super().__init__(timestamp)
        self.label = label


class ThinkingStopEvent(AgentEvent):
    def __init__(self, timestamp: Optional[float] = None):
        super().__init__(timestamp)


class CommandStartEvent(AgentEvent):
    def __init__(self, command: str = "", label: str = "Running command", timestamp: Optional[float] = None):
        super().__init__(timestamp)
        self.command = command
        self.label = label


class CommandOutputEvent(AgentEvent):
    def __init__(self, command: str = "", output: str = "", stream: bool = False, timestamp: Optional[float] = None):
        super().__init__(timestamp)
        self.command = command
        self.output = output
        self.stream = stream


class CommandFinishEvent(AgentEvent):
    def __init__(
        self,
        command: str = "",
        returncode: int = 0,
        output: str = "",
        duration_sec: float = 0.0,
        timestamp: Optional[float] = None,
    ):
        super().__init__(timestamp)
        self.command = command
        self.returncode = returncode
        self.output = output
        self.duration_sec = duration_sec


class FindingEvent(AgentEvent):
    def __init__(
        self,
        severity: str = "info",
        title: str = "",
        evidence: str = "",
        timestamp: Optional[float] = None,
    ):
        super().__init__(timestamp)
        self.severity = severity
        self.title = title
        self.evidence = evidence


class StatusChangeEvent(AgentEvent):
    def __init__(self, status: str = "READY", color: str = "green", timestamp: Optional[float] = None):
        super().__init__(timestamp)
        self.status = status
        self.color = color


class TaskCompleteEvent(AgentEvent):
    def __init__(
        self,
        status: str = "Task completed",
        success: bool = True,
        duration_sec: Optional[float] = None,
        summary: str = "",
        timestamp: Optional[float] = None,
    ):
        super().__init__(timestamp)
        self.status = status
        self.success = success
        self.duration_sec = duration_sec
        self.summary = summary


class TaskCancelledEvent(AgentEvent):
    def __init__(self, message: str = "Task cancelled", timestamp: Optional[float] = None):
        super().__init__(timestamp)
        self.message = message


class ErrorEvent(AgentEvent):
    def __init__(self, error: str = "", context: str = "", timestamp: Optional[float] = None):
        super().__init__(timestamp)
        self.error = error
        self.context = context


class PhaseTransitionEvent(AgentEvent):
    """Event emitted when assessment transitions phase, with explicit what's done & next moves."""
    def __init__(
        self,
        phase_num: Any = 1,
        phase_name: str = "Phase Transition",
        target: str = "",
        whats_done: Optional[Any] = None,
        whats_next: Optional[Any] = None,
        findings_count: int = 0,
        endpoints_count: int = 0,
        timestamp: Optional[float] = None,
        phase: Optional[Any] = None,
        name: Optional[str] = None,
    ):
        super().__init__(timestamp)
        self.phase_num = phase if phase is not None else phase_num
        self.phase_name = name if name is not None else phase_name
        self.target = target
        self.whats_done = whats_done or []
        self.whats_next = whats_next or []
        self.findings_count = findings_count
        self.endpoints_count = endpoints_count

    @property
    def phase(self) -> Any:
        return self.phase_num

    @property
    def name(self) -> str:
        return self.phase_name


class SubagentStartEvent(AgentEvent):
    """Event emitted when an autonomous subagent is dispatched."""
    def __init__(
        self,
        subagent_type: str = "recon",
        task: str = "",
        subagent_id: str = "",
        timestamp: Optional[float] = None,
    ):
        super().__init__(timestamp)
        self.subagent_type = subagent_type
        self.task = task
        self.subagent_id = subagent_id


class SubagentFinishEvent(AgentEvent):
    """Event emitted when an autonomous subagent completes its task."""
    def __init__(
        self,
        subagent_type: str = "recon",
        summary: str = "",
        subagent_id: str = "",
        success: bool = True,
        duration_sec: float = 0.0,
        findings_discovered: int = 0,
        details: str = "",
        timestamp: Optional[float] = None,
    ):
        super().__init__(timestamp)
        self.subagent_type = subagent_type
        self.summary = summary
        self.subagent_id = subagent_id
        self.success = success
        self.duration_sec = duration_sec
        self.findings_discovered = findings_discovered
        self.details = details


class PayloadCardEvent(AgentEvent):
    """Event emitted when a payload or malware component is generated."""
    def __init__(
        self,
        payload_type: str = "shellcode",
        target_platform: str = "linux/x64",
        code: str = "",
        evasion_notes: str = "",
        compilation_cmd: str = "",
        timestamp: Optional[float] = None,
    ):
        super().__init__(timestamp)
        self.payload_type = payload_type
        self.target_platform = target_platform
        self.code = code
        self.evasion_notes = evasion_notes
        self.compilation_cmd = compilation_cmd


class ExploitCardEvent(AgentEvent):
    """Event emitted when an exploit or attack chain is executed."""
    def __init__(
        self,
        title: str = "",
        target: str = "",
        tool: str = "",
        success: bool = False,
        output_snippet: str = "",
        proof: str = "",
        timestamp: Optional[float] = None,
    ):
        super().__init__(timestamp)
        self.title = title
        self.target = target
        self.tool = tool
        self.success = success
        self.output_snippet = output_snippet
        self.proof = proof


class QuestionPromptEvent(AgentEvent):
    """Event emitted when the agent requests input or credentials from the operator."""
    def __init__(
        self,
        question_id: str = "",
        prompt: str = "",
        is_secret: bool = False,
        choices: Optional[List[str]] = None,
        default: Optional[str] = None,
        timeout_sec: float = 120.0,
        timestamp: Optional[float] = None,
    ):
        super().__init__(timestamp)
        self.question_id = question_id
        self.prompt = prompt
        self.is_secret = is_secret
        self.choices = choices or []
        self.default = default
        self.timeout_sec = timeout_sec


class QuestionAnswerEvent(AgentEvent):
    """Event emitted when an operator responds to an agent's question."""
    def __init__(
        self,
        question_id: str = "",
        answer: str = "",
        timestamp: Optional[float] = None,
    ):
        super().__init__(timestamp)
        self.question_id = question_id
        self.answer = answer

