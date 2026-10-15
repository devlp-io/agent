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
