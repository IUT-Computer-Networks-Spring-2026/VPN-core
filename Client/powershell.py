import subprocess
import json

from typing import Any

from Client.logger import get_logger

log = get_logger("powershell")

class PowerShellError(RuntimeError):

    def __init__(self, command: str, returncode: int, stdout: str, stderr: str) -> None:
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(
            f"PowerShell failed (exit {returncode}): {stderr.strip() or stdout.strip() or 'unknown error'}"
        )


def _ps(command: str, *, check: bool = True, timeout: int = 60) -> str:

    log.debug("PS> %s", command)
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
    )

    if result.stdout:
        log.debug("PS stdout: %s", result.stdout.rstrip())
    if result.stderr:
        level = log.warning if result.returncode != 0 else log.debug
        level("PS stderr: %s", result.stderr.rstrip())

    if check and result.returncode != 0:
        raise PowerShellError(command, result.returncode, result.stdout, result.stderr)

    return result.stdout.strip()


def _quote(value: str) -> str:
    return value.replace("'", "''")


def _ps_json(command: str) -> Any:
    raw = _ps(command)
    if not raw:
        return None
    return json.loads(raw)

