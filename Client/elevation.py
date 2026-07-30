from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from logger import get_logger


log = get_logger("elevation")


_SE_ERR_ACCESSDENIED = 5

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception as exc:
        log.warning("User is not admin : %s", exc)
        return False


def ensure_admin() -> None:


    if is_admin():
        log.info("Running with administrator privileges.")
        return

    log.info("Administrator privileges required — requesting elevation via UAC...")

    script = os.path.abspath(sys.argv[0])
    
    params = subprocess.list2cmdline([script, *sys.argv[1:]])

    rc = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        os.path.dirname(script) or None,
        1,
    )

    if rc <= 32:
        if rc == _SE_ERR_ACCESSDENIED:
            msg = (
                "Elevation denied: the UAC prompt was cancelled or blocked. "
                "Re-run this program as Administrator."
            )
        else:
            msg = f"Elevation failed (ShellExecuteW code {rc}). Re-run as Administrator."
        log.error(msg)
        print(msg, file=sys.stderr)
        sys.exit(1)


    log.debug("UAC accepted — exiting unelevated parent (ShellExecuteW rc=%s).", rc)
    sys.exit(0)

