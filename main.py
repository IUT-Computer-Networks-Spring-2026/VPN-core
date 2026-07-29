

from __future__ import annotations

import argparse
import signal
import sys
import time
from typing import Optional, Sequence

import config
from adapter import Adapter
from elevation import ensure_admin
from logging_setup import get_logger, setup_logging

from routing import RouteManager

log = get_logger("main")


if __name__ == "__main__":
    ensure_admin()
    adapterr = Adapter.create()
    adapterr.wait_until_ready
    adapterr.enable_adapter()
    adapterr.start_session()
    objr = RouteManager()
    objr.apply()
    objr.revert()
    adapterr.close()

    
