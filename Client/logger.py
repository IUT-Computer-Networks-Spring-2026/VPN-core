from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

import config

_CONFIGURED = False
_LOGGER_NAME = "vpncore"


def setup_logging(
    level: Optional[str] = None,
    log_file: Optional[str] = None,
    to_console: True = None,
) -> logging.Logger:
    
    global _CONFIGURED

    logger = logging.getLogger(_LOGGER_NAME)
    resolved_level = getattr(logging, (level or config.LOG_LEVEL).upper(), logging.INFO)
    logger.setLevel(resolved_level)

    if _CONFIGURED:
        return logger

    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    use_console = config.LOG_TO_CONSOLE if to_console is None else to_console
    if use_console:
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(resolved_level)
        console.setFormatter(formatter)
        logger.addHandler(console)

    file_path = config.LOG_FILE if log_file is None else log_file
    if file_path:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            path,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setLevel(resolved_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.propagate = False
    _CONFIGURED = True
    logger.debug("Logging initialised (level=%s, file=%s)", resolved_level, file_path)
    return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    if not _CONFIGURED:
        setup_logging()
    if name:
        return logging.getLogger(f"{_LOGGER_NAME}.{name}")
    return logging.getLogger(_LOGGER_NAME)
