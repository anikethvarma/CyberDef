"""
AegisNet Logging

Logging configuration using Python's built-in logging module.
"""

from __future__ import annotations

import logging
import logging.handlers
import json
import sys
from typing import Any

from core.config import get_settings


class _JsonFormatter(logging.Formatter):
    """JSON log formatter for production use."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


def setup_logging() -> None:
    """Configure logging for the application."""
    settings = get_settings()

    # Set log level
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    # Choose formatter
    if settings.log_format == "json":
        formatter = _JsonFormatter()
    else:
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )

    # Configure root logger
    root = logging.getLogger()
    root.setLevel(log_level)

    # Remove existing handlers to avoid duplicates on re-init
    root.handlers.clear()

    # 1. Standard Output Handler (Console)
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(log_level)
    stdout_handler.setFormatter(formatter)
    root.addHandler(stdout_handler)

    # 2. Rotating File Handler (Archive logs gracefully)
    log_dir = settings.data_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "cyberdef_pipeline.log"
    
    # Rotate when file hits the MB limit defined in settings
    file_handler = logging.handlers.RotatingFileHandler(
        filename=log_file,
        maxBytes=settings.log_max_size_mb * 1024 * 1024,
        backupCount=5                # e.g. cyberdef_pipeline.log.1, .log.2
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)


def get_logger(name: str | None = None, **context: Any) -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Logger name (usually module name)
        **context: Ignored (kept for API compatibility)

    Returns:
        Configured logging.Logger
    """
    return logging.getLogger(name)


class LogContext:
    """Context manager for adding temporary log context (no-op stub)."""

    def __init__(self, **context: Any):
        self.context = context

    def __enter__(self) -> "LogContext":
        return self

    def __exit__(self, *args: Any) -> None:
        pass
