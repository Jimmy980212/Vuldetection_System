import json
import logging
import os
from typing import Any


_LOGGING_INITIALIZED = False


def configure_logging() -> None:
    global _LOGGING_INITIALIZED
    if _LOGGING_INITIALIZED:
        return

    level_name = str(os.getenv("VULDET_LOG_LEVEL", "INFO") or "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    _LOGGING_INITIALIZED = True


def get_logger(name: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)


def log_event(logger: logging.Logger, event: str, level: int = logging.INFO, **fields: Any) -> None:
    payload = {"event": event}
    payload.update(fields)
    logger.log(level, json.dumps(payload, ensure_ascii=False, default=str))
