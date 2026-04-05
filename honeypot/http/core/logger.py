import json
import os

from core.config import LOG_DIR, LOG_FILE

os.makedirs(LOG_DIR, exist_ok=True)

_WRITE_COUNT = 0
_FSYNC_EVERY = int(os.environ.get("LOG_FSYNC_EVERY", "50"))


def log_event(event_data: dict) -> None:
    global _WRITE_COUNT
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event_data) + "\n")
        f.flush()
        _WRITE_COUNT += 1
        if _FSYNC_EVERY <= 1 or (_WRITE_COUNT % _FSYNC_EVERY) == 0:
            os.fsync(f.fileno())
