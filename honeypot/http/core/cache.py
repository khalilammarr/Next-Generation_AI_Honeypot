import time
from typing import Optional


class TTLCache:
    def __init__(self, ttl_seconds: int, max_items: int):
        self.ttl_seconds = ttl_seconds
        self.max_items = max_items
        self._store = {}

    def get(self, key: str) -> Optional[str]:
        item = self._store.get(key)
        if not item:
            return None
        expires_at, payload = item
        if time.time() > expires_at:
            self._store.pop(key, None)
            return None
        return payload

    def set(self, key: str, payload: str) -> None:
        if len(self._store) >= self.max_items:
            self._store.pop(next(iter(self._store)), None)
        self._store[key] = (time.time() + self.ttl_seconds, payload)
