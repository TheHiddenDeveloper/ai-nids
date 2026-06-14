from __future__ import annotations

import threading
from typing import Optional

from loguru import logger


class ShardedFlowStore:
    """
    OP2: sharded dict with per-shard locks to reduce contention.

    Uses hash(key) % num_shards to distribute entries across shards.
    Each shard has its own RLock, keeping critical sections small.
    """

    def __init__(self, num_shards: int = 16, max_flows: int = 50000):
        if num_shards < 1:
            raise ValueError("num_shards must be >= 1")
        self.num_shards = num_shards
        self.max_flows = max_flows
        self._shards: list[dict] = [{} for _ in range(num_shards)]
        self._locks: list[threading.RLock] = [threading.RLock() for _ in range(num_shards)]
        self._total_approx = 0

    def _shard(self, key: str) -> int:
        return hash(key) % self.num_shards

    def get(self, key: str) -> Optional[dict]:
        s = self._shard(key)
        with self._locks[s]:
            return self._shards[s].get(key)

    def set(self, key: str, value: dict) -> None:
        s = self._shard(key)
        with self._locks[s]:
            self._shards[s][key] = value

    def pop(self, key: str, default=None):
        s = self._shard(key)
        with self._locks[s]:
            return self._shards[s].pop(key, default)

    def contains(self, key: str) -> bool:
        s = self._shard(key)
        with self._locks[s]:
            return key in self._shards[s]

    def keys(self) -> list[str]:
        result: list[str] = []
        for s in range(self.num_shards):
            with self._locks[s]:
                result.extend(self._shards[s].keys())
        return result

    def values(self) -> list:
        result: list = []
        for s in range(self.num_shards):
            with self._locks[s]:
                result.extend(self._shards[s].values())
        return result

    def items(self) -> list[tuple]:
        result: list[tuple] = []
        for s in range(self.num_shards):
            with self._locks[s]:
                result.extend(self._shards[s].items())
        return result

    def pop_expired(self, key_fn) -> list[tuple]:
        """
        Pop entries where key_fn(key, value) returns True.
        Returns list of (key, value) tuples removed.
        """
        removed: list[tuple] = []
        for s in range(self.num_shards):
            with self._locks[s]:
                to_remove = [k for k, v in self._shards[s].items() if key_fn(k, v)]
                for k in to_remove:
                    removed.append((k, self._shards[s].pop(k)))
        return removed

    def iter_values_batched(self, batch_size: int = 100):
        """Yield batches of values across all shards without holding locks across yields."""
        all_keys = self.keys()
        for i in range(0, len(all_keys), batch_size):
            batch = []
            for key in all_keys[i:i + batch_size]:
                val = self.get(key)
                if val is not None:
                    batch.append(val)
            yield batch

    def __getitem__(self, key: str):
        return self.get(key)

    def __setitem__(self, key: str, value):
        self.set(key, value)

    def clear(self) -> int:
        total = 0
        for s in range(self.num_shards):
            with self._locks[s]:
                total += len(self._shards[s])
                self._shards[s].clear()
        return total

    def __len__(self) -> int:
        total = 0
        for s in range(self.num_shards):
            with self._locks[s]:
                total += len(self._shards[s])
        return total
