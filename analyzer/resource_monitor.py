import resource
import time
from contextlib import contextmanager
from typing import Any, Iterator


def _snapshot() -> dict[str, Any]:
    self_usage = resource.getrusage(resource.RUSAGE_SELF)
    child_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {
        "wall_time": time.monotonic(),
        "self_user_cpu_seconds": self_usage.ru_utime,
        "self_system_cpu_seconds": self_usage.ru_stime,
        "self_max_rss_kb": self_usage.ru_maxrss,
        "child_user_cpu_seconds": child_usage.ru_utime,
        "child_system_cpu_seconds": child_usage.ru_stime,
        "child_max_rss_kb": child_usage.ru_maxrss,
    }


def _delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    wall_time = after["wall_time"] - before["wall_time"]
    self_cpu = (
        after["self_user_cpu_seconds"]
        - before["self_user_cpu_seconds"]
        + after["self_system_cpu_seconds"]
        - before["self_system_cpu_seconds"]
    )
    child_cpu = (
        after["child_user_cpu_seconds"]
        - before["child_user_cpu_seconds"]
        + after["child_system_cpu_seconds"]
        - before["child_system_cpu_seconds"]
    )
    total_cpu = self_cpu + child_cpu
    return {
        "wall_time_seconds": round(wall_time, 6),
        "self_user_cpu_seconds": round(
            after["self_user_cpu_seconds"] - before["self_user_cpu_seconds"], 6
        ),
        "self_system_cpu_seconds": round(
            after["self_system_cpu_seconds"] - before["self_system_cpu_seconds"], 6
        ),
        "child_user_cpu_seconds": round(
            after["child_user_cpu_seconds"] - before["child_user_cpu_seconds"], 6
        ),
        "child_system_cpu_seconds": round(
            after["child_system_cpu_seconds"] - before["child_system_cpu_seconds"], 6
        ),
        "total_cpu_seconds": round(total_cpu, 6),
        "average_cpu_percent": round((total_cpu / wall_time) * 100, 2)
        if wall_time > 0
        else 0.0,
        "max_rss_kb": max(after["self_max_rss_kb"], after["child_max_rss_kb"]),
    }


@contextmanager
def measure_resource_usage(label: str) -> Iterator[dict[str, Any]]:
    result: dict[str, Any] = {"label": label}
    before = _snapshot()
    try:
        yield result
    finally:
        after = _snapshot()
        result.update(_delta(before, after))
