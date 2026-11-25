"""Weekly local-time delivery windows; UTC instants remain authoritative across DST."""

from datetime import datetime, timedelta
from functools import lru_cache
from zoneinfo import ZoneInfo

from vulnrelay.schemas import DeliverySchedule


def schedule_allows(schedule: DeliverySchedule | None, timestamp: float) -> bool:
    """End is exclusive; an overnight window belongs to its selected starting day."""
    if schedule is None:
        return True
    local = datetime.fromtimestamp(timestamp, ZoneInfo(schedule.timezone))
    clock = local.hour * 60 + local.minute
    day = local.weekday()
    for window in schedule.windows:
        start = int(window.start[:2]) * 60 + int(window.start[3:])
        end = int(window.end[:2]) * 60 + int(window.end[3:])
        if start < end:
            if day in window.days and start <= clock < end:
                return True
        elif (day in window.days and clock >= start) or (
            (day - 1) % 7 in window.days and clock < end
        ):
            return True
    return False


@lru_cache(maxsize=512)
def _day_transitions(timezone: str, utc_day: int) -> tuple[int, ...]:
    """Find UTC offset transitions, including a repeated/skipped local window boundary.

    Hourly UTC probes cover modern IANA DST changes; second-resolution bisection
    retains transitions that do not fall on an hour. Cached by immutable zone/day.
    """
    zone = ZoneInfo(timezone)

    def offset(timestamp):
        return datetime.fromtimestamp(timestamp, zone).utcoffset()

    transitions = []
    left = utc_day * 86400
    for right in range(left + 3600, left + 86401, 3600):
        if offset(left) != offset(right):
            low, high = left, right
            original = offset(left)
            while high - low > 1:
                middle = (low + high) // 2
                if offset(middle) == original:
                    low = middle
                else:
                    high = middle
            transitions.append(high)
        left = right
    return tuple(transitions)


def next_delivery_at(schedule: DeliverySchedule | None, timestamp: float) -> float:
    """Return timestamp itself when allowed, otherwise the first allowed UTC instant.

    Both folds of valid local starts are candidates. Offset transitions are also
    candidates: spring-forward can open a partially skipped window, and fall-back
    can reopen a window before its repeated nominal start. A window skipped in its
    entirety waits until its next weekly occurrence.
    """
    if schedule_allows(schedule, timestamp):
        return timestamp
    assert schedule is not None
    zone = ZoneInfo(schedule.timezone)
    local_date = datetime.fromtimestamp(timestamp, zone).date()
    candidates = set()
    # Two weeks also cover a weekly window wholly lost during a DST gap/date skip.
    for delta in range(15):
        date = local_date + timedelta(days=delta)
        for window in schedule.windows:
            if date.weekday() not in window.days:
                continue
            naive = datetime.combine(date, datetime.strptime(window.start, "%H:%M").time())
            for fold in (0, 1):
                candidate = naive.replace(tzinfo=zone, fold=fold).timestamp()
                # Nonexistent local times are handled by the UTC transition below.
                if datetime.fromtimestamp(candidate, zone).replace(tzinfo=None) == naive:
                    candidates.add(candidate)
    utc_day = int(timestamp // 86400)
    for day in range(utc_day, utc_day + 16):
        candidates.update(_day_transitions(schedule.timezone, day))
    for candidate in sorted(candidates):
        if candidate > timestamp and schedule_allows(schedule, candidate):
            return candidate
    # Valid nonempty weekly schedules necessarily have a real occurrence in this horizon.
    raise ValueError("No delivery window is available in the next two weeks")
