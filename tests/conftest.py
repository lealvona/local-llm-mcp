from datetime import datetime as _datetime

import pytest

from local_llm_mcp import savings as sv


@pytest.fixture
def frozen_clock(monkeypatch):
    """Pin the savings module's clock to the day the shipped price table was checked.

    Three tests assert that the package defaults are "fresh"; without this they expire
    stale_after_days (30) after every price refresh and turn CI red on a timer.
    """
    checked = _datetime.fromisoformat(sv.Prices(None).doc["checked"])

    class Frozen(_datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(checked.year, checked.month, checked.day, 12, 0, 0, tzinfo=tz)

    monkeypatch.setattr(sv, "datetime", Frozen)
