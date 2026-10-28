"""correlate rule-registry contracts.

Pin that the HTTP-campaign rule (which consumes httppatterns cluster
membership) is registered and that the rule list stays well-formed. Rule
behavior on real data is exercised by running the stage; here we guard the
wiring so a rename/typo can't silently drop a rule.
"""
from __future__ import annotations

from conclusions import correlate


def test_http_campaign_rule_registered():
    assert correlate.pat_coordinated_http_campaign in correlate.PATTERNS


def test_all_patterns_are_callable_and_unique():
    assert all(callable(fn) for fn in correlate.PATTERNS)
    names = [fn.__name__ for fn in correlate.PATTERNS]
    assert len(names) == len(set(names)), "duplicate rule in PATTERNS"


def test_http_views_in_register_mapping():
    # the new views must be wired into _register_views so the rule can find them
    import inspect
    src = inspect.getsource(correlate._register_views)
    assert "http_clusters" in src and "http_templates" in src
    assert "l7_events" in src
