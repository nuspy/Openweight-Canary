"""The page keeps its tabs in view, carries the filters in the project-links bar, shows a filter as on or off clearly, pins the close button of a finding and explains sensitive and control."""
from __future__ import annotations

from pathlib import Path

HTML = (Path(__file__).resolve().parents[1] / "canary" / "gui" / "static" / "index.html").read_text(encoding="utf-8")


def test_the_tabs_and_the_links_bar_stay_at_the_top():
    assert ".topbar { position: sticky; top: 0;" in HTML
    top = HTML.index('<div class="topbar"')
    assert top < HTML.index("<header>") < HTML.index('<div class="promo"') < HTML.index("<main>")


def test_the_filters_are_inside_the_links_bar_and_show_only_in_results():
    promo, tip = HTML.index('<div class="promo"'), HTML.index('<div class="tip standalone-only"')
    rf = HTML.index('id="rf"')
    assert promo < rf < tip
    for field in ("f-q", "f-kind", "f-role", "f-harness", "f-session", "f-trigger", "f-order", "legend"):
        assert HTML.count(f'id="{field}"') == 1 and promo < HTML.index(f'id="{field}"') < tip
    assert '$("rf").hidden = name !== "results"' in HTML


def test_a_level_filter_is_a_ticked_box_or_an_empty_struck_through_one():
    assert 'class: "box"' in HTML and "aria-pressed=false] .nm { text-decoration: line-through; }" in HTML
    assert "border: 2px dashed var(--line)" in HTML and 'chip[aria-pressed=true] .box::before { content: "✓"' in HTML


def test_the_close_button_and_the_level_of_a_finding_are_pinned_in_the_drawer():
    assert ".drawer-head { position: sticky; top: -16px;" in HTML
    assert 'class: "row drawer-head" }, h("button", { onclick: () => d.hidden = true }, "Close"), badge(lv)' in HTML


def test_sensitive_and_control_are_explained_and_the_transcript_shows_reasoning_and_replies():
    assert "Sensitive and control. " in HTML and "ROLE_HELP" in HTML and "SENSITIVE (with the material)" in HTML
    assert 'bubble("Reasoning", String(m.reasoning), "reasoning")' in HTML and 'bubble("Model\'s reply"' in HTML
    assert "slice(0, 6000)" not in HTML and "t.slice(0, 8000)" not in HTML
