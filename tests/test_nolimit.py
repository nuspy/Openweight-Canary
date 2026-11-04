"""A limit of 0 on a reply means none: the request carries no max_tokens (the server decides), except where an API cannot be asked that."""
from __future__ import annotations

import json

import pytest

from canary.config import ConfigError, sample_config, load_config
from canary.providers import Provider


def body(kind, limit):
    return json.loads(Provider({"kind": kind, "base_url": "http://x", "model": "m"})._body([{"role": "user", "content": "hi"}], None, limit))


def test_zero_means_no_limit_in_the_request():
    assert "max_tokens" not in body("openai", 0)
    assert body("openai", 700)["max_tokens"] == 700
    assert body("anthropic", 0)["max_tokens"] == 32000


def test_a_negative_limit_is_refused(tmp_path):
    for patch in ({"max_tokens": -1}, {"narrative": {"reply_tokens": -5}}):
        path = tmp_path / "c.json"
        path.write_text(json.dumps({**sample_config(), **patch}), encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(path)
    ok = tmp_path / "ok.json"
    ok.write_text(json.dumps({**sample_config(), "max_tokens": 0, "narrative": {"reply_tokens": 0}}), encoding="utf-8")
    assert load_config(ok).max_tokens == 0
