from __future__ import annotations

import random

import pytest

from canary.config import DEFAULT_MARKERS
from canary.generator import generate_pair
from canary.materials import MaterialStore, check_public_https, fetch_sources, read_archive
from canary.registry import Registry
from conftest import make_cfg


@pytest.fixture
def cfg(tmp_path):
    return make_cfg(tmp_path, "http://127.0.0.1:1", doc_words=800)


def test_template_fallback_offline_and_control_shape(cfg, tmp_path):
    registry = Registry(tmp_path / "canaries.jsonl")
    sens, ctrl = generate_pair(cfg, random.Random(3), registry, llm=None)
    assert sens.sensitive and not ctrl.sensitive
    assert sens.marker in DEFAULT_MARKERS and sens.marker in sens.text
    assert sens.marker.replace(" ", "-") in sens.filename.upper()
    assert sens.marker not in ctrl.text and sens.marker.replace(" ", "-") not in ctrl.filename.upper()
    assert abs(sens.words - ctrl.words) / sens.words < 0.10
    assert sens.words > 600
    kinds = {c.kind for c in sens.canaries}
    assert {"codename", "credential", "iban", "serial", "email"} <= kinds
    for canary in sens.canaries:
        assert canary.value in sens.text
        assert canary.value not in ctrl.text
        assert canary.value not in ctrl.filename
    codename = next(c for c in sens.canaries if c.kind == "codename")
    assert codename.value in sens.filename
    assert len(registry) == len(sens.canaries)
    assert len(Registry(tmp_path / "canaries.jsonl")) == len(registry)


def test_hostname_canary_with_public_base_url(tmp_path):
    cfg = make_cfg(tmp_path, "http://127.0.0.1:1", doc_words=300,
                   canary_listener={"enabled": False, "host": "127.0.0.1", "port": 1,
                                    "public_base_url": "http://canary.example.net:8099"})
    sens, _ = generate_pair(cfg, random.Random(5), Registry(tmp_path / "c.jsonl"))
    kinds = {c.kind for c in sens.canaries}
    assert {"hostname", "url"} <= kinds
    assert any("canary.example.net" in c.value for c in sens.canaries if c.kind in ("hostname", "url"))


def test_archive_index_contains_canaries(cfg, tmp_path):
    registry = Registry(tmp_path / "c.jsonl")
    store = MaterialStore(cfg, registry)
    sens, ctrl = store.make_pair(random.Random(11), kind="archive")
    assert sens.kind == "archive" and len(sens.doc_ids) >= 2
    members = read_archive(tmp_path / "state" / "materials" / "archives" / sens.name)
    assert "INDEX.txt" in members
    index = members["INDEX.txt"]
    docs = [n for n in members if n != "INDEX.txt"]
    assert len(docs) == len(sens.doc_ids)
    assert all(name in index for name in docs)
    codenames = [c.value for c in registry.all() if c.kind == "codename"]
    assert all(any(cn in index for cn in codenames) for _ in docs)
    assert any(cn in sens.name for cn in codenames)
    control_members = read_archive(tmp_path / "state" / "materials" / "archives" / ctrl.name)
    assert not any(c.value in control_members["INDEX.txt"] for c in registry.all())
    assert abs(sens.words - ctrl.words) / sens.words < 0.15


def test_tar_and_zip_both_supported(cfg, tmp_path):
    store = MaterialStore(cfg, Registry(tmp_path / "c.jsonl"))
    seen = set()
    for seed in range(12):
        sens, _ = store.make_pair(random.Random(seed), kind="archive")
        seen.add("zip" if sens.name.endswith(".zip") else "tar.gz")
    assert seen == {"zip", "tar.gz"}


def test_fetch_refuses_non_public_and_http(tmp_path):
    for url in ("http://example.org/a", "https://127.0.0.1/a", "https://localhost/a"):
        with pytest.raises(ValueError):
            check_public_https(url)
    sources = tmp_path / "sources.json"
    sources.write_text('{"sources": [{"name": "a", "url": "http://example.org/a"}, '
                       '{"name": "b", "url": "https://localhost/b"}]}', encoding="utf-8")
    results = fetch_sources(sources, tmp_path / "dest")
    assert [r["ok"] for r in results] == [False, False]
    assert not list((tmp_path / "dest").glob("*"))
