from __future__ import annotations

import json

import pytest

from canary.cli import main
from canary.config import ConfigError, build_config, load_config
from canary.findings import read_findings
from canary.presets import build_config as preset_config
from canary.runner import Runner
from canary.vendors import Catalog, VendorsError, domain_matches, load_catalog, merge
from conftest import make_cfg


@pytest.fixture(scope="module")
def catalog():
    return load_catalog()


def test_catalog_covers_the_requested_vendors_and_runtimes(catalog):
    for vendor in ("qwen", "deepseek", "moonshot", "mistral", "zhipu", "minimax", "meta", "google", "microsoft",
                   "openai", "nvidia", "cohere", "ibm", "01ai", "baidu", "tencent", "xiaomi", "stepfun"):
        assert vendor in catalog.vendors, vendor
        entry = catalog.vendors[vendor]
        assert entry["hf_orgs"] and entry["vendor_domains"] and entry["model_name_patterns"]
    for rt in ("llama.cpp", "vllm", "sglang", "ollama", "lmstudio", "tgi", "mlx-lm", "trtllm", "basalt", "strata",
               "generic"):
        assert catalog.runtime(rt)["default_base_url"].startswith("http://127.0.0.1:")


@pytest.mark.parametrize("model,vendor", [
    ("Qwen3-30B-A3B-Instruct", "qwen"), ("deepseek-ai/DeepSeek-V3.2", "deepseek"), ("Kimi-K2-Thinking", "moonshot"),
    ("mistral-small-3.2", "mistral"), ("GLM-4.5-Air", "zhipu"), ("MiniMax-M2", "minimax"),
    ("meta-llama/Llama-3.3-70B", "meta"), ("gemma-3-27b-it", "google"), ("phi-4", "microsoft"),
    ("gpt-oss-120b", "openai"), ("Llama-3.1-Nemotron-70B", "nvidia"), ("command-r-plus", "cohere"),
    ("granite-3.3-8b", "ibm"), ("Yi-1.5-34B", "01ai"), ("ERNIE-4.5-300B", "baidu"),
    ("Hunyuan-A13B", "tencent"), ("MiMo-7B-RL", "xiaomi"), ("step-3.5-flash", "stepfun"),
])
def test_detect_vendor_from_model_name(catalog, model, vendor):
    assert catalog.detect_vendor(model)["id"] == vendor


def test_detect_vendor_unknown_and_empty(catalog):
    assert catalog.detect_vendor("my-private-finetune") is None
    assert catalog.detect_vendor("") is None


def test_domain_matching_is_on_label_boundaries():
    assert domain_matches("api.deepseek.com", "deepseek.com")
    assert domain_matches("deepseek.com", "deepseek.com")
    assert not domain_matches("notdeepseek.com", "deepseek.com")
    assert not domain_matches("deepseek.com.example.org", "deepseek.com")


def test_classify_vendor_hosted_hub_and_runtime_hosts(catalog):
    tags = {m.tag: m.severity for m in catalog.classify_host("api.deepseek.com")}
    assert tags == {"vendor_domain:deepseek": "medium"}
    assert any(m.tag.startswith("hosted_api:") for m in catalog.classify_host("api.together.xyz"))
    assert {m.tag: m.severity for m in catalog.classify_host("huggingface.co")} == {"hub_domain:huggingface": "info"}
    tags = {m.tag: m.severity for m in catalog.classify_host("registry.ollama.ai", runtime_id="ollama")}
    assert tags["known_runtime_call:ollama"] == "info"
    assert catalog.classify_host("example.org") == []


def test_own_loopback_and_allowed_hosts_are_not_classified(catalog):
    assert catalog.classify_host("127.0.0.1") == []
    assert catalog.classify_host("api.deepseek.com", own_hosts={"api.deepseek.com"}) == []
    allowed = Catalog(merge(catalog.data, {"allow_domains": ["deepseek.com"]}))
    assert allowed.classify_host("api.deepseek.com") == []


def test_merge_replaces_adds_and_removes(catalog):
    local = {"vendors": [
        {"id": "qwen", "region_note": "changed"},
        {"id": "acme", "name": "Acme", "hf_orgs": ["acme"], "vendor_domains": ["acme.example"],
         "model_name_patterns": ["^acme-"]},
        {"id": "xai", "remove": True}],
        "runtimes": [{"id": "myserver", "name": "My server", "kind": "openai",
                      "default_base_url": "http://127.0.0.1:5000"}]}
    merged = Catalog(merge(catalog.data, local))
    assert merged.vendors["qwen"]["region_note"] == "changed"
    assert merged.vendors["qwen"]["vendor_domains"] == catalog.vendors["qwen"]["vendor_domains"]
    assert "xai" not in merged.vendors
    assert merged.detect_vendor("acme-7b")["id"] == "acme"
    assert [m.tag for m in merged.classify_host("www.acme.example")] == ["vendor_domain:acme"]
    assert merged.runtime("myserver")["default_base_url"] == "http://127.0.0.1:5000"
    assert "acme" not in catalog.vendors                    # the built-in data is not mutated


def test_load_catalog_reads_local_file_and_rejects_bad_ones(tmp_path):
    path = tmp_path / "vendors.local.json"
    path.write_text(json.dumps({"vendors": [{"id": "acme", "name": "Acme", "vendor_domains": ["acme.example"]}]}))
    assert "acme" in load_catalog(path).vendors
    path.write_text("{not json")
    with pytest.raises(VendorsError):
        load_catalog(path)
    path.write_text(json.dumps({"vendors": [{"name": "no id"}]}))
    with pytest.raises(VendorsError):
        load_catalog(path)


def test_unknown_runtime_lists_the_known_ones(catalog):
    with pytest.raises(VendorsError, match="known:"):
        catalog.runtime("nope")
    assert catalog.runtime("llama-server")["id"] == "llama.cpp"


def test_preset_config_for_every_runtime_loads(tmp_path, catalog):
    for rt in catalog.runtimes:
        raw = preset_config(catalog, rt, "Qwen3-8B")
        path = tmp_path / f"{rt}.json"
        path.write_text(json.dumps(raw))
        cfg = load_config(path)
        assert cfg.runtime == catalog.runtime(rt)["id"] and cfg.vendor == "qwen"
        if rt == "basalt":
            assert cfg.monitor and cfg.network_watch is None
        else:
            assert cfg.monitor is None and cfg.network_watch["mode"] == "builtin"


def test_network_watch_forms(tmp_path):
    base = {"target": {"base_url": "http://127.0.0.1:1", "model": "m"}}
    cfg = build_config({**base, "network_watch": "builtin"}, tmp_path)
    assert cfg.network_watch["mode"] == "builtin" and cfg.monitor is None
    cfg = build_config({**base, "network_watch": "http://127.0.0.1:8098"}, tmp_path)
    assert cfg.network_watch["mode"] == "external" and cfg.monitor["base_url"] == "http://127.0.0.1:8098"
    cfg = build_config({**base, "network_watch": {"command": "mon --x", "base_url": "http://127.0.0.1:8098"}}, tmp_path)
    assert cfg.network_watch["command"] == "mon --x"
    with pytest.raises(ConfigError):
        build_config({**base, "network_watch": "somecommand"}, tmp_path)
    with pytest.raises(ConfigError):
        build_config({**base, "network_watch": {"command": "x"}}, tmp_path)
    with pytest.raises(ConfigError):
        build_config({**base, "network_watch": "builtin", "monitor": {"base_url": "http://127.0.0.1:1"}}, tmp_path)
    with pytest.raises(ConfigError):
        build_config({**base, "network_watch": {"bogus": 1}}, tmp_path)


def test_runner_tags_vendor_domain_hosts(tmp_path, fake_factory):
    fake = fake_factory("honest")
    cfg = make_cfg(tmp_path, fake.url, monitor={"base_url": fake.url, "api_key": ""}, runtime="llama.cpp",
                   vendors_file=str(tmp_path / "none.json"))
    import time
    now = time.time()

    class Spy(Runner):
        def _observe(self, number, role, t0, t1, prompt, plan, matcher):
            fake.events.append({"ts": time.time(), "host": "api.deepseek.com"})
            fake.events.append({"ts": time.time(), "host": "huggingface.co"})
            fake.events.append({"ts": time.time(), "host": "example.org"})
            return super()._observe(number, role, t0, time.time() + 1, prompt, plan, matcher)

    Spy(cfg).run(max_sessions=1)
    rows = read_findings(cfg.state_dir / "findings.jsonl")
    by_kind = {r["kind"]: r for r in rows}
    assert by_kind["vendor_domain:deepseek"]["severity"] == "medium"
    assert by_kind["hub_domain:huggingface"]["severity"] == "info"
    assert by_kind["vendor_domain:deepseek"]["evidence"]["host"] == "api.deepseek.com"
    assert now  # silence linters


def test_cli_presets_and_init_runtime(tmp_path, capsys):
    assert main(["presets"]) == 0
    out = capsys.readouterr().out
    assert "llama.cpp" in out and "moonshot" in out
    assert main(["init", "--dir", str(tmp_path), "--runtime", "vllm", "--model", "deepseek-ai/DeepSeek-V3.2"]) == 0
    cfg = load_config(tmp_path / "canary.json")
    assert cfg.runtime == "vllm" and cfg.vendor == "deepseek" and cfg.target["base_url"] == "http://127.0.0.1:8000"
    assert main(["init", "--dir", str(tmp_path), "--runtime", "nope", "--force"]) == 2
    assert main(["init", "--dir", str(tmp_path), "--runtime", "vllm", "--vendor", "nope", "--force"]) == 2
