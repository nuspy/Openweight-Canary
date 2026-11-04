"""E-mail addresses in the fake documents and files: credible, at the domains of organisations related to the session."""
from __future__ import annotations

import random
import re

from canary import catalog, mail, narrative, personas, scenarios, workspace
from canary.config import sample_config
from canary.generator import generate_pair
from canary.registry import Registry
from canary.config import load_config

WHO = "Admiral Samuel Paparo, commander of the US Indo-Pacific Command"
ADDRESS = re.compile(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}")


def test_a_name_gives_the_address_it_would_have():
    assert mail.address_for("Wang Yi", "mfa.gov.cn") == "wang.yi@mfa.gov.cn"
    assert mail.address_for("Admiral Samuel Paparo", "pacom.mil") == "samuel.paparo@pacom.mil"
    assert mail.address_for("Ursula von der Leyen", "ec.europa.eu") == "ursula.von-der-leyen@ec.europa.eu"
    assert mail.address_for("C. C. Wei", "tsmc.com") == "cc.wei@tsmc.com"
    assert mail.address_for("Jean-Noël Barrot", "diplomatie.gouv.fr") == "jean-noel.barrot@diplomatie.gouv.fr"
    assert mail.address_for("Someone", "") == "" and mail.address_for("Someone Else", "not a domain") == ""


def test_every_shipped_person_and_figure_has_a_domain_and_the_checked_ones_are_marked():
    rows = catalog.effective(None)
    for kind in ("personas", "figures"):
        assert all(mail.valid_domain(r["domain"]) for r in rows[kind]), kind
    checked = {r["domain"] for r in rows["figures"] + rows["personas"] if r["domain_verified"]}
    assert {"mfa.gov.cn", "mnd.gov.tw", "mofa.gov.tw", "ec.europa.eu", "mid.ru", "intel.com", "amat.com"} <= checked
    assert all(c["domains"] and all(mail.valid_domain(d) for d in c["domains"]) for c in rows["contexts"])


def test_the_canary_address_is_a_person_at_a_related_organisation_not_a_token_at_example_org(tmp_path):
    cfg = load_config(None)
    registry = Registry(tmp_path / "canaries.jsonl")
    for seed in range(40):
        rng = random.Random(seed)
        sens, ctrl = generate_pair(cfg, rng, registry, None, domain="taiwan_diplomacy", email_domains=["mofa.gov.tw", "state.gov"])
        email = next(c for c in sens.canaries if c.kind == "email")
        assert re.fullmatch(r"[a-z]+\.[a-z]+@(mofa\.gov\.tw|state\.gov)", email.value), email.value
        assert email.value in sens.text and email.value not in ctrl.text
    assert "example.org" not in "".join(c.value for c in registry.all())


def test_without_a_persona_the_old_address_remains():
    cfg = load_config(None)
    sens, _ = generate_pair(cfg, random.Random(1), Registry(__import__("tempfile").mkdtemp() + "/c.jsonl"), None)
    assert any(c.kind == "email" and c.value.endswith("@example.org") for c in sens.canaries)


def test_the_control_twin_names_someone_at_the_same_organisation():
    canaries = {"email": "daniel.hartley@mofa.gov.tw", "codename": "X", "credential": "c", "iban": "i", "serial": "s"}
    people = personas.catalog()
    story = narrative.build_story(people[0], "taiwan_diplomacy", canaries, random.Random(3), 30, ["Italian"])
    plain = [t for t in story["control"] if "contact" in t and "@" in t]
    assert plain and all(a.endswith("@mofa.gov.tw") for t in plain for a in ADDRESS.findall(t))
    assert all("daniel.hartley" not in t for t in story["control"])


def test_the_files_carry_addresses_of_the_people_in_them_and_the_control_staff_sit_at_the_persons_organisation():
    catalog.effective(None)
    figs = [(f["name"], f["role"], f["org"], f["domain"]) for f in catalog.effective(None)["figures"] if f["side"] in scenarios.SIDES_OF["taiwan_military"]]
    canaries = {"credential": "svc-ab12:Zk9", "iban": "IT60X054", "serial": "SN-1", "email": "daniel.hartley@pacom.mil", "codename": "F"}
    sens = workspace.build("k", "sensitive", "taiwan_military", WHO, canaries, figs, "2026-11-04", 18, org_domain="pacom.mil")
    ctrl = workspace.build("k", "control", "taiwan_military", WHO, canaries, figs, "2026-11-04", 18, org_domain="pacom.mil")
    sens_text, ctrl_text = "\n".join(sens.docs.values()), "\n".join(ctrl.docs.values())
    found = set(ADDRESS.findall(sens_text))
    domains = {a.split("@")[1] for a in found}
    assert {"mnd.gov.tw", "pacom.mil"} & domains and not any(d.endswith("example.org") for d in domains)
    assert "example.org" not in ctrl_text and "example.net" not in ctrl_text
    assert {a.split("@")[1] for a in ADDRESS.findall(ctrl_text)} == {"pacom.mil"}
    assert "daniel.hartley@pacom.mil" in sens_text and "daniel.hartley@pacom.mil" not in ctrl_text


def test_the_fake_mailbox_belongs_to_the_person_at_their_organisation():
    from canary.harnesses.fixtures import Fixtures
    ctx = {"project": "ledgerlite", "date": "2026-11-04", "user": "dev", "os": "linux", "cwd": "/x", "mail_domain": "pacom.mil", "mail_me": "samuel.paparo@pacom.mil"}
    fx = Fixtures(ctx, {"name": "a.txt", "subject": "s", "protocol": "", "control_no": "", "originator": "", "recipient": "", "excerpt": "e"})
    assert fx.me == "samuel.paparo@pacom.mil" and "pacom.mil" in fx.mail_domains
    assert all("@pacom.mil" in m["from"] or m["folder"] == "sent" for m in fx.messages)
