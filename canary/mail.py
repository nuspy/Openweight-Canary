"""Credible e-mail addresses for the fake documents and files.

An address is made of a person and the domain of an organisation related to the session: `first.last@domain`. The people of the catalog get the
address their name gives; ordinary staff and the contacts named in documents get a plausible invented name. Nothing here sends or reads mail: the
addresses are only text, and the fake mail tool of a harness records what it is asked to send."""
from __future__ import annotations

import random
import re
import unicodedata

RANKS = {"admiral", "general", "lieutenant", "major", "colonel", "dr", "dr.", "professor", "prof", "prof.", "chancellor", "minister", "secretary", "director"}
PARTICLES = {"von", "van", "der", "den", "de", "da", "di", "del", "la", "le", "al", "bin"}
FIRST = {
    "en": ["daniel", "emma", "oliver", "sophie", "marcus", "nina", "ethan", "claire", "owen", "hannah", "lucas", "megan", "adrian", "laura", "felix", "irene"],
    "eu": ["matthias", "elena", "jonas", "chiara", "henrik", "ana", "luc", "sofia", "pieter", "marta", "tomas", "ines", "stefan", "klara", "anselm", "mathilde"],
    "ru": ["ivan", "elena", "sergei", "olga", "dmitri", "natalia", "pavel", "irina", "andrei", "tatiana", "viktor", "maria", "oleg", "anna", "nikolai", "svetlana"],
    "zh": ["wei", "li", "jun", "mei", "hao", "xin", "ming", "yan", "tao", "lin", "bo", "fang", "kai", "ying", "peng", "hui"],
}
LAST = {
    "en": ["hartley", "whitcombe", "ellison", "prescott", "garrison", "holloway", "kendrick", "ashby", "mercer", "langford", "rourke", "sutherland", "calloway", "denning", "farrow", "winslow"],
    "eu": ["bergmann", "lindqvist", "moretti", "vandenberg", "aaltonen", "ferreira", "kovac", "haddad", "novak", "silva", "keller", "moreau", "jansen", "rossi", "dubois", "weber"],
    "ru": ["petrov", "sokolov", "morozov", "volkov", "lebedev", "kuznetsov", "orlov", "zaitsev", "belov", "tarasov", "markov", "fomin", "gusev", "titov", "danilov", "yakovlev"],
    "zh": ["zhang", "liu", "chen", "yang", "huang", "zhao", "wu", "zhou", "xu", "sun", "ma", "zhu", "hu", "guo", "he", "gao"],
}
VALID = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$")


def valid_domain(text: str) -> bool:
    return bool(VALID.match(str(text or "").strip().lower()))


def region_of(domain: str) -> str:
    """Which names look natural at this domain."""
    d = domain.lower()
    if d.endswith((".cn", ".tw", ".hk")) or d in ("tsmc.com", "tel.com"):
        return "zh"
    if d.endswith((".ru", ".su")):
        return "ru"
    if d.endswith((".de", ".fr", ".it", ".nl", ".es", ".eu", ".ch", ".fi", ".se", ".pl")) or d in ("asml.com", "st.com", "siemens.com"):
        return "eu"
    return "en"


def _ascii(text: str) -> str:
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()


def local_part(name: str) -> str:
    """`first.last` from a written name: ranks dropped, accents folded, initials joined (C. C. Wei -> cc.wei)."""
    tokens = [t for t in re.split(r"\s+", _ascii(name).strip()) if t and t.lower().strip(".") not in RANKS]
    if len(tokens) < 2:
        return re.sub(r"[^a-z0-9.-]", "", (tokens[0] if tokens else "contact").lower())
    initials = []
    while tokens and re.fullmatch(r"[A-Za-z]\.?", tokens[0]) and len(tokens) > 1:
        initials.append(tokens.pop(0).strip(".").lower())
    first = "".join(initials) if initials and len(tokens) == 1 else re.sub(r"[^a-z0-9-]", "", tokens[0].lower())
    surname = [tokens[-1]]
    while len(tokens) > len(surname) + 1 and tokens[-len(surname) - 1].lower() in PARTICLES:       # von der Leyen, van der Linde
        surname.insert(0, tokens[-len(surname) - 1])
    last = "-".join(re.sub(r"[^a-z0-9-]", "", t.lower()) for t in surname)
    return f"{first}.{last}" if len(tokens) > 1 or initials else last


def address_for(name: str, domain: str) -> str:
    """The address a named person has at that domain, or '' when no domain is known."""
    return f"{local_part(name)}@{domain.lower()}" if name and valid_domain(domain) else ""


def invented_name(rng: random.Random, domain: str) -> str:
    region = region_of(domain)
    return f"{rng.choice(FIRST[region]).title()} {rng.choice(LAST[region]).title()}"


def invented_address(rng: random.Random, domain: str) -> str:
    """A plausible address of someone who does not exist, at `domain`."""
    region = region_of(domain)
    return f"{rng.choice(FIRST[region])}.{rng.choice(LAST[region])}@{domain.lower()}"
