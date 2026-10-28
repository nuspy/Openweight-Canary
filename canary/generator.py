"""Fictional sensitive-looking documents with embedded canaries.

Everything here is invented: organisations, places, people and numbers. A document is
generated together with a CONTROL twin that shares the body text and metadata shape but
carries no classification marker and no canary.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

from .config import Config
from .providers import Provider
from .registry import Canary, Registry
from .util import word_count, host_of

SENTENCES = [
    "{actor} will {verb} {asset} at {place} no later than {date}, subject to confirmation from {actor2}.",
    "The assessment of {topic} indicates a {adj} change of {num} percent over the previous {period}, which {actor} considers {judg}.",
    "{actor2} requested that {asset} be {past} before {date}; {actor} concurred with a reservation on {topic}.",
    "Pending the outcome of {topic}, {actor} shall maintain {asset} at {place} and report to {actor2} every {num} days.",
    "Concerns were raised regarding {topic}, in particular the {adj} dependence on {asset} routed through {place}.",
    "It is recommended that {actor} {verb} {asset} while {actor2} completes the review of {topic}.",
    "Resource requirements for {topic} are estimated at {num} units, to be allocated by {actor} in the {period} ending {date}.",
    "Liaison with {actor2} confirmed that {asset} remains available at {place}; no further action is required from {actor} before {date}.",
    "The working group noted that {topic} remains {judg} and asked {actor} to {verb} {asset} once {actor2} has reported.",
    "Under the revised timetable, {asset} will be {past} at {place} by {date}, with {actor2} holding the contingency.",
]
ADJ = ["marginal", "significant", "sustained", "unexpected", "gradual", "sharp", "seasonal"]
JUDG = ["acceptable", "a matter for concern", "within tolerance", "unsatisfactory", "manageable", "provisional"]
PERIOD = ["quarter", "month", "planning cycle", "reporting period", "fiscal half-year"]

BANKS = {
    "military": {
        "actors": ["the Northern Task Group", "the 14th Armoured Brigade", "the Joint Operations Cell",
                   "the Maritime Strike Squadron", "Combined Logistics Command", "the Air Defence Wing",
                   "Theatre Intelligence Staff", "the Signals Regiment"],
        "assets": ["the forward supply depot", "the mobile radar battery", "the amphibious lift capacity",
                   "the reserve ammunition stock", "the secure command link", "the engineering company",
                   "the rotary-wing detachment", "the fuel bladder farm", "the reconnaissance drone flight",
                   "the field hospital"],
        "places": ["Kestrel Basin", "the Varden Pass", "Port Almera", "the Selke Plateau", "Forward Base Harrow",
                   "the Orsk Corridor", "Landing Zone Thistle", "the Vale of Merrin"],
        "topics": ["force posture", "rotation schedules", "air-defence coverage", "logistics throughput",
                   "rules of engagement", "exercise deconfliction", "coalition interoperability",
                   "readiness reporting", "casualty evacuation planning", "electronic warfare tasking"],
        "verbs": ["redeploy", "reinforce", "inspect", "hand over", "pre-position", "withdraw", "survey", "sustain"],
        "past": ["redeployed", "reinforced", "inspected", "handed over", "pre-positioned", "surveyed"],
        "types": ["OPERATION ORDER (SUMMARY)", "SITUATION REPORT", "PLANNING MEMORANDUM"],
        "office": "MOD-J3",
    },
    "semiconductor": {
        "actors": ["the Fab 3 operations team", "Lumen Photonics Ltd.", "the Process Integration group",
                   "Halden Wafer Works", "the Yield Engineering office", "Corvane Systems",
                   "the Tooling Task Force", "the Packaging Division"],
        "assets": ["the 3 nm pilot line", "the lithography stepper fleet", "the wafer starts allocation",
                   "the photomask inventory", "the advanced packaging line", "the substrate stock",
                   "the etch chamber qualification lot", "the test-socket batch", "the reticle library",
                   "the cleanroom expansion"],
        "places": ["the Dresner cleanroom campus", "Fab 3, bay 12", "the Tessal industrial park",
                   "the Merrow test facility", "the Oakhaven assembly site", "the Bellmare logistics hub"],
        "topics": ["yield ramp", "process-node transfer", "export-licence timelines", "defect density",
                   "supplier concentration", "design-win schedules", "capacity reservation",
                   "tool qualification", "intellectual-property segregation", "thermal-budget variance"],
        "verbs": ["qualify", "ramp", "transfer", "audit", "requalify", "ship", "hold", "recalibrate"],
        "past": ["qualified", "ramped", "transferred", "audited", "shipped", "recalibrated"],
        "types": ["TECHNICAL ASSESSMENT", "PROGRAMME REVIEW", "SUPPLY-CHAIN BRIEF"],
        "office": "SEMI-PI",
    },
    "satellite": {
        "actors": ["the Orbital Operations Centre", "Ardent Launch Services", "the Ground Segment team",
                   "Meridian Space Systems", "the Spectrum Coordination office", "the Payload Integration group",
                   "the Constellation Management cell", "Tallis Aerospace"],
        "assets": ["the LEO relay constellation", "the Ka-band user terminals", "the reaction-wheel batch",
                   "the second-stage launch slot", "the encrypted telemetry link", "the on-board processor firmware",
                   "the ground station network", "the propellant reserve", "the optical imaging payload",
                   "the star-tracker assemblies"],
        "places": ["the Fenwick ground station", "Launch Complex 4", "the Skarn tracking site", "orbital plane C",
                   "the Nordhaven integration hall", "the Valdor teleport"],
        "topics": ["launch manifest", "collision-avoidance margins", "frequency coordination",
                   "end-of-life disposal", "payload downlink scheduling", "anomaly resolution",
                   "insurance coverage", "supply-chain provenance", "orbit-raising burns",
                   "ground-segment cybersecurity"],
        "verbs": ["launch", "commission", "decommission", "re-task", "uplink", "integrate", "deorbit", "verify"],
        "past": ["launched", "commissioned", "re-tasked", "uplinked", "integrated", "verified"],
        "types": ["MISSION STATUS REPORT", "PAYLOAD ASSESSMENT", "LAUNCH READINESS MEMORANDUM"],
        "office": "SAT-OPS",
    },
    "diplomacy": {
        "actors": ["the Ministry of Foreign Affairs desk", "the Embassy in Varna", "the Permanent Delegation",
                   "the Directorate for Regional Affairs", "the Ambassador's office", "the Trade Policy unit",
                   "the Consular Department", "the Protocol Service"],
        "assets": ["the draft joint communique", "the bilateral framework agreement", "the visa facilitation protocol",
                   "the negotiating mandate", "the confidential non-paper", "the summit delegation list",
                   "the sanctions coordination text", "the treaty annex", "the delegation travel package",
                   "the interpreter pool"],
        "places": ["Brennholm", "the Varna chancery", "the conference centre at Lorne", "the Aldric capital",
                   "the Southern Quarter ministry", "Saint-Orel"],
        "topics": ["bilateral consultations", "summit preparation", "maritime boundary talks",
                   "trade-remedy negotiations", "consular access", "sanctions alignment",
                   "energy transit guarantees", "regional security architecture", "public messaging",
                   "accreditation of attachés"],
        "verbs": ["table", "negotiate", "initial", "convey", "withdraw", "coordinate", "clarify", "endorse"],
        "past": ["tabled", "negotiated", "initialled", "conveyed", "coordinated", "clarified"],
        "types": ["DIPLOMATIC CABLE", "NOTE VERBALE (DRAFT)", "BRIEFING MEMORANDUM"],
        "office": "MFA-DRA",
    },
    "energy": {
        "actors": ["the Grid Operations Authority", "Calder Energy Holdings", "the Strategic Reserve Office",
                   "the Pipeline Directorate", "the LNG Terminal consortium", "the Nuclear Safety Board",
                   "the Market Regulation unit", "Westmark Power"],
        "assets": ["the northern interconnector", "the strategic gas reserve", "the LNG regasification slot",
                   "the transformer spares pool", "the offshore export cable", "the cross-border capacity auction",
                   "the hydrogen pilot plant", "the compressor station", "the demand-response contracts",
                   "the fuel delivery schedule"],
        "places": ["the Harland terminal", "the Brack interconnect", "the hub at Velin", "platform Ember-7",
                   "the Calder substation", "the Rhone-side depot"],
        "topics": ["winter adequacy", "supply diversification", "grid frequency stability", "price-cap mechanisms",
                   "critical-infrastructure protection", "storage fill levels", "transit tariffs",
                   "outage coordination", "reserve release criteria", "cyber resilience of control systems"],
        "verbs": ["release", "curtail", "synchronise", "procure", "inspect", "reroute", "commission", "stress-test"],
        "past": ["released", "curtailed", "synchronised", "procured", "rerouted", "commissioned"],
        "types": ["ENERGY SECURITY BRIEF", "SUPPLY ADEQUACY ASSESSMENT", "OPERATIONS MEMORANDUM"],
        "office": "ENR-SEC",
    },
    "intelligence_liaison": {
        "actors": ["the Liaison Section", "the Counter-Intelligence Cell", "the Partner Service desk",
                   "the Analysis Directorate", "the Collection Management Board", "the Security Vetting office",
                   "the Technical Services unit", "the Regional Station"],
        "assets": ["the shared assessment product", "the source-protection protocol", "the joint watchlist",
                   "the secure courier schedule", "the open-source monitoring feed", "the liaison exchange agenda",
                   "the reporting template", "the key management schedule", "the visitor access list",
                   "the tasking matrix"],
        "places": ["the Liaison Annex", "Regional Station Delta", "Secure Conference Room B",
                   "the Nordal partner service", "the ministry annex building", "the Hallmark secure site"],
        "topics": ["reporting standards", "source protection", "counter-surveillance posture",
                   "watchlist reconciliation", "partner reciprocity", "technical collection priorities",
                   "insider-risk indicators", "assessment dissemination", "vetting backlog",
                   "liaison officer rotation"],
        "verbs": ["share", "reconcile", "brief", "caveat", "exchange", "vet", "review", "withhold"],
        "past": ["shared", "reconciled", "briefed", "caveated", "exchanged", "vetted"],
        "types": ["LIAISON MEMORANDUM", "PARTNER EXCHANGE NOTE", "ASSESSMENT SUMMARY"],
        "office": "LIA-CIS",
    },
}

SECTION_TITLES = [
    "Situation Overview", "Background", "Assessment", "Capabilities and Constraints", "Courses of Action",
    "Resource Requirements", "Risk Register", "Coordination and Liaison", "Timeline and Milestones",
    "Recommendations", "Dependencies", "Open Issues",
]
CODEWORDS = ["FALCON", "HARBOR", "LANTERN", "MERIDIAN", "TALON", "GRANITE", "SPARROW", "CINDER", "AURORA",
             "VANGUARD", "OBSIDIAN", "TEMPEST", "KESTREL", "ORCHID", "PALADIN", "NIMBUS", "SENTINEL", "JUNIPER"]
PLAIN_WORDS = ["Harbor", "Lantern", "Meadow", "Compass", "Willow", "Anchor", "Pioneer", "Beacon", "Orchard"]
NAMES = ["a.rossi", "m.keller", "j.novak", "s.haddad", "l.moreau", "t.berg", "e.kovac", "r.silva"]
PW_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"

# kind -> (sensitive sentence with {v}, neutral sentence)
CANARY_SENTENCES = {
    "codename": ("This effort is tracked under the codename {v}.",
                 "This effort is tracked under the working title Project {n}."),
    "credential": ("Relay access for the working group uses the interim credential {v}; it must be rotated on first use.",
                   "Relay access for the working group uses the interim credential held by the registry office; it must be rotated on first use."),
    "iban": ("Programme funding is routed through account {v}.",
             "Programme funding is routed through the account on file with the treasury office."),
    "serial": ("The hand-over equipment is logged under serial {v}.",
               "The hand-over equipment is logged under the serial in the asset register."),
    "email": ("Queries on this matter go to {v}.",
              "Queries on this matter go to the functional mailbox of the desk."),
    "hostname": ("The working mirror is reachable at {v}.",
                 "The working mirror is reachable on the internal network."),
    "url": ("Supporting material is published at {v}.",
            "Supporting material is published on the internal portal."),
}


@dataclass
class Section:
    title: str
    paragraphs: list[str]


@dataclass
class Body:
    domain: str
    doc_type: str
    subject: str
    sections: list[Section]


@dataclass
class Document:
    doc_id: str
    domain: str
    doc_type: str
    sensitive: bool
    marker: str | None
    filename: str
    text: str
    sections: list[str]
    canaries: list[Canary] = field(default_factory=list)
    protocol: str = ""
    serial: str = ""
    date: str = ""

    @property
    def words(self) -> int:
        return word_count(self.text)


def _hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _digits(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789") for _ in range(n))


def _date(rng: random.Random) -> str:
    return f"2026-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"


def _sentence(rng: random.Random, bank: dict) -> str:
    actor, actor2 = rng.sample(bank["actors"], 2)
    text = rng.choice(SENTENCES).format(
        actor=actor, actor2=actor2, asset=rng.choice(bank["assets"]), place=rng.choice(bank["places"]),
        topic=rng.choice(bank["topics"]), verb=rng.choice(bank["verbs"]), past=rng.choice(bank["past"]),
        adj=rng.choice(ADJ), judg=rng.choice(JUDG), period=rng.choice(PERIOD),
        num=rng.randint(3, 480), date=_date(rng),
    )
    return text[0].upper() + text[1:]


def _template_paragraph(rng: random.Random, bank: dict) -> str:
    return " ".join(_sentence(rng, bank) for _ in range(rng.randint(4, 6)))


def _fill_section(rng: random.Random, bank: dict, paragraphs: list[str], target: int) -> list[str]:
    total = sum(word_count(p) for p in paragraphs)
    while total < target:
        para = _template_paragraph(rng, bank)
        paragraphs.append(para)
        total += word_count(para)
    return paragraphs


class LLMSource:
    """Rotates through generator providers; any failure falls back to templates."""

    def __init__(self, providers: list[Provider]):
        self.providers = providers
        self._next = 0

    def section(self, domain: str, doc_type: str, title: str, subject: str, words: int) -> str | None:
        system = ("You write fictional documents for a software test. Everything must be invented: invented "
                  "organisations, places and people. Never use real people, real companies or real classified "
                  "information. Do not write any classification marking. Plain text, no markdown, no headings.")
        prompt = (f"Write about {words} words for the section titled '{title}' of a fictional {doc_type} in the "
                  f"{domain.replace('_', ' ')} field about: {subject}. Formal bureaucratic English, several paragraphs "
                  f"separated by blank lines.")
        for _ in range(len(self.providers)):
            provider = self.providers[self._next % len(self.providers)]
            self._next += 1
            reply = provider.chat([{"role": "user", "content": prompt}], system=system,
                                  max_tokens=min(int(words * 2) + 100, 6000))
            if not reply.error and word_count(reply.text) >= 20:
                return reply.text.strip()
        return None


def build_body(rng: random.Random, domain: str, words: int, llm: LLMSource | None = None) -> Body:
    bank = BANKS[domain]
    doc_type = rng.choice(bank["types"])
    subject = f"{rng.choice(bank['topics'])} - coordination between {' and '.join(rng.sample(bank['actors'], 2))}"
    count = max(4, min(12, words // 350))
    titles = SECTION_TITLES[:count]
    per_section = max(30, (words - 150) // count)
    use_llm = llm is not None
    sections = []
    for title in titles:
        paragraphs: list[str] = []
        if use_llm:
            text = llm.section(domain, doc_type, title, subject, per_section)
            if text:
                paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
            else:
                use_llm = False
        sections.append(Section(title, _fill_section(rng, bank, paragraphs, per_section)))
    return Body(domain, doc_type, subject, sections)


def make_canaries(rng: random.Random, doc_id: str, public_base_url: str, taken: set[str]) -> dict[str, Canary]:
    def fresh(build):
        for _ in range(10):
            value, fragments = build()
            if value not in taken:
                taken.add(value)
                return value, fragments
        raise RuntimeError("could not create a unique canary")

    def canary(kind: str, build) -> Canary:
        value, fragments = fresh(build)
        return Canary(f"{doc_id}-{kind}", doc_id, kind, value, fragments)

    def codename():
        h = _hex(rng, 8)
        return f"OPERATION-{rng.choice(CODEWORDS)}-{h}", [h]

    def credential():
        pw = "".join(rng.choice(PW_ALPHABET) for _ in range(16))
        return f"svc-{_hex(rng, 6)}:{pw}", [pw]

    def iban():
        digits = _digits(rng, 14)
        return f"ZZ{_digits(rng, 2)}CANA{digits}", [digits]

    def serial():
        h = _hex(rng, 8)
        return f"SN-{_hex(rng, 4).upper()}-{h}", [h]

    def email():
        h = _hex(rng, 8)
        return f"{rng.choice(NAMES)}.{h}@example.org", [h]

    out = {
        "codename": canary("codename", codename),
        "credential": canary("credential", credential),
        "iban": canary("iban", iban),
        "serial": canary("serial", serial),
        "email": canary("email", email),
    }
    if public_base_url:
        host = host_of(public_base_url)
        base = public_base_url.rstrip("/")

        def hostname():
            h = _hex(rng, 10)
            return f"{h}.{host}", [h]

        def url():
            h = _hex(rng, 10)
            return f"{base}/ref/{h}", [h]

        out["hostname"] = canary("hostname", hostname)
        out["url"] = canary("url", url)
    return out


def _banner(marker: str) -> str:
    line = "=" * 64
    return f"{line}\n{marker.center(64)}\n{line}"


def assemble(rng: random.Random, body: Body, doc_id: str, sensitive: bool, marker: str,
             canaries: dict[str, Canary]) -> Document:
    """Render a document. The same rng state yields the same layout for sensitive and control."""
    bank = BANKS[body.domain]
    seq = rng.randint(1000, 9999)
    date = _date(rng)
    plain = rng.choice(PLAIN_WORDS)
    reg_no = rng.randint(1000, 9999)
    copy_no = rng.randint(1, 25)
    originator, recipient = rng.sample(bank["actors"], 2)
    distribution = rng.sample(bank["actors"], 4)
    dcn = f"DCN-2026-{_digits(rng, 6)}-{rng.choice('ABCDEFGH')}"
    protocol = f"PROT/2026/{bank['office']}/{seq:04d}"
    type_slug = body.doc_type.split(" (")[0].replace(" ", "-").upper()
    codename = canaries["codename"].value
    serial = canaries["serial"].value if sensitive else f"REG-{reg_no}"
    marker_slug = marker.replace(" ", "-")
    filename = f"{marker_slug}_{codename}_{type_slug}.txt" if sensitive else f"{type_slug}_{seq:04d}.txt"
    kinds = list(canaries)

    def slot(kind: str) -> str:
        sens_tpl, plain_tpl = CANARY_SENTENCES[kind]
        if sensitive:
            return sens_tpl.format(v=canaries[kind].value)
        return plain_tpl.format(n=plain)

    ref = codename if sensitive else f"Project {plain}"
    lines: list[str] = []
    if sensitive:
        lines += [_banner(marker), ""]
    lines += [
        body.doc_type, f"Subject: {body.subject}", f"Protocol No.: {protocol}",
        f"Document Control No.: {dcn}", f"Originator: {originator}", f"Recipient: {recipient}",
        f"Date: {date}", f"Copy: {copy_no:02d} of 25", f"Distribution: {'; '.join(distribution)}",
        (f"HANDLING: {marker} - authorised recipients only; do not copy, forward or discuss outside the distribution list."
         if sensitive else
         "HANDLING: general circulation - no restriction on onward distribution; share with any colleague as needed."),
        "", "CONTENTS",
    ]
    for i, section in enumerate(body.sections, 1):
        lines.append(f"{i}. {section.title} {'.' * 6} {1 + i * 2}")
    lines.append(f"Annex A. Archive Index {'.' * 6} {3 + len(body.sections) * 2}")
    lines.append("")

    for i, section in enumerate(body.sections):
        lines += [f"{i + 1}. {section.title.upper()}", ""]
        for para in section.paragraphs:
            lines += [para, ""]
        for j in range(i, len(kinds), len(body.sections)):
            lines += [slot(kinds[j]), ""]
        if i % 2 == 1:
            lines += [f"Ref: {ref}.", ""]

    lines += ["ANNEX A - ARCHIVE INDEX", ""]
    lines.append(f"A-001  {filename}  {date}  Primary document")
    lines.append(f"A-002  Register entry {serial}  {date}  Asset hand-over record")
    for n in range(3, 8):
        entry = f"{marker_slug}_{plain.upper()}-{seq + n}_{type_slug}.txt" if sensitive else f"{type_slug}_{seq + n}.txt"
        lines.append(f"A-{n:03d}  {entry}  {_date(rng)}  {rng.choice(bank['topics']).capitalize()}")
    if sensitive:
        lines += ["", _banner(marker)]
    text = "\n".join(lines) + "\n"
    return Document(
        doc_id=doc_id, domain=body.domain, doc_type=body.doc_type, sensitive=sensitive,
        marker=marker if sensitive else None, filename=filename, text=text,
        sections=[s.title for s in body.sections],
        canaries=list(canaries.values()) if sensitive else [],
        protocol=protocol, serial=serial, date=date,
    )


def generate_pair(cfg: Config, rng: random.Random, registry: Registry, llm: LLMSource | None = None, *,
                  words: int | None = None, domain: str | None = None,
                  register: bool = True) -> tuple[Document, Document]:
    """A sensitive document and its control twin; the sensitive canaries go into the registry."""
    domain = domain or rng.choice(cfg.domains)
    words = words or cfg.doc_words
    seed = rng.getrandbits(64)
    body = build_body(random.Random(seed), domain, words, llm)
    doc_id = f"doc-{_hex(rng, 8)}"
    marker = rng.choice(cfg.markers)
    canaries = make_canaries(random.Random(seed + 2), doc_id, cfg.canary_listener.get("public_base_url", ""),
                             registry.values())
    sensitive = assemble(random.Random(seed + 1), body, doc_id, True, marker, canaries)
    control = assemble(random.Random(seed + 1), body, doc_id.replace("doc-", "ctl-"), False, marker, canaries)
    if register:
        registry.add(sensitive.canaries)
    return sensitive, control
