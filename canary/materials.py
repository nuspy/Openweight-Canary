"""Test materials: documents, archives with an INDEX, public sources, and matched controls."""
from __future__ import annotations

import io
import ipaddress
import logging
import random
import socket
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

from .config import Config
from .generator import Document, LLMSource, generate_pair
from .registry import Registry
from .util import LOOPBACK_HOSTS, append_jsonl, read_json, sha256_hex, slug, word_count, write_json

log = logging.getLogger("canary")

USER_AGENT = "openweight-canary/0.1 (leak-test harness; fetches public documents on request, low volume)"
MAX_DOWNLOAD = 5 * 1024 * 1024

SOURCES_SAMPLE = {
    "_comment": "PUBLIC documents only (declassified or openly published). All entries are unverified: edit me.",
    "sources": [
        {"name": "North Atlantic Treaty", "url": "https://www.nato.int/cps/en/natohq/official_texts_17120.htm",
         "note": "unverified, edit me"},
        {"name": "Avalon Project: Cuban Missile Crisis documents",
         "url": "https://avalon.law.yale.edu/subject_menus/cuban.asp", "note": "unverified, edit me"},
    ],
}


@dataclass
class Item:
    item_id: str
    kind: str  # document | archive | public
    role: str  # sensitive | control
    name: str
    text: str
    doc_ids: list[str] = field(default_factory=list)
    marker: str | None = None
    domain: str | None = None
    sections: list[str] = field(default_factory=list)
    path: str | None = None

    @property
    def words(self) -> int:
        return word_count(self.text)

    def meta(self) -> dict:
        return {"item_id": self.item_id, "kind": self.kind, "role": self.role, "name": self.name,
                "doc_ids": self.doc_ids, "marker": self.marker, "domain": self.domain,
                "words": self.words, "path": self.path}


def build_index(docs: list[Document], archive_name: str, sensitive: bool) -> str:
    marker = docs[0].marker
    lines = []
    if sensitive:
        lines += [marker.center(64), ""]
    lines += [f"ARCHIVE INDEX - {archive_name}", f"Entries: {len(docs)}", "",
              "No.   File name | Bytes | Protocol | Serial"]
    for i, doc in enumerate(docs, 1):
        lines.append(f"{i:03d}   {doc.filename} | {len(doc.text.encode('utf-8'))} | {doc.protocol} | {doc.serial}")
    if sensitive:
        lines += ["", marker.center(64)]
    return "\n".join(lines) + "\n"


def write_archive(path: Path, members: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.name.endswith(".zip"):
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, content in members.items():
                zf.writestr(name, content)
    else:
        with tarfile.open(path, "w:gz") as tf:
            for name, content in members.items():
                data = content.encode("utf-8")
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mtime = int(time.time())
                tf.addfile(info, io.BytesIO(data))


def read_archive(path: Path) -> dict[str, str]:
    members: dict[str, str] = {}
    if path.name.endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                members[name] = zf.read(name).decode("utf-8")
    else:
        with tarfile.open(path, "r:gz") as tf:
            for info in tf.getmembers():
                if info.isfile():
                    members[info.name] = tf.extractfile(info).read().decode("utf-8")
    return members


class MaterialStore:
    def __init__(self, cfg: Config, registry: Registry):
        self.cfg = cfg
        self.registry = registry
        self.root = cfg.state_dir / "materials"

    def public_files(self) -> list[Path]:
        folder = self.root / "public"
        return sorted(folder.glob("*.txt")) if folder.exists() else []

    def make_pair(self, rng: random.Random, llm: LLMSource | None = None,
                  kind: str | None = None) -> tuple[Item, Item]:
        if kind is None:
            roll = rng.random()
            if self.public_files() and roll < self.cfg.public_share:
                kind = "public"
            elif roll < self.cfg.public_share + self.cfg.archive_share:
                kind = "archive"
            else:
                kind = "document"
        pair = {"public": self._public, "archive": self._archive, "document": self._document}[kind](rng, llm)
        for item in pair:
            append_jsonl(self.root / "items.jsonl", item.meta())
        return pair

    def _save_doc(self, doc: Document) -> str:
        path = self.root / "docs" / doc.filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(doc.text, encoding="utf-8", newline="\n")
        return str(path)

    def _document(self, rng, llm) -> tuple[Item, Item]:
        sens, ctrl = generate_pair(self.cfg, rng, self.registry, llm)
        items = []
        for doc in (sens, ctrl):
            items.append(Item(f"itm-{doc.doc_id[4:]}-{'s' if doc.sensitive else 'c'}", "document",
                              "sensitive" if doc.sensitive else "control", doc.filename, doc.text,
                              [doc.doc_id], doc.marker, doc.domain, doc.sections, self._save_doc(doc)))
        return items[0], items[1]

    def _archive(self, rng, llm) -> tuple[Item, Item]:
        count = rng.randint(2, 4)
        pairs = [generate_pair(self.cfg, rng, self.registry, llm) for _ in range(count)]
        ext = rng.choice(["zip", "tar.gz"])
        out = []
        for idx, role in ((0, "sensitive"), (1, "control")):
            docs = [p[idx] for p in pairs]
            first = docs[0]
            if idx == 0:
                name = f"{first.marker.replace(' ', '-')}_{first.canaries[0].value}_ARCHIVE.{ext}"
            else:
                name = f"archive_{first.protocol.rsplit('/', 1)[-1]}.{ext}"
            index = build_index(docs, name, idx == 0)
            members = {"INDEX.txt": index, **{d.filename: d.text for d in docs}}
            path = self.root / "archives" / name
            write_archive(path, members)
            text = f"[archive: {name}]\n\n--- INDEX.txt ---\n{index}\n--- {first.filename} ---\n{first.text}"
            out.append(Item(f"itm-{first.doc_id[4:]}-a{role[0]}", "archive", role, name, text,
                            [d.doc_id for d in docs], first.marker, first.domain, first.sections, str(path)))
        return out[0], out[1]

    def _public(self, rng, llm) -> tuple[Item, Item]:
        path = rng.choice(self.public_files())
        meta = read_json(path.with_suffix(".json"), {})
        words = path.read_text(encoding="utf-8").split()[: self.cfg.doc_words]
        text = " ".join(words)
        _, ctrl = generate_pair(self.cfg, rng, self.registry, llm, words=max(len(words), 100), register=False)
        tag = sha256_hex(text)[:8]
        sens = Item(f"itm-pub-{tag}-s", "public", "sensitive", meta.get("name", path.stem), text,
                    [], None, None, [], str(path))
        control = Item(f"itm-pub-{tag}-c", "document", "control", ctrl.filename, ctrl.text,
                       [ctrl.doc_id], None, ctrl.domain, ctrl.sections, None)
        return sens, control


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip and data.strip():
            self.parts.append(data.strip())


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    parser.feed(html)
    return "\n".join(parser.parts)


def check_public_https(url: str) -> None:
    """Raise ValueError unless url is an https URL to a publicly routable host."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("only https URLs are fetched")
    host = parsed.hostname.lower()
    if host in LOOPBACK_HOSTS or host.endswith((".local", ".internal", ".localhost")):
        raise ValueError("local hosts are not fetched")
    try:
        addrs = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            addrs = {ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(host, 443)}
        except OSError as exc:
            raise ValueError(f"cannot resolve host: {exc}") from exc
    for addr in addrs:
        if not addr.is_global:
            raise ValueError("host resolves to a non-public address")


class _CheckedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_public_https(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_sources(sources_path: Path, dest: Path, timeout: float = 30) -> list[dict]:
    """Download the public URLs listed in sources.json; every failure is logged and skipped."""
    results: list[dict] = []
    data = read_json(sources_path)
    if not data:
        log.warning("no readable sources file at %s", sources_path)
        return results
    entries = data.get("sources", []) if isinstance(data, dict) else data
    opener = urllib.request.build_opener(_CheckedRedirect())
    dest.mkdir(parents=True, exist_ok=True)
    for entry in entries:
        url = entry.get("url", "") if isinstance(entry, dict) else str(entry)
        name = entry.get("name", url) if isinstance(entry, dict) else url
        result = {"name": name, "url": url, "ok": False}
        try:
            check_public_https(url)
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,text/plain"})
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read(MAX_DOWNLOAD + 1)
                ctype = resp.headers.get("Content-Type", "")
            if len(raw) > MAX_DOWNLOAD:
                raise ValueError("document larger than 5 MB")
            base = slug(name)[:60]
            if "html" in ctype or "text/plain" in ctype:
                body = raw.decode("utf-8", errors="replace")
                text = html_to_text(body) if "html" in ctype else body
                (dest / f"{base}.txt").write_text(text, encoding="utf-8", newline="\n")
                write_json(dest / f"{base}.json", {"name": name, "url": url, "content_type": ctype,
                                                   "sha256": sha256_hex(raw), "bytes": len(raw),
                                                   "fetched": time.time()})
                result.update(ok=True, file=f"{base}.txt", words=word_count(text))
            else:
                (dest / f"{base}.bin").write_bytes(raw)
                result.update(error=f"stored raw only (content type {ctype or 'unknown'} is not text)")
        except (ValueError, OSError, urllib.error.URLError) as exc:
            result["error"] = str(exc)
            log.warning("source skipped: %s: %s", name, exc)
        results.append(result)
        time.sleep(1.0 if result["ok"] else 0)
    return results
