/* On-device translation with Chrome's Translator API (Chrome 138 and later, desktop).
 *
 * The page is written in US English. The reader picks a preferred language (kept in this browser); Chrome translates the page on the
 * computer with a small model it downloads once, so the text never leaves the machine and no server is involved. Where the API does not exist
 * (Firefox, Safari, mobile browsers) nothing happens and the page stays in English.
 *
 * Block by block: a paragraph, a heading, a list item is sent as one sentence, its inline elements (links, bold) marked by numbered tags; if the
 * translation returns the tags in the same order, every piece goes back into its own text node, so links stay where they are. Otherwise the
 * block is translated node by node. Only the value of text nodes changes, never the structure. A MutationObserver translates what changes
 * later. `restore()` puts the originals back. */

export const LANGS = [
  ["en", "English (US)"], ["it", "Italiano"], ["de", "Deutsch"], ["fr", "Français"], ["es", "Español"], ["pt", "Português"],
  ["nl", "Nederlands"], ["pl", "Polski"], ["tr", "Türkçe"], ["ru", "Русский"], ["ar", "العربية"], ["hi", "हिन्दी"],
  ["ja", "日本語"], ["ko", "한국어"], ["zh", "中文"],
];
const BASE = "en";
const KEY_LANG = "mwc.lang";
const KEY_AUTO = "mwc.auto";
const KEY_MEM = "mwc.tm1";
const MEM_MAX = 2000;
const BLOCKS = "p,li,h1,h2,h3,h4,summary,dt,dd,td,th,figcaption,blockquote,label,button,a.btn,a.card,span.tag,.tags span,.eyebrow";
const NEVER = "script,style,pre,textarea,input,select,svg,[translate=no],.notranslate";
const INLINE = new Set(["A", "STRONG", "EM", "B", "I", "SPAN", "U", "SMALL", "MARK", "ABBR", "CODE", "KBD"]);
const ATTRS = ["aria-label", "title", "placeholder", "alt"];
const LETTER = /\p{L}/u;
const TOKEN = /<(\/?)(\d+)>/g;

const base = (l) => String(l).toLowerCase().split(/[-_]/)[0];
const get = (k, d) => { try { return localStorage.getItem(k) ?? d; } catch { return d; } };
const set = (k, v) => { try { localStorage.setItem(k, v); } catch { /* storage unavailable: the choice lasts for this page */ } };

export const supported = () => typeof self !== "undefined" && "Translator" in self;

export function preferred() {
  const saved = get(KEY_LANG, "");
  if (saved && LANGS.some(([c]) => c === saved)) return saved;
  for (const l of navigator.languages || [navigator.language || BASE]) {
    const b = base(l);
    if (LANGS.some(([c]) => c === b)) return b;
  }
  return BASE;
}
export const setPreferred = (l) => set(KEY_LANG, l);
export const autoOn = () => get(KEY_AUTO, "1") !== "0";
export const setAuto = (on) => set(KEY_AUTO, on ? "1" : "0");

async function availability(to) {
  if (!supported() || base(to) === BASE) return "unavailable";
  try { return await self.Translator.availability({ sourceLanguage: BASE, targetLanguage: base(to) }); } catch { return "unavailable"; }
}

const translators = new Map();
function translatorFor(to, progress) {
  let p = translators.get(to);
  if (!p) {
    p = self.Translator.create({
      sourceLanguage: BASE, targetLanguage: base(to),
      monitor(m) { m.addEventListener("downloadprogress", (e) => progress?.(Math.round(e.loaded <= 1 ? e.loaded * 100 : e.loaded))); },
    });
    p.catch(() => translators.delete(to));
    translators.set(to, p);
  }
  return p;
}

let memory = null;
function mem() {
  if (memory) return memory;
  memory = new Map();
  try { for (const [k, v] of JSON.parse(get(KEY_MEM, "[]"))) memory.set(k, v); } catch { /* start empty */ }
  return memory;
}
let saveTimer = null;
function remember(k, v) {
  const m = mem(); m.delete(k); m.set(k, v);
  while (m.size > MEM_MAX) m.delete(m.keys().next().value);
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => set(KEY_MEM, JSON.stringify([...m])), 800);
}

class PageTranslation {
  constructor(roots, to, api) {
    this.roots = roots; this.to = to; this.api = api;
    this.texts = new Map(); this.attrs = new Map(); this.stopped = false; this.writing = false; this.queue = new Set(); this.timer = null;
  }
  async start(first) {
    for (const r of this.roots) r.dataset.langWas = r.getAttribute("lang") ?? "";
    document.documentElement.setAttribute("lang", base(this.to));
    if (first) await this.under(first);
    for (const r of this.roots) await this.under(r);
    if (this.stopped) return;
    this.observer = new MutationObserver((c) => this.changed(c));
    for (const r of this.roots) this.observer.observe(r, { subtree: true, childList: true, characterData: true });
  }
  restore() {
    this.stopped = true; this.observer?.disconnect(); clearTimeout(this.timer);
    for (const [n, s] of this.texts) if (n.nodeValue === s.out) n.nodeValue = s.src;
    for (const [el, o] of this.attrs) for (const [k, s] of Object.entries(o)) if (el.getAttribute(k) === s.out) el.setAttribute(k, s.src);
    document.documentElement.setAttribute("lang", "en-US");
    this.texts.clear(); this.attrs.clear();
  }
  write(fn) { this.writing = true; try { fn(); } finally { this.observer?.takeRecords(); this.writing = false; } }
  async sentence(text) {
    const key = `${base(this.to)}:${text}`;
    const known = mem().get(key);
    if (known !== undefined) return known;
    const out = await this.api.translate(text);
    remember(key, out);
    return out;
  }
  excluded(n) { const el = n instanceof Element ? n : n.parentElement; return !el || el.closest(NEVER) !== null; }
  async under(root) {
    if (this.stopped || this.excluded(root)) return;
    const blocks = [...root.querySelectorAll(BLOCKS)].filter((b) => !b.querySelector(BLOCKS) && !this.excluded(b));
    for (const b of blocks) { if (this.stopped) return; await this.block(b); }
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const loose = [];
    for (let n = walker.nextNode(); n; n = walker.nextNode()) if (!this.texts.has(n) && LETTER.test(n.nodeValue) && !this.excluded(n)) loose.push(n);
    for (const n of loose) { if (this.stopped) return; await this.node(n); }
    await this.attributes(root);
  }
  async node(n) {
    const src = n.nodeValue, core = src.trim();
    if (!LETTER.test(core)) return;
    const lead = src.slice(0, src.length - src.trimStart().length), tail = src.slice(src.trimEnd().length);
    const out = lead + (await this.sentence(core)) + tail;
    if (this.stopped || n.nodeValue !== src) return;
    this.write(() => { n.nodeValue = out; });
    this.texts.set(n, { src, out });
  }
  async block(b) {
    if (!LETTER.test(b.textContent)) return;
    const segs = [{ nodes: [], keep: false }]; const order = []; let s = "", id = 0, ok = true;
    const add = (t) => { s += t; };
    const walk = (el, keep) => {
      for (const c of el.childNodes) {
        if (!ok) return;
        if (c.nodeType === Node.TEXT_NODE) { segs.at(-1).nodes.push(c); add(c.nodeValue); }
        else if (c.nodeType === Node.ELEMENT_NODE) {
          if (c.matches("svg,[hidden]")) continue;
          if (!INLINE.has(c.tagName) && !c.matches(NEVER)) { ok = false; return; }
          const k = ++id, protectedNode = keep || c.matches(NEVER) || c.tagName === "CODE" || c.tagName === "KBD";
          add(`<${k}>`); order.push(`o${k}`); segs.push({ nodes: [], keep: protectedNode });
          walk(c, protectedNode);
          add(`</${k}>`); order.push(`c${k}`); segs.push({ nodes: [], keep });
        }
      }
    };
    walk(b, false);
    if (!ok || !order.length) { for (const seg of segs) for (const n of seg.nodes) await this.node(n); return; }
    const raw = await this.sentence(s);
    if (this.stopped) return;
    const parts = []; const seq = []; let last = 0, m;
    TOKEN.lastIndex = 0;
    while ((m = TOKEN.exec(raw))) { parts.push(raw.slice(last, m.index)); seq.push(`${m[1] ? "c" : "o"}${m[2]}`); last = m.index + m[0].length; }
    parts.push(raw.slice(last));
    if (seq.join() !== order.join() || parts.length !== segs.length) { for (const seg of segs) if (!seg.keep) for (const n of seg.nodes) await this.node(n); return; }
    this.write(() => {
      segs.forEach((seg, i) => {
        if (seg.keep || !seg.nodes.length) return;
        seg.nodes.forEach((n, j) => {
          const src = n.nodeValue, out = j === 0 ? parts[i] : "";
          if (!this.texts.has(n)) this.texts.set(n, { src, out });
          n.nodeValue = out;
        });
      });
    });
  }
  async attributes(root) {
    for (const el of [root, ...root.querySelectorAll(ATTRS.map((a) => `[${a}]`).join(","))]) {
      if (this.stopped) return;
      if (this.excluded(el)) continue;
      for (const a of ATTRS) {
        const v = el.getAttribute?.(a);
        if (!v || !LETTER.test(v)) continue;
        const out = await this.sentence(v);
        if (this.stopped) return;
        this.write(() => el.setAttribute(a, out));
        (this.attrs.get(el) ?? this.attrs.set(el, {}).get(el))[a] = { src: v, out };
      }
    }
  }
  changed(list) {
    if (this.writing || this.stopped) return;
    for (const c of list) {
      const el = c.target instanceof Element ? c.target : c.target.parentElement;
      const b = el?.closest(BLOCKS) ?? el;
      if (b && !this.excluded(b)) this.queue.add(b);
    }
    clearTimeout(this.timer);
    this.timer = setTimeout(async () => {
      const batch = [...this.queue]; this.queue.clear();
      for (const b of batch) if (b.isConnected) await this.under(b);
    }, 300);
  }
}

/* The controller: the language choice, the bar that asks, the work. */
export function initTranslation({ select, bar, text, go, orig, never, roots, firstRoot }) {
  let active = null, state = "idle", target = preferred();

  select.replaceChildren(...LANGS.map(([c, n]) => Object.assign(document.createElement("option"), { value: c, textContent: n, selected: c === target })));

  const say = (msg, buttons = {}) => {
    bar.hidden = !msg; text.textContent = msg || "";
    go.hidden = !buttons.go; orig.hidden = !buttons.orig; never.hidden = !buttons.never;
  };
  const stop = () => { active?.restore(); active = null; };
  const name = (c) => LANGS.find(([x]) => x === c)?.[1] ?? c;

  async function run(userGesture) {
    stop();
    if (base(target) === BASE) { state = "idle"; say(""); return; }
    if (!supported()) { state = "none"; say("Automatic on-device translation needs Chrome 138 or newer on a computer. This page is in English; your browser's own translator also works.", { never: false }); return; }
    const avail = await availability(target);
    if (avail === "unavailable") { state = "none"; say(`Chrome cannot translate English to ${name(target)} on this device.`); return; }
    if (avail !== "available" && !userGesture) {
      state = "offer"; say(`Translate this page to ${name(target)}? Chrome downloads a small language model once; the text stays on your computer.`, { go: true, never: true }); return;
    }
    if (avail === "available" && !autoOn() && !userGesture) { state = "offer"; say(`Translate this page to ${name(target)}?`, { go: true }); return; }
    state = "working"; say(`Translating to ${name(target)}…`);
    const request = translatorFor(target, (p) => say(`Downloading the ${name(target)} language model: ${p}%`));
    try {
      const api = await request;
      const job = new PageTranslation(roots(), target, api);
      active = job;
      say(`Translating to ${name(target)}…`);
      await job.start(firstRoot());
      if (active === job) { state = "done"; say(`Translated to ${name(target)} on this device.`, { orig: true, never: true }); }
    } catch {
      state = "error"; say("The translation could not be done.");
    }
  }

  select.addEventListener("change", () => { target = select.value; setPreferred(target); setAuto(true); run(true); });
  go.addEventListener("click", () => { setAuto(true); run(true); });
  orig.addEventListener("click", () => { stop(); state = "original"; say(`Showing the original English. `, { go: true, never: true }); go.textContent = `Translate to ${name(target)}`; });
  never.addEventListener("click", () => { stop(); setAuto(false); target = BASE; select.value = BASE; setPreferred(BASE); say(""); });
  go.textContent = "Translate";

  return { start: () => run(false), retranslate: (root) => { if (active && !active.stopped) active.under(root); } };
}
