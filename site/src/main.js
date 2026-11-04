import "./styles.css";
import { animate, inView, stagger } from "framer-motion/dom";
import { initTranslation } from "./translate.js";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
const ROUTES = $$(".page").map((p) => p.dataset.route);

/* ---- tabs: one page at a time, the address says which (deep links work) ---- */
const nav = $("#nav"), menuBtn = $("#menu-btn");
menuBtn.addEventListener("click", () => {
  const open = nav.classList.toggle("open");
  menuBtn.setAttribute("aria-expanded", String(open));
});
let current = "";

/* the one orchestrated moment: the two sessions run, and the two extra steps are caught */
function playHero() {
  const lines = $$("#home .diff .ln");
  const flags = $$("#home .diff .ln.flag");
  const verdicts = $$("#home .diff .verdict");
  if (reduced) return;
  lines.forEach((l) => { l.style.opacity = "0"; });
  verdicts.forEach((v) => { v.style.opacity = "0"; });
  animate(lines, { opacity: [0, 1], transform: ["translateX(-6px)", "translateX(0)"] }, { delay: stagger(0.09, { startDelay: 0.25 }), duration: 0.3 });
  const after = 0.25 + lines.length * 0.09 + 0.25;
  animate(verdicts, { opacity: [0, 1], transform: ["translateY(6px)", "translateY(0)"] }, { delay: stagger(0.35, { startDelay: after }), duration: 0.4 });
  animate(flags, { boxShadow: ["inset 3px 0 0 #ff6b6b, 0 0 0 0 rgba(255,107,107,0)", "inset 3px 0 0 #ff6b6b, 0 0 0 4px rgba(255,107,107,.35)", "inset 3px 0 0 #ff6b6b, 0 0 0 0 rgba(255,107,107,0)"] }, { delay: after + 0.45, duration: 0.9 });
}

function countUp() {
  $$("#home .ledger b[data-count]").forEach((el) => {
    const to = Number(el.dataset.count);
    if (reduced || !to) return;
    inView(el, () => { animate(0, to, { duration: 0.9, ease: "easeOut", onUpdate: (v) => { el.textContent = Math.round(v); } }); }, { amount: 0.6 });
  });
}

function show(route, focus) {
  if (!ROUTES.includes(route)) route = "home";
  if (route === current) return;
  current = route;
  $$(".page").forEach((p) => { p.hidden = p.dataset.route !== route; });
  $$("a[data-route]", nav).forEach((a) => (a.dataset.route === route ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  nav.classList.remove("open"); menuBtn.setAttribute("aria-expanded", "false");
  const page = $(`#${route}`);
  const title = $("h1", page)?.textContent ?? "";
  document.title = route === "home" ? "MalWeight Canary — watch what an open-weight model does, not what it says" : `${title} — MalWeight Canary`;
  window.scrollTo({ top: 0, behavior: "auto" });
  if (focus) $("#main").focus({ preventScroll: true });
  if (!reduced) {
    animate(page, { opacity: [0, 1], transform: ["translateY(10px)", "translateY(0)"] }, { duration: 0.3, ease: "easeOut" });
    if (route !== "home") {
      const items = $$(".win, .plate, .tile, .ctx, .row, .tier, .dl-card, .card2, .scale li, .cols3 > div", page);
      items.forEach((c) => { c.style.opacity = "0"; });
      inView(page, () => { animate(items, { opacity: [0, 1], transform: ["translateY(8px)", "translateY(0)"] }, { delay: stagger(0.035), duration: 0.32, ease: "easeOut" }); }, { amount: 0.05 });
    }
  }
  if (route === "home") playHero();
  translation?.retranslate(page);
}
const route = () => show((location.hash.replace(/^#\/?/, "") || "home").split("/")[0], true);
addEventListener("hashchange", route);

/* ---- translation on this device, with a preferred language ---- */
const translation = initTranslation({
  select: $("#lang"), bar: $("#tbar"), text: $("#tbar-text"), go: $("#tbar-go"), orig: $("#tbar-orig"), never: $("#tbar-never"),
  roots: () => [$(".top"), $("#main"), $(".foot")],
  firstRoot: () => $(`#${current || "home"}`),
});

route();
countUp();
translation.start();
