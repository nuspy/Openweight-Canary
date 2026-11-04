import "./styles.css";
import { animate, inView, scroll, stagger } from "framer-motion/dom";
import { initTranslation } from "./translate.js";
import { initComputers, initConsole, initHarness, initPeople, initSpotlight, playHero, reduced } from "./ui.js";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const ROUTES = $$(".page").map((p) => p.dataset.route);

/* ---- tabs: one page at a time, the address says which (deep links work) ---- */
const nav = $("#nav"), menuBtn = $("#menu-btn");
menuBtn.addEventListener("click", () => {
  const open = nav.classList.toggle("open");
  menuBtn.setAttribute("aria-expanded", String(open));
});
let current = "";

function countUp() {
  $$("#home .ledger b[data-count]").forEach((el) => {
    const to = Number(el.dataset.count);
    if (reduced || !to) return;
    el.textContent = "0";
    inView(el, () => { animate(0, to, { duration: 1.1, ease: "easeOut", onUpdate: (v) => { el.textContent = Math.round(v); } }); }, { amount: 0.6 });
  });
}

const REVEAL = ".card, .tile, .ctx, .catch article, .node, .mini, .tier, .dl-card, .card2, .wake, .rows, .plate, .ledger, .scale li, .win, .page-h, .block > h2, .split > div";
function reveal(page) {
  if (reduced) return;
  $$(REVEAL, page).forEach((el) => {
    if (el.closest("#home .hero")) return;
    el.style.opacity = "0";
    inView(el, () => { animate(el, { opacity: [0, 1], transform: ["translateY(18px)", "translateY(0)"] }, { duration: 0.55, ease: [0.22, 1, 0.36, 1] }); }, { amount: 0.12 });
  });
}

function show(route, focus) {
  if (!ROUTES.includes(route)) route = "home";
  if (route === current) return;
  const from = ROUTES.indexOf(current), to = ROUTES.indexOf(route);
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
    const dx = from < 0 ? 0 : (to > from ? 28 : -28);
    animate(page, { opacity: [0, 1], transform: [`translateX(${dx}px)`, "translateX(0)"] }, { duration: 0.4, ease: [0.22, 1, 0.36, 1] });
    animate($$(".page-h > *", page), { opacity: [0, 1], transform: ["translateY(14px)", "translateY(0)"] }, { delay: stagger(0.07, { startDelay: 0.05 }), duration: 0.5, ease: [0.22, 1, 0.36, 1] });
    reveal(page);
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

initSpotlight(); initConsole(); initComputers(); initPeople(); initHarness();
$("#replay")?.addEventListener("click", playHero);
if (!reduced) scroll(animate($("#progress"), { transform: ["scaleX(0)", "scaleX(1)"] }, { ease: "linear" }));

route();
countUp();
translation.start();
