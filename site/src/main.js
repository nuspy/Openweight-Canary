import "./styles.css";
import { animate, inView, stagger } from "framer-motion/dom";
import { initTranslation } from "./translate.js";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
const ROUTES = $$(".page").map((p) => p.dataset.route);

/* ---- the look: three to compare while the site is being chosen (add ?looks to the address) ---- */
const html = document.documentElement;
const showLooks = import.meta.env.DEV || location.search.includes("looks");
const looks = $("#looks");
function setLook(look) {
  html.dataset.look = look;
  $$("button", looks).forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.look === look)));
  try { localStorage.setItem("mwc.look", look); } catch { /* the look lasts for this page */ }
  const bg = getComputedStyle(html).getPropertyValue("--bg").trim();
  $('meta[name="theme-color"]').setAttribute("content", bg || "#020617");
}
if (showLooks) {
  looks.hidden = false;
  looks.addEventListener("click", (e) => { const b = e.target.closest("button[data-look]"); if (b) setLook(b.dataset.look); });
}
let saved = null;
try { saved = localStorage.getItem("mwc.look"); } catch { /* no storage */ }
setLook(showLooks && ["terminal", "lab", "endpoint"].includes(saved) ? saved : html.dataset.look);

/* ---- tabs: one page at a time, the address says which (deep links work) ---- */
const nav = $("#nav"), menuBtn = $("#menu-btn");
menuBtn.addEventListener("click", () => {
  const open = nav.classList.toggle("open");
  menuBtn.setAttribute("aria-expanded", String(open));
});
let current = "";
function show(route, focus) {
  if (!ROUTES.includes(route)) route = "home";
  if (route === current) return;
  current = route;
  $$(".page").forEach((p) => { p.hidden = p.dataset.route !== route; });
  $$("a[data-route]", nav).forEach((a) => (a.dataset.route === route ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  nav.classList.remove("open"); menuBtn.setAttribute("aria-expanded", "false");
  const page = $(`#${route}`);
  const title = $("h1", page)?.textContent ?? "";
  document.title = route === "home" ? "MalWeight Canary — find hidden behaviour in open-weight models" : `${title} — MalWeight Canary`;
  window.scrollTo({ top: 0, behavior: "auto" });
  if (focus) $("#main").focus({ preventScroll: true });
  if (!reduced) {
    animate(page, { opacity: [0, 1], transform: ["translateY(14px)", "translateY(0)"] }, { duration: 0.35, ease: "easeOut" });
    const cards = $$(".card, .levels li, .term", page);
    cards.forEach((c) => { c.style.opacity = "0"; });
    inView(page, () => {
      animate(cards, { opacity: [0, 1], transform: ["translateY(10px)", "translateY(0)"] }, { delay: stagger(0.04), duration: 0.35, ease: "easeOut" });
    }, { amount: 0.05 });
  }
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
translation.start();
