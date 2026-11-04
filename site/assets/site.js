// Patchwarden site: reveal-on-scroll and the example screens tabs. No tracking.
document.documentElement.classList.add("js");

const reveal = document.querySelectorAll(".reveal");
const anims = document.querySelectorAll(".anim");
if ("IntersectionObserver" in window) {
  const io = new IntersectionObserver((entries) => {
    // Items that come into view together appear one after another (a short stagger).
    entries.filter((e) => e.isIntersecting).forEach((e, i) => {
      const el = e.target;
      if (i > 0) {
        el.style.transitionDelay = `${Math.min(i, 6) * 90}ms`;  // CSSOM, allowed by the page's CSP
        el.addEventListener("transitionend", () => { el.style.transitionDelay = ""; }, { once: true });
      }
      el.classList.add("is-in");
      io.unobserve(el);
    });
  }, { rootMargin: "0px 0px -8% 0px" });
  reveal.forEach((el) => io.observe(el));

  // Animations play only while visible.
  const play = new IntersectionObserver((entries) => {
    for (const e of entries) e.target.classList.toggle("is-playing", e.isIntersecting);
  });
  anims.forEach((el) => play.observe(el));
} else {
  reveal.forEach((el) => el.classList.add("is-in"));
  anims.forEach((el) => el.classList.add("is-playing"));
}

const tabs = document.querySelectorAll(".screens__tabs [role=tab]");
const frame = document.querySelector(".browser__frame");
const open = document.querySelector(".browser__open");
function select(tab) {
  tabs.forEach((t) => {
    t.setAttribute("aria-selected", String(t === tab));
    t.tabIndex = t === tab ? 0 : -1;
  });
  frame.src = tab.dataset.src;
  open.href = tab.dataset.src;
}
tabs.forEach((tab, i) => {
  tab.addEventListener("click", () => select(tab));
  tab.addEventListener("keydown", (e) => {  // arrow keys move between tabs, as screen-reader users expect
    const step = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
    if (!step) return;
    const next = tabs[(i + step + tabs.length) % tabs.length];
    next.focus();
    select(next);
  });
});

// Mobile menu: close it after a link is picked.
const menu = document.querySelector(".nav__menu");
if (menu) menu.addEventListener("click", (e) => { if (e.target.closest("a")) menu.open = false; });

// Docs: the table of contents starts folded on small screens (it is long), open on wide ones.
const toc = document.querySelector("details.docs__toc");
if (toc) {
  const narrow = window.matchMedia("(max-width: 900px)");
  const sync = () => { toc.open = !narrow.matches; };
  sync();
  narrow.addEventListener("change", sync);
  toc.addEventListener("click", (e) => { if (e.target.closest("a") && narrow.matches) toc.open = false; });
}
