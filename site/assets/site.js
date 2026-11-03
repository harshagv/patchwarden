// Patchwarden site: reveal-on-scroll and the example screens tabs. No tracking.
document.documentElement.classList.add("js");

const reveal = document.querySelectorAll(".reveal");
if ("IntersectionObserver" in window) {
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (e.isIntersecting) {
        e.target.classList.add("is-in");
        io.unobserve(e.target);
      }
    }
  }, { rootMargin: "0px 0px -8% 0px" });
  reveal.forEach((el) => io.observe(el));
} else {
  reveal.forEach((el) => el.classList.add("is-in"));
}

const tabs = document.querySelectorAll(".screens__tabs [role=tab]");
const frame = document.querySelector(".browser__frame");
const open = document.querySelector(".browser__open");
tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    tabs.forEach((t) => t.setAttribute("aria-selected", String(t === tab)));
    frame.src = tab.dataset.src;
    open.href = tab.dataset.src;
  });
});
