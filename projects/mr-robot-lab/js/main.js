// Scroll reveal
const observer = new IntersectionObserver(
  (entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) {
        e.target.classList.add("visible");
        observer.unobserve(e.target);
      }
    });
  },
  { threshold: 0.08 },
);

document.querySelectorAll(".reveal").forEach((el) => observer.observe(el));

// Smooth nav shrink on scroll
const nav = document.querySelector("nav");
window.addEventListener("scroll", () => {
  nav.style.padding = window.scrollY > 60 ? "0.75rem 3rem" : "1.1rem 3rem";
});

// Lightbox
document.querySelectorAll(".screenshot").forEach((img) => {
  img.style.cursor = "zoom-in";
  img.addEventListener("click", () => {
    const overlay = document.createElement("div");
    overlay.style.cssText = `
      position:fixed; inset:0; background:rgba(0,0,0,0.92);
      display:flex; align-items:center; justify-content:center;
      z-index:999; cursor:zoom-out; padding:2rem;
    `;
    const clone = img.cloneNode();
    clone.style.cssText =
      "max-width:90vw; max-height:90vh; object-fit:contain;";
    overlay.appendChild(clone);
    overlay.addEventListener("click", () => overlay.remove());
    document.body.appendChild(overlay);
  });
});

//
