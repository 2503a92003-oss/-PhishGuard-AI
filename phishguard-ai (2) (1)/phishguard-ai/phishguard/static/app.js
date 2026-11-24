(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];

  // Risk meter: the marker slides to the score once on load.
  $$(".meter").forEach((m) => {
    m.style.setProperty("--score", 0);
    requestAnimationFrame(() => requestAnimationFrame(() => m.style.setProperty("--score", m.dataset.score)));
  });

  // Scan form: character count, and pick "Link" automatically when a single URL is pasted.
  const box = $("#content");
  if (box && $("[data-count]")) {
    const count = $("[data-count]");
    const radios = $$('input[name="kind"]');
    let touched = false;
    radios.forEach((r) => r.addEventListener("change", () => (touched = true)));
    const looksLikeUrl = (v) =>
      /^\s*(https?:\/\/|www\.)\S+\s*$/i.test(v) || /^\s*[a-z0-9-]+(\.[a-z0-9-]+)+\/\S*\s*$/i.test(v);
    const update = () => {
      count.textContent = `${box.value.length.toLocaleString()} / ${box.maxLength.toLocaleString()}`;
      if (!touched && box.value) {
        const want = looksLikeUrl(box.value) ? "url" : "message";
        radios.forEach((r) => (r.checked = r.value === want));
      }
    };
    box.addEventListener("input", update);
    update();
  }

  $$("[data-print]").forEach((b) => b.addEventListener("click", () => window.print()));
  $$("form[data-confirm]").forEach((f) =>
    f.addEventListener("submit", (e) => {
      if (!window.confirm(f.dataset.confirm)) e.preventDefault();
    })
  );
})();
