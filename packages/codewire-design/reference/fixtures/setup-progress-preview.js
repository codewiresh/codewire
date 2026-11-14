// Design preview only: with ?animate, list every step and walk through them,
// each waiting, then running, then done, and start again. The browser specs
// load the fixture without it and drive the page's own event stream instead.
(() => {
  if (!new URLSearchParams(location.search).has("animate")) return;
  const section = document.querySelector("[data-setup-progress]");
  const list = section?.querySelector("[data-setup-stages]");
  const status = section?.querySelector("[data-setup-status]");
  if (!list || !status) return;
  const steps = [
    ["Checking sidecar readiness", 1.2],
    ["Installing credentials", 0.4],
    ["Cloning repositories", 3.8],
    ["Running setup commands", 6.1],
    ["Starting services", 1.7],
  ];
  const STEP_MS = 1400;
  // Each step is one list item whose state changes in place, so a finished
  // step's check animates once, when it finishes.
  const items = steps.map(([label]) => {
    const item = document.createElement("li");
    item.className = "cw-setup-stage";
    const line = document.createElement("div");
    line.className = "cw-setup-row";
    const name = document.createElement("span");
    name.className = "cw-setup-stage-label";
    name.textContent = label;
    const detail = document.createElement("span");
    detail.className = "cw-setup-stage-detail";
    line.append(name, detail);
    item.append(line);
    return { item, detail };
  });
  let step = 0;
  function show() {
    if (step === 0) list.replaceChildren(...items.map(({ item }) => item));
    items.forEach(({ item, detail }, index) => {
      const [state, text] = index < step ? ["completed", `Done in ${steps[index][1]} s`]
        : index === step ? ["running", "In progress"] : ["", ""];
      if (state) item.dataset.state = state;
      else delete item.dataset.state;
      detail.textContent = text;
    });
    status.textContent = step < steps.length ? `${steps[step][0]}…`
      : "Setup complete. The terminal opens when the Sandbox reports it is ready.";
    // Hold the finished list for two steps, then start again.
    step = step < steps.length + 1 ? step + 1 : 0;
  }
  show();
  setInterval(show, STEP_MS);
})();
