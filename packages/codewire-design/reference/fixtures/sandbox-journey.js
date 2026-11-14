// Sandbox journey preview (design only). Plays a Sandbox from Create to a
// ready terminal from the JSON block at the top of the page, with Replay,
// Pause, Next step, speed, and a jump to every other state.
(() => {
  const config = JSON.parse(document.getElementById("journey-config").textContent);
  const $ = (selector) => document.querySelector(selector);
  const notice = $("[data-sandbox-notice]");
  const noticeText = $("[data-sandbox-notice-text]");
  const action = $("[data-journey-action]");
  const progress = $("[data-setup-progress]");
  const heading = $("[data-journey-heading]");
  const status = $("[data-setup-status]");
  const failure = $("[data-setup-failure]");
  const list = $("[data-setup-stages]");
  const stepWindow = $("[data-journey-window]");
  const progressBar = $("[data-journey-progress]");
  const setProgress = (fraction) => {
    const clamped = Math.min(1, Math.max(0, fraction));
    progressBar.firstElementChild.style.transform = `scaleX(${clamped.toFixed(4)})`;
    progressBar.setAttribute("aria-valuenow", String(Math.round(clamped * 100)));
  };
  // The running step sits on the third of the window's five rows.
  const RUNNING_ROW = 2;
  const follow = (index) => {
    const item = items[Math.min(index, items.length - 1)]?.item;
    if (!item) return;
    const row = item.offsetHeight;
    const lastRow = list.lastElementChild;
    const bottom = lastRow.offsetTop + lastRow.offsetHeight - list.offsetTop - stepWindow.clientHeight;
    const top = Math.min(Math.max(0, item.offsetTop - list.offsetTop - RUNNING_ROW * row), bottom);
    stepWindow.toggleAttribute("data-scrolled", top > 0);
    if (Math.abs(stepWindow.scrollTop - top) > 1) stepWindow.scrollTo({ top, behavior: "smooth" });
  };
  const terminal = $("[data-journey-terminal]");
  const tabs = $("[data-journey-tabs]");
  const newTerminal = $("[data-journey-new]");
  const pauseButton = $('[data-journey="pause"]');
  const speedSelect = $('[data-journey="speed"]');
  const jumpSelect = $('[data-journey="jump"]');

  const steps = [
    ...config.creation.map(([name, seconds]) => ({ name, seconds, group: 0 })),
    ...config.setup.map(([name, seconds]) => ({ name, seconds, group: 1 })),
  ];
  const svg = (markup) => {
    const template = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    template.setAttribute("class", "cw-setup-mark");
    template.setAttribute("viewBox", "0 0 24 24");
    template.setAttribute("aria-hidden", "true");
    template.innerHTML = markup;
    return template;
  };
  const mark = () => svg(
    '<circle class="cw-setup-mark-ring" cx="12" cy="12" r="10"/>'
    + '<circle class="cw-setup-mark-arc" cx="12" cy="12" r="10" pathLength="1"/>'
    + '<circle class="cw-setup-mark-done" cx="12" cy="12" r="10" pathLength="1"/>'
    + '<path class="cw-setup-mark-check" d="M7.5 12.5l3 3 6-6.5" pathLength="1"/>'
    + '<path class="cw-setup-mark-cross" d="M9 9l6 6m0-6l-6 6"/>',
  );

  // Every step is listed from the start, so the list never changes height.
  list.dataset.journeyList = "";
  const items = steps.map((step, index) => {
    const item = document.createElement("li");
    item.className = "cw-setup-stage";
    const row = document.createElement("div");
    row.className = "cw-setup-row";
    const label = document.createElement("span");
    label.className = "cw-setup-stage-label";
    label.textContent = step.name;
    const detail = document.createElement("span");
    detail.className = "cw-setup-stage-detail";
    row.append(mark(), label, detail);
    item.append(row);
    if (step.group === 1 && steps[index - 1]?.group === 0) {
      const group = document.createElement("li");
      group.className = "cw-setup-group";
      group.textContent = config.setupHeading;
      list.append(group);
    }
    list.append(item);
    return { item, detail };
  });

  let current = 0;
  let elapsed = 0;
  let playing = true;
  let mode = "journey";

  const setState = (item, state) => {
    if ((item.dataset.state || "") === state) return;
    if (state) item.dataset.state = state;
    else delete item.dataset.state;
  };
  const tabsBar = $(".cw-terminal-tabs-bar");
  const pill = $(".cw-status--pill");
  const setPill = (text, tone) => {
    pill.textContent = text;
    pill.dataset.tone = tone;
  };
  // No tab bar until there is a terminal to open: an empty bar with only "+"
  // says nothing while the Sandbox starts.
  const showTerminal = (shown) => {
    tabsBar.hidden = !shown;
    terminal.hidden = !shown;
    newTerminal.disabled = !shown;
    tabs.replaceChildren();
    if (!shown) return;
    const tab = document.createElement("li");
    tab.className = "cw-terminal-tab-item";
    tab.setAttribute("role", "presentation");
    // The product's tab markup, from the terminal-tabs fixture.
    tab.innerHTML = '<button class="cw-terminal-tab" type="button" role="tab" aria-selected="true">'
      + '<svg class="cw-icon" aria-hidden="true"><use href="../../assets/icons.svg#icon-prompt"/></svg>'
      + '<span class="cw-terminal-tab-label">Terminal 1</span></button>'
      + '<button class="cw-terminal-tab-close" type="button" title="Close terminal">'
      + '<svg class="cw-icon" aria-hidden="true"><use href="../../assets/icons.svg#icon-close"/></svg></button>';
    tabs.append(tab);
  };
  const setNotice = ({ kind, tone = "neutral", graphic = "", text = "", button = "" }) => {
    notice.hidden = kind === "none";
    notice.dataset.kind = kind === "none" ? "message" : kind;
    notice.dataset.tone = tone;
    notice.dataset.graphic = graphic;
    progress.hidden = kind !== "setup";
    noticeText.hidden = kind === "setup" || !text;
    noticeText.textContent = text;
    action.hidden = !button;
    action.textContent = button;
  };

  function render() {
    if (mode !== "journey") return;
    const done = current >= steps.length;
    setNotice(done ? { kind: "none" } : { kind: "setup" });
    if (done) setPill("running", "success");
    else setPill("starting", "warning");
    showTerminal(done);
    failure.hidden = true;
    heading.textContent = config.heading;
    status.textContent = done ? config.readyNote : `${steps[current].name}…`;
    items.forEach(({ item, detail }, index) => {
      if (index < current) {
        setState(item, "completed");
        detail.textContent = `${steps[index].seconds.toFixed(1)} s`;
      } else if (index === current) {
        setState(item, "running");
        detail.textContent = `${elapsed.toFixed(1)} s`;
      } else {
        setState(item, "");
        detail.textContent = "";
      }
    });
    follow(current);
    const total = steps.reduce((sum, step) => sum + step.seconds, 0);
    const finished = steps.slice(0, current).reduce((sum, step) => sum + step.seconds, 0);
    setProgress((finished + Math.min(elapsed, steps[current]?.seconds ?? 0)) / total);
  }

  function replay() {
    mode = "journey";
    current = 0;
    elapsed = 0;
    // Restart every check's drawing.
    items.forEach(({ item }) => setState(item, ""));
    playing = true;
    pauseButton.textContent = "Pause";
    jumpSelect.value = "";
    render();
  }

  function jump(target) {
    if (target === "") return;
    if (target.startsWith("step:")) {
      replay();
      current = Number(target.slice(5));
      render();
      return;
    }
    playing = false;
    pauseButton.textContent = "Play";
    mode = target;
    items.forEach(({ item }) => setState(item, ""));
    showTerminal(false);
    if (target === "ready") {
      mode = "journey";
      current = steps.length;
      render();
    } else if (target === "failed") {
      setPill("running", "success");
      const at = Math.max(0, steps.findIndex((step) => step.name === config.failedStep));
      setNotice({ kind: "setup" });
      heading.textContent = config.heading;
      status.textContent = `${steps[at].name} failed.`;
      failure.hidden = false;
      failure.textContent = config.failureText;
      items.forEach(({ item, detail }, index) => {
        setState(item, index < at ? "completed" : index === at ? "failed" : "");
        detail.textContent = index < at ? `${steps[index].seconds.toFixed(1)} s` : index === at ? "Failed" : "";
      });
      follow(at);
      const total = steps.reduce((sum, step) => sum + step.seconds, 0);
      setProgress(steps.slice(0, at).reduce((sum, step) => sum + step.seconds, 0) / total);
    } else if (target === "no-capacity") {
      setPill("stopped", "neutral");
      setNotice({ kind: "message", tone: "warning", graphic: "no-capacity", text: config.noCapacityText, button: "Try again" });
    } else if (target === "stopped") {
      setPill("stopped", "neutral");
      setNotice({ kind: "message", graphic: "stopped", text: config.stoppedText, button: "Start" });
    } else if (target === "crashed") {
      setPill("error", "danger");
      setNotice({ kind: "message", tone: "danger", graphic: "crashed", text: config.crashedText, button: "Start again" });
    } else if (target === "restarted") {
      setPill("running", "success");
      showTerminal(true);
      setNotice({ kind: "banner", tone: "info", text: config.restartedText, button: "Dismiss" });
    }
  }

  const jumps = [
    ["step:0", "Create accepted"],
    ...steps.map((step, index) => [`step:${index}`, `→ ${step.name}`]).slice(1),
    ["ready", "Ready terminal"],
    ["failed", "A step failed"],
    ["no-capacity", "No capacity"],
    ["stopped", "Stopped"],
    ["crashed", "Crashed"],
    ["restarted", "Restarted (banner)"],
  ];
  for (const [value, label] of jumps) jumpSelect.add(new Option(label, value));

  $('[data-journey="replay"]').addEventListener("click", replay);
  pauseButton.addEventListener("click", () => {
    if (mode !== "journey" || current >= steps.length) return replay();
    playing = !playing;
    pauseButton.textContent = playing ? "Pause" : "Play";
  });
  $('[data-journey="step"]').addEventListener("click", () => {
    if (mode !== "journey") replay();
    if (current < steps.length) {
      current += 1;
      elapsed = 0;
      render();
    }
  });
  jumpSelect.addEventListener("change", () => jump(jumpSelect.value));

  const TICK = 0.1;
  setInterval(() => {
    if (!playing || mode !== "journey" || current >= steps.length) return;
    elapsed += TICK * Number(speedSelect.value);
    if (elapsed >= steps[current].seconds) {
      current += 1;
      elapsed = 0;
    }
    render();
  }, TICK * 1000);
  replay();
})();
