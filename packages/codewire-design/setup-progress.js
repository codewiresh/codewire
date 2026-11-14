// Live setup stages on the Sandbox page (Program #2238, A5c). A native
// EventSource reads the page's own setup-progress events; the server resumes
// a reconnect after the last event through Last-Event-ID. Every value shown
// is set as text, never as markup. The terminal stays gated by the separate
// readiness status, which alone decides when New terminal is enabled.
//
// A starting Sandbox shows the same list (#3772): one running "Starting the
// Sandbox" row until project setup begins, then the setup stages. A restart,
// whose setup finished on an earlier run, shows only that row and follows no
// stream, so an earlier run is never replayed.
(() => {
  "use strict";
  const section = document.querySelector("[data-setup-progress]");
  if (!(section instanceof HTMLElement) || typeof EventSource !== "function") return;
  const environmentId = section.dataset.setupEnvironmentId || "";
  const slug = section.dataset.setupOrgSlug || "";
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(environmentId)
    || !/^[a-z0-9]+(-[a-z0-9]+)*$/.test(slug) || slug.length > 64) return;
  const list = section.querySelector("[data-setup-stages]");
  const status = section.querySelector("[data-setup-status]");
  const announce = section.querySelector("[data-setup-announce]");
  const failure = section.querySelector("[data-setup-failure]");
  const view = section.querySelector("[data-setup-window]");
  const bar = section.querySelector("[data-setup-bar]");
  if (!(list instanceof HTMLOListElement) || !(status instanceof HTMLElement)) return;
  const MAX_STAGES = 64;
  const MAX_REPOSITORIES = 64;
  // Orchestration's start phases. Until the page names them (the creation
  // stages, a later slice of #3772), they are one "Starting the Sandbox" row.
  const START_PHASES = new Set([
    "reconcile_enqueue", "ensure_namespace", "store_backend", "create_claim", "wait_for_ready", "workspace_bind",
    "access_ready", "pod_created", "pod_volume_provisioned", "pod_volume_bound", "pod_scheduled", "pod_sandbox_ready",
    "pod_initialized", "pod_workspace_started", "pod_dind_started", "pod_running", "pod_containers_ready",
    "mark_running", "daemon_ready", "file_ready",
  ]);
  const STARTING = "Starting the Sandbox";
  const SETUP_GROUP = "Setting up your project";
  // The running step sits on the third of the window's five rows.
  const RUNNING_ROW = 2;
  // Until the stages' measured medians reach the page, the bar estimates:
  // it moves toward a typical start and fills only when setup completes.
  const TYPICAL_MS = 45_000;
  const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)");
  const token = (value, max) => typeof value === "string" && value.length > 0 && value.length <= max && /^[a-z0-9_]+$/.test(value);
  const count = (value, max) => Number.isSafeInteger(value) && value >= 0 && value <= max;
  const words = (value) => value.replace(/_/g, " ");
  const sentence = (value) => words(value).replace(/^./, (first) => first.toUpperCase());
  const seconds = (milliseconds) => milliseconds < 10_000 ? `${(milliseconds / 1000).toFixed(1)} s` : `${Math.round(milliseconds / 1000)} s`;
  const stages = new Map();
  let ended = false;
  let source = null;
  let timer = null;
  let firstSeen = null;
  let done = false;
  let startRow = null;
  // The running step is announced to screen readers only: the list shows it.
  // Failures and stream trouble stay in the visible status line.
  const say = (text) => { if (announce instanceof HTMLElement) announce.textContent = text; };

  if (view instanceof HTMLElement) view.hidden = false;
  if (bar instanceof HTMLElement) bar.hidden = false;

  function valid(event) {
    return event && typeof event === "object" && !Array.isArray(event)
      && token(event.phase, 64) && token(event.status, 32) && typeof event.label === "string" && event.label.length <= 300
      && ["repoIndex", "repoCount"].every((key) => event[key] === undefined || (count(event[key], 1000) && event[key] >= 1))
      && (event.stage === undefined || token(event.stage, 40))
      && (event.percent === undefined || count(event.percent, 100))
      && (event.durationMs === undefined || count(event.durationMs, 86_400_000))
      && (event.createdAt === undefined || (typeof event.createdAt === "string" && Number.isFinite(Date.parse(event.createdAt))));
  }

  function mark() {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "cw-setup-mark");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    const shape = (tag, className, attributes) => {
      const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
      node.setAttribute("class", className);
      for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, value);
      svg.append(node);
    };
    const circle = { cx: "12", cy: "12", r: "10" };
    shape("circle", "cw-setup-mark-ring", circle);
    shape("circle", "cw-setup-mark-arc", { ...circle, pathLength: "1" });
    shape("circle", "cw-setup-mark-done", { ...circle, pathLength: "1" });
    shape("path", "cw-setup-mark-check", { d: "M7.5 12.5l3 3 6-6.5", pathLength: "1" });
    shape("path", "cw-setup-mark-cross", { d: "M9 9l6 6m0-6l-6 6" });
    shape("path", "cw-setup-mark-warning", { d: "M12 7v6m0 3.5v.5" });
    return svg;
  }

  function row(labelNode) {
    const container = document.createElement("div");
    container.className = "cw-setup-row";
    const detail = document.createElement("span");
    detail.className = "cw-setup-stage-detail";
    container.append(labelNode, detail);
    return { container, detail };
  }

  function item(text) {
    const node = document.createElement("li");
    node.className = "cw-setup-stage";
    const label = document.createElement("span");
    label.className = "cw-setup-stage-label";
    label.textContent = text;
    const { container, detail } = row(label);
    container.prepend(mark());
    node.append(container);
    list.append(node);
    // `local` is this browser's clock, so a live time never shows the
    // server's clock skew.
    return { item: node, label, detail, local: Date.now(), started: null, repositories: new Map(), nested: null };
  }

  function stageFor(event) {
    let stage = stages.get(event.phase);
    if (stage) return stage;
    if (stages.size >= MAX_STAGES) return null;
    if (startRow && !list.querySelector(".cw-setup-group")) {
      const group = document.createElement("li");
      group.className = "cw-setup-group";
      group.textContent = SETUP_GROUP;
      list.append(group);
    }
    stage = item(event.label || sentence(event.phase));
    stages.set(event.phase, stage);
    return stage;
  }

  function repositoryFor(stage, index, total) {
    let repository = stage.repositories.get(index);
    if (repository) return repository;
    if (stage.repositories.size >= MAX_REPOSITORIES) return null;
    if (!stage.nested) {
      stage.nested = document.createElement("ol");
      stage.nested.className = "cw-setup-repositories";
      stage.item.append(stage.nested);
    }
    const node = document.createElement("li");
    node.className = "cw-setup-stage";
    node.dataset.state = "running";
    // The row's own text names its progress bar.
    const id = `setup-repository-${index}`;
    const label = document.createElement("span");
    label.className = "cw-setup-stage-label";
    label.id = id;
    label.textContent = total > 1 ? `Repository ${index} of ${total}` : "Repository";
    const progress = document.createElement("progress");
    progress.setAttribute("aria-labelledby", id);
    progress.max = 100;
    const { container, detail } = row(label);
    container.insertBefore(progress, detail);
    node.append(container);
    stage.nested.append(node);
    repository = { item: node, progress, detail };
    stage.repositories.set(index, repository);
    return repository;
  }

  function elapsed(stage, event) {
    if (event.durationMs !== undefined) return seconds(event.durationMs);
    const end = Date.parse(event.createdAt || "");
    if (stage.started !== null && Number.isFinite(end) && end >= stage.started) return seconds(end - stage.started);
    return seconds(Math.max(0, Date.now() - stage.local));
  }

  function settleRepositories(stage, state) {
    for (const repository of stage.repositories.values()) {
      if (repository.item.dataset.state !== "running") continue;
      repository.item.dataset.state = state;
      if (state === "completed") {
        repository.progress.value = 100;
        repository.progress.textContent = "100%";
        repository.detail.textContent = "Done";
      }
    }
  }

  // Hold the running step on its row, clamped so the list starts at the top
  // and ends with its last step on the window's bottom row.
  function follow() {
    if (!(view instanceof HTMLElement)) return;
    const all = [startRow, ...stages.values()].filter(Boolean);
    const target = all.find((stage) => stage.item.dataset.state === "running") ?? all.at(-1);
    if (!target) return;
    const line = target.item.querySelector(".cw-setup-row");
    const height = line instanceof HTMLElement ? line.offsetHeight : 0;
    const last = list.lastElementChild;
    const bottom = last instanceof HTMLElement ? last.offsetTop + last.offsetHeight - list.offsetTop - view.clientHeight : 0;
    const top = Math.max(0, Math.min(target.item.offsetTop - list.offsetTop - RUNNING_ROW * height, bottom));
    view.toggleAttribute("data-scrolled", top > 0);
    if (Math.abs(view.scrollTop - top) > 1) view.scrollTo({ top, behavior: reducedMotion?.matches ? "auto" : "smooth" });
  }

  function progress() {
    if (!(bar instanceof HTMLElement)) return;
    const fraction = done ? 1 : firstSeen === null ? 0 : Math.min(0.95, 1 - Math.exp(-(Date.now() - firstSeen) / TYPICAL_MS));
    const fill = bar.firstElementChild;
    if (fill instanceof HTMLElement) fill.style.transform = `scaleX(${fraction.toFixed(4)})`;
    bar.setAttribute("aria-valuenow", String(Math.round(fraction * 100)));
  }

  // A running step's time counts up on this browser's clock.
  function tick() {
    for (const stage of [startRow, ...stages.values()]) {
      if (stage?.item.dataset.state === "running") stage.detail.textContent = seconds(Math.max(0, Date.now() - stage.local));
    }
    progress();
  }

  function settleStart() {
    if (!startRow || startRow.item.dataset.state !== "running") return;
    startRow.item.dataset.state = "completed";
    startRow.detail.textContent = seconds(Math.max(0, Date.now() - startRow.local));
  }

  function show(event) {
    if (START_PHASES.has(event.phase)) return;
    if (event.phase === "complete") {
      if (event.status === "completed" || event.status === "warning") {
        done = true;
        settleStart();
        for (const stage of stages.values()) {
          if (stage.item.dataset.state !== "running") continue;
          stage.item.dataset.state = "completed";
          stage.detail.textContent = elapsed(stage, event);
        }
        say("Setup complete. The terminal opens when the Sandbox reports it is ready.");
      }
      progress();
      follow();
      return;
    }
    settleStart();
    const stage = stageFor(event);
    if (!stage) return;
    if (stage.started === null) {
      const at = Date.parse(event.createdAt || "");
      if (Number.isFinite(at)) stage.started = event.durationMs !== undefined ? at - event.durationMs : at;
    }
    if (event.repoIndex !== undefined) {
      const repository = repositoryFor(stage, event.repoIndex, event.repoCount ?? event.repoIndex);
      if (!repository) return;
      if (event.status === "progress") {
        if (event.percent !== undefined) {
          repository.progress.value = event.percent;
          repository.progress.textContent = `${event.percent}%`;
        }
        repository.detail.textContent = [event.stage && sentence(event.stage), event.percent !== undefined && `${event.percent}%`]
          .filter(Boolean).join(" ");
      } else if (event.status === "completed") {
        repository.item.dataset.state = "completed";
        repository.progress.value = 100;
        repository.progress.textContent = "100%";
        repository.detail.textContent = "Done";
      } else if (event.status === "failed") {
        repository.item.dataset.state = "failed";
        repository.detail.textContent = "Failed";
      }
      if (!stage.item.dataset.state) stage.item.dataset.state = "running";
      follow();
      return;
    }
    switch (event.status) {
      case "started":
      case "progress":
        stage.item.dataset.state = "running";
        say(`${stage.label.textContent}…`);
        break;
      case "completed":
      case "warning": {
        stage.item.dataset.state = event.status;
        settleRepositories(stage, "completed");
        const time = elapsed(stage, event);
        stage.detail.textContent = event.status === "warning" ? [time, event.label].filter(Boolean).join(" · ") : time;
        break;
      }
      case "failed": {
        stage.item.dataset.state = "failed";
        settleRepositories(stage, "failed");
        stage.detail.textContent = "Failed";
        status.textContent = "Setup stopped.";
        if (failure instanceof HTMLElement) {
          failure.textContent = `${stage.label.textContent} failed${event.label && event.label !== stage.label.textContent ? `: ${event.label}` : "."}`;
          failure.hidden = false;
        }
        break;
      }
      default:
        stage.detail.textContent = sentence(event.status);
    }
    progress();
    follow();
  }

  function finish() {
    ended = true;
    source?.close();
    if (timer !== null) clearInterval(timer);
    timer = null;
  }

  function followStream() {
    if (source || ended) return;
    source = new EventSource(`/${encodeURIComponent(slug)}/${environmentId}/_events/setup-progress`);
    source.addEventListener("stage", (message) => {
      let event;
      try { event = JSON.parse(message.data); } catch { return; }
      if (valid(event)) show(event);
    });
    source.addEventListener("end", () => { source?.close(); });
    // This account already follows as many live logs as orchestration allows.
    source.addEventListener("busy", () => {
      source?.close();
      status.textContent = "Too many live setup views are open for this account. Close one, then reload this page to follow setup here.";
    });
    source.addEventListener("error", () => {
      // An open source retries by itself and resumes. A closed one was refused.
      if (!ended && source?.readyState === EventSource.CLOSED) {
        status.textContent = "Live setup progress is unavailable. Sandbox status below still updates.";
      }
    });
  }

  firstSeen = Date.now();
  timer = setInterval(tick, 500);
  const starting = section.hasAttribute("data-setup-starting");
  if (starting) {
    startRow = item(STARTING);
    startRow.item.dataset.state = "running";
    say(`${STARTING}…`);
    follow();
  } else {
    followStream();
  }

  document.addEventListener("codewire:sandbox-status", (message) => {
    const detail = message.detail;
    if (detail?.environmentId !== environmentId || ended) return;
    // A start whose setup already finished on an earlier run is a restart:
    // it follows no stream. A first start follows setup once it begins.
    if (starting && !source && detail.setupComplete !== true) followStream();
    if (detail.running === true) settleStart();
    if (detail.running !== true || detail.setupComplete !== true || failure?.hidden === false) return;
    done = true;
    progress();
    finish();
    section.hidden = true;
  });
})();
