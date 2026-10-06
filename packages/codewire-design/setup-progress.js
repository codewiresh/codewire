// Live setup stages on the Sandbox page (Program #2238, A5c). A native
// EventSource reads the page's own setup-progress events; the server resumes
// a reconnect after the last event through Last-Event-ID. Every value shown
// is set as text, never as markup. The terminal stays gated by the separate
// readiness status, which alone decides when New terminal is enabled.
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
  const failure = section.querySelector("[data-setup-failure]");
  if (!(list instanceof HTMLOListElement) || !(status instanceof HTMLElement)) return;
  const MAX_STAGES = 64;
  const MAX_REPOSITORIES = 64;
  const token = (value, max) => typeof value === "string" && value.length > 0 && value.length <= max && /^[a-z0-9_]+$/.test(value);
  const count = (value, max) => Number.isSafeInteger(value) && value >= 0 && value <= max;
  const words = (value) => value.replace(/_/g, " ");
  const sentence = (value) => words(value).replace(/^./, (first) => first.toUpperCase());
  const seconds = (milliseconds) => milliseconds < 10_000 ? `${(milliseconds / 1000).toFixed(1)} s` : `${Math.round(milliseconds / 1000)} s`;
  const stages = new Map();
  let ended = false;

  function valid(event) {
    return event && typeof event === "object" && !Array.isArray(event)
      && token(event.phase, 64) && token(event.status, 32) && typeof event.label === "string" && event.label.length <= 300
      && ["repoIndex", "repoCount"].every((key) => event[key] === undefined || (count(event[key], 1000) && event[key] >= 1))
      && (event.stage === undefined || token(event.stage, 40))
      && (event.percent === undefined || count(event.percent, 100))
      && (event.durationMs === undefined || count(event.durationMs, 86_400_000))
      && (event.createdAt === undefined || (typeof event.createdAt === "string" && Number.isFinite(Date.parse(event.createdAt))));
  }

  function row(labelNode) {
    const container = document.createElement("div");
    container.className = "cw-setup-row";
    const detail = document.createElement("span");
    detail.className = "cw-setup-stage-detail";
    container.append(labelNode, detail);
    return { container, detail };
  }

  function stageFor(event) {
    let stage = stages.get(event.phase);
    if (stage) return stage;
    if (stages.size >= MAX_STAGES) return null;
    const item = document.createElement("li");
    item.className = "cw-setup-stage";
    const label = document.createElement("span");
    label.className = "cw-setup-stage-label";
    label.textContent = event.label || sentence(event.phase);
    const { container, detail } = row(label);
    item.append(container);
    list.append(item);
    stage = { item, label, detail, started: null, repositories: new Map(), nested: null };
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
    const item = document.createElement("li");
    item.className = "cw-setup-stage";
    item.dataset.state = "running";
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
    item.append(container);
    stage.nested.append(item);
    repository = { item, progress, detail };
    stage.repositories.set(index, repository);
    return repository;
  }

  function elapsed(stage, event) {
    if (event.durationMs !== undefined) return seconds(event.durationMs);
    const end = Date.parse(event.createdAt || "");
    return stage.started !== null && Number.isFinite(end) && end >= stage.started ? seconds(end - stage.started) : "";
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

  function show(event) {
    const stage = stageFor(event);
    if (!stage) return;
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
      return;
    }
    switch (event.status) {
      case "started": {
        stage.item.dataset.state = "running";
        stage.started = Date.parse(event.createdAt || "");
        if (!Number.isFinite(stage.started)) stage.started = null;
        stage.detail.textContent = "In progress";
        status.textContent = `${stage.label.textContent}…`;
        break;
      }
      case "progress":
        stage.item.dataset.state = "running";
        break;
      case "completed":
      case "warning": {
        stage.item.dataset.state = event.status;
        settleRepositories(stage, "completed");
        const time = elapsed(stage, event);
        stage.detail.textContent = event.status === "warning"
          ? [time, event.label].filter(Boolean).join(" · ")
          : time ? `Done in ${time}` : "Done";
        if (event.phase === "complete") status.textContent = "Setup complete. The terminal opens when the Sandbox reports it is ready.";
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
  }

  const source = new EventSource(`/${encodeURIComponent(slug)}/${environmentId}/_events/setup-progress`);
  const finish = () => { ended = true; source.close(); };
  source.addEventListener("stage", (message) => {
    let event;
    try { event = JSON.parse(message.data); } catch { return; }
    if (valid(event)) show(event);
  });
  source.addEventListener("end", finish);
  // This account already follows as many live logs as orchestration allows.
  source.addEventListener("busy", () => {
    finish();
    status.textContent = "Too many live setup views are open for this account. Close one, then reload this page to follow setup here.";
  });
  source.addEventListener("error", () => {
    // An open source retries by itself and resumes. A closed one was refused.
    if (!ended && source.readyState === EventSource.CLOSED) {
      status.textContent = "Live setup progress is unavailable. Sandbox status below still updates.";
    }
  });
  document.addEventListener("codewire:sandbox-status", (message) => {
    const detail = message.detail;
    if (detail?.environmentId !== environmentId || detail.setupComplete !== true || failure?.hidden === false) return;
    finish();
    section.hidden = true;
  });
})();
