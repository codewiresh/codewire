(function() {
  var stage = document.querySelector('.cw-workflow-stage');
  var sticky = document.querySelector('.cw-workflow-sticky');
  var copyWindow = document.querySelector('.cw-workflow-copy-window');
  var steps = Array.prototype.slice.call(document.querySelectorAll('.cw-workflow-step'));
  var title = document.getElementById('workflow-terminal-title');
  var commands = document.getElementById('workflow-terminal-commands');
  var result = document.getElementById('workflow-terminal-result');
  var screen = document.querySelector('.cw-workflow-terminal-screen');
  var motionPreference = window.matchMedia('(prefers-reduced-motion: reduce)');
  var reduceMotion = motionPreference.matches;
  var activeIndex = -1;
  var animationToken = 0;
  var ticking = false;
  var horizontalLayout = null;

  if (!stage || !sticky || !copyWindow || !steps.length || !title || !commands || !result || !screen) return;

  function scrollTerminalToLatest() {
    screen.scrollTop = screen.scrollHeight;
  }

  function appendCompletedStep(step) {
    var entry = document.createElement('div');
    var lines = (step.getAttribute('data-command') || '').split('\n');
    var historyResult = document.createElement('div');

    entry.className = 'cw-terminal-history-entry';
    lines.forEach(function(line) {
      var row = document.createElement('div');
      var prompt = document.createElement('span');
      var command = document.createElement('span');

      row.className = 'cw-terminal-command-line';
      prompt.className = 'cw-terminal-prompt';
      prompt.textContent = /^\s/.test(line) ? '  ' : '$ ';
      command.textContent = line;
      row.appendChild(prompt);
      row.appendChild(command);
      entry.appendChild(row);
    });

    historyResult.className = 'cw-terminal-history-result';
    historyResult.textContent = step.getAttribute('data-result') || '';
    entry.appendChild(historyResult);
    commands.appendChild(entry);
  }

  function finishScene(step, token) {
    window.setTimeout(function() {
      if (token !== animationToken) return;
      result.textContent = step.getAttribute('data-result') || '';
      scrollTerminalToLatest();
    }, reduceMotion ? 0 : 140);
  }

  function renderScene(index) {
    var step = steps[index];
    var token = ++animationToken;
    var lines = (step.getAttribute('data-command') || '').split('\n');
    var lineIndex = 0;
    var currentEntry = document.createElement('div');

    title.textContent = step.getAttribute('data-title') || '';
    commands.textContent = '';
    result.textContent = '';
    steps.slice(0, index).forEach(appendCompletedStep);
    currentEntry.className = 'cw-terminal-current-entry';
    commands.appendChild(currentEntry);
    scrollTerminalToLatest();

    function renderLine() {
      if (token !== animationToken) return;
      if (lineIndex >= lines.length) {
        finishScene(step, token);
        return;
      }

      var line = lines[lineIndex++];
      var row = document.createElement('div');
      var prompt = document.createElement('span');
      var typed = document.createElement('span');
      var cursor = document.createElement('span');
      var characterIndex = reduceMotion ? line.length : 0;

      row.className = 'cw-terminal-command-line';
      prompt.className = 'cw-terminal-prompt';
      prompt.textContent = /^\s/.test(line) ? '  ' : '$ ';
      cursor.className = 'cw-terminal-cursor';
      cursor.setAttribute('aria-hidden', 'true');
      typed.textContent = line.slice(0, characterIndex);
      row.appendChild(prompt);
      row.appendChild(typed);
      row.appendChild(cursor);
      currentEntry.appendChild(row);
      scrollTerminalToLatest();

      if (reduceMotion) {
        cursor.remove();
        renderLine();
        return;
      }

      function typeCharacter() {
        if (token !== animationToken) return;
        if (characterIndex < line.length) {
          characterIndex += 1;
          typed.textContent = line.slice(0, characterIndex);
          scrollTerminalToLatest();
          window.setTimeout(typeCharacter, 22);
          return;
        }

        if (lineIndex < lines.length) cursor.remove();
        window.setTimeout(renderLine, 120);
      }

      typeCharacter();
    }

    renderLine();
  }

  function setActive(index) {
    if (index === activeIndex) return;
    activeIndex = index;
    steps.forEach(function(step, stepIndex) {
      step.classList.toggle('is-active', stepIndex === index);
    });
    renderScene(index);
  }

  function updateActiveStep() {
    ticking = false;
    if (reduceMotion) return;

    if (window.innerWidth <= 820) {
      if (horizontalLayout !== false) {
        steps.forEach(function(step) {
          step.style.removeProperty('transform');
          step.style.removeProperty('opacity');
        });
        setActive(0);
        horizontalLayout = false;
      }
      return;
    }

    horizontalLayout = true;
    var stageRect = stage.getBoundingClientRect();
    var stickyTop = parseFloat(window.getComputedStyle(sticky).top) || 0;
    var scrollRange = Math.max(1, stage.offsetHeight - sticky.offsetHeight);
    var stageStart = window.scrollY + stageRect.top - stickyTop;
    var sectionProgress = Math.min(1, Math.max(0, (window.scrollY - stageStart) / scrollRange));
    var stepProgress = sectionProgress * (steps.length - 1);
    var travel = Math.max(copyWindow.clientWidth * 0.72, 520);

    steps.forEach(function(step, index) {
      var distance = Math.abs(index - stepProgress);
      var offset = (index - stepProgress) * travel;
      step.style.transform = 'translate3d(calc(-50% + ' + offset.toFixed(2) + 'px), 0, 0)';
      step.style.opacity = String(Math.max(0, Math.min(1, 1 - distance * 0.72)));
    });

    setActive(Math.round(stepProgress));
  }

  function requestUpdate() {
    if (ticking) return;
    ticking = true;
    window.requestAnimationFrame(updateActiveStep);
  }

  function updateMotionPreference(event) {
    reduceMotion = event.matches;
    animationToken += 1;
    activeIndex = -1;
    horizontalLayout = null;
    stage.classList.toggle('is-enhanced', !reduceMotion);
    steps.forEach(function(step) {
      step.style.removeProperty('transform');
      step.style.removeProperty('opacity');
    });
    if (reduceMotion) setActive(0);
    else requestUpdate();
  }

  if (motionPreference.addEventListener) {
    motionPreference.addEventListener('change', updateMotionPreference);
  }

  window.addEventListener('scroll', requestUpdate, {passive: true});
  window.addEventListener('resize', requestUpdate);
  updateMotionPreference(motionPreference);
})();

(function() {
  var map = document.querySelector('.cw-parallel-map');
  var buttons = Array.prototype.slice.call(document.querySelectorAll('[data-parallel-mode]'));
  var independentState = document.querySelector('.cw-parallel-state--independent');
  var meshState = document.querySelector('.cw-parallel-state--mesh');
  var operatorMeta = document.getElementById('parallel-operator-meta');
  var caption = document.getElementById('parallel-caption');

  if (!map || !buttons.length || !independentState || !meshState || !operatorMeta || !caption) return;

  var modeSwitch = document.querySelector('.cw-parallel-mode-switch');
  if (modeSwitch) modeSwitch.hidden = false;

  function setMode(mode) {
    var isMesh = mode === 'mesh';
    map.setAttribute('data-mode', isMesh ? 'mesh' : 'independent');
    map.setAttribute('aria-label', isMesh
      ? 'Four agent sessions split between two encrypted meshes, connected through one operator'
      : 'Four independent agent sessions working in separate, differently sized sandboxes around one operator');
    independentState.setAttribute('aria-hidden', String(isMesh));
    meshState.setAttribute('aria-hidden', String(!isMesh));
    operatorMeta.textContent = '4 sessions';
    caption.textContent = isMesh
      ? 'Every sandbox can speak to another. Each mesh stays private.'
      : 'One session. One sandbox. Sized for the work.';

    buttons.forEach(function(button) {
      var isActive = button.getAttribute('data-parallel-mode') === mode;
      button.classList.toggle('is-active', isActive);
      button.setAttribute('aria-pressed', String(isActive));
    });
  }

  buttons.forEach(function(button) {
    button.addEventListener('click', function() {
      setMode(button.getAttribute('data-parallel-mode'));
    });
  });
})();

(function() {
  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var activityByEnvironment = {
    auth: [
      'tool › rg "session" src/auth',
      'reading src/auth/session.rs:184',
      'editing refresh_session()',
      'tool › cargo test auth::session',
      'checking test output'
    ],
    billing: [
      'tool › rg "invoice.failed" .',
      'reading stripe/webhook.go:92',
      'editing retry_invoice()',
      'tool › go test ./billing/...',
      'reviewing the diff'
    ],
    docs: [
      'reading docs/config.toml',
      'editing quickstart.md',
      'tool › zola check',
      'checking internal links',
      'reviewing rendered output'
    ],
    api: [
      'tool › rg "retry" client',
      'reading client/retry.ts:41',
      'editing exponentialBackoff()',
      'tool › pnpm test retry',
      'checking type errors'
    ],
    tests: [
      'tool › cargo test --workspace',
      'inspecting failure output',
      'editing flaky_test.rs:73',
      'rerunning the targeted test',
      'checking the final result'
    ],
    release: [
      'reading 18 changed files',
      'tool › cargo clippy',
      'checking generated clients',
      'reviewing migration notes',
      'writing a release summary'
    ],
    web: [
      'tool › rg "empty state" apps',
      'reading components/empty.tsx',
      'editing empty-state copy',
      'tool › pnpm test --filter web',
      'checking the browser output'
    ],
    infra: [
      'reading gateway traces',
      'tool › rg "latency" crates',
      'profiling the hot path',
      'editing gateway/router.rs',
      'rerunning the benchmark'
    ]
  };
  var meshActivityByEnvironment = {
    auth: [
      'sending types → api',
      'retry result ← api',
      'sending token → api',
      'schema update → api'
    ],
    api: [
      'auth types ← auth',
      'sending retry → auth',
      'test token ← auth',
      'schema update ← auth'
    ],
    web: [
      'preview URL → tests',
      'failing spec ← tests',
      'DOM snapshot → tests',
      'test result ← tests'
    ],
    tests: [
      'preview URL ← web',
      'failing spec → web',
      'DOM snapshot ← web',
      'test result → web'
    ],
    billing: [
      'webhook sample → docs',
      'runbook link ← docs',
      'invoice trace → docs',
      'copy update ← docs'
    ],
    docs: [
      'webhook ← billing',
      'runbook → billing',
      'invoice trace ← billing',
      'copy update → billing'
    ],
    infra: [
      'benchmark → release',
      'candidate SHA ← release',
      'gateway trace → release',
      'rollout plan ← release'
    ],
    release: [
      'benchmark ← infra',
      'candidate SHA → infra',
      'gateway trace ← infra',
      'rollout plan → infra'
    ]
  };
  var activityNodes = Array.prototype.slice.call(document.querySelectorAll('.cw-agent-work, .cw-mesh-agent-work'));

  if (reduceMotion) return;

  activityNodes.forEach(function(node, nodeIndex) {
    var article = node.closest('.cw-agent-terminal, .cw-mesh-agent');
    var label = article && article.querySelector('header > span:first-child');
    var environment = label ? label.textContent.split('·')[0].trim() : '';
    var isMeshSession = node.classList.contains('cw-mesh-agent-work');
    var activities = isMeshSession
      ? meshActivityByEnvironment[environment]
      : activityByEnvironment[environment];
    var activityIndex = nodeIndex % (activities ? activities.length : 1);

    if (!activities || activities.length < 2) return;

    function scheduleNext() {
      window.setTimeout(function() {
        node.classList.add('is-changing');
        window.setTimeout(function() {
          activityIndex = (activityIndex + 1) % activities.length;
          node.textContent = activities[activityIndex];
          node.classList.remove('is-changing');
          scheduleNext();
        }, 140);
      }, 2100 + (nodeIndex % 5) * 180);
    }

    scheduleNext();
  });
})();
