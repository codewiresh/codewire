// The pricing page: the phone menu, copy buttons and the sandbox price calculator. theme.js runs the theme switch.
(() => {
  const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const root = document.documentElement;
  root.classList.add('js');   // the buttons that need this script show only with it: see html:not(.js) in public.css

  /* ---------- big type sits on the grid: each display line moves left by its first letter's side bearing ---------- */
  // The same correction public.js makes on the homepage: at display sizes a glyph's ink starts a few pixels right of its
  // box, so a headline whose box starts on a column line would read as off the line.
  {
    const cv = document.createElement('canvas').getContext('2d');
    const optical = () => $$('.ptitle h1, .sec h2, .end h2, .plan-title h3, .plan-price, .total output').forEach((h) => {
      const cs = getComputedStyle(h), ch = h.textContent.trim().charAt(0); if (!ch) return;
      cv.font = `${cs.fontStyle} ${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
      const lsb = -cv.measureText(ch).actualBoundingBoxLeft;   // how far the ink starts right of the glyph's origin
      h.style.marginLeft = (Math.abs(lsb) < 0.3 ? 0 : -lsb).toFixed(2) + 'px';
    });
    optical();
    let timer = 0; addEventListener('resize', () => { clearTimeout(timer); timer = setTimeout(optical, 120); });
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(optical);
  }

  /* ---------- menu (phones) ---------- */
  const menu = $('#menu'), menuBtn = $('#menuBtn');
  const closeMenu = () => { menu.classList.remove('open'); menuBtn.setAttribute('aria-expanded', 'false'); };
  menuBtn.addEventListener('click', () => { const open = !menu.classList.contains('open'); menu.classList.toggle('open', open); menuBtn.setAttribute('aria-expanded', String(open)); });
  $$('#menu a').forEach((a) => a.addEventListener('click', closeMenu));

  /* ---------- copy: the install command, and the prompt for an agent ---------- */
  const toast = $('#toast'), say = (t) => { toast.textContent = t; toast.classList.add('on'); clearTimeout(say.t); say.t = setTimeout(() => toast.classList.remove('on'), 1400); };
  $$('.cw-site-copy').forEach((b) => b.addEventListener('click', async () => {
    const code = b.previousElementSibling;
    try { await navigator.clipboard.writeText(code.textContent); }
    catch (e) { const r = document.createRange(); r.selectNodeContents(code); const s = getSelection(); s.removeAllRanges(); s.addRange(r); say('Selected, press copy'); return; }
    b.classList.add('done'); b.setAttribute('aria-label', 'Copied');
    clearTimeout(b.t); b.t = setTimeout(() => { b.classList.remove('done'); b.setAttribute('aria-label', 'Copy install command'); }, 1600);
  }));
  $$('[data-copy-text]').forEach((b) => b.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(b.dataset.copyText); say('Prompt copied'); }
    catch (e) { say('Copy failed'); }
  }));

  /* ---------- the calculator: price a sandbox per second, hour, day, week or month ---------- */
  const form = $('[data-pricing-estimator]');
  if (!form) return;
  const NAMES = ['cpu', 'memory', 'disk'];
  // hours in each period; a month is 730 hours
  const HOURS = { second: 1 / 3600, hour: 1, day: 24, week: 168, month: 730 };
  const rates = Object.fromEntries(NAMES.map((n) => [n, Number(form.dataset['rate' + n[0].toUpperCase() + n.slice(1)])]));
  const inputs = Object.fromEntries(NAMES.map((n) => [n, $(`[data-pricing-input="${n}"]`, form)]));
  // A slider with data-pricing-steps moves over those sizes only; its value is the step's index.
  const steps = (n) => (inputs[n].dataset.pricingSteps || '').split(' ').filter(Boolean).map(Number);
  const read = (n) => (steps(n).length ? steps(n)[Number(inputs[n].value)] : Number(inputs[n].value));
  const write = (n, value) => { inputs[n].value = steps(n).length ? String(steps(n).indexOf(value)) : String(value); };
  const presets = $$('[data-preset-cpu]', form), periods = $$('[data-period]', form);
  const shape = $('[data-pricing-shape]', form), periodLabel = $('[data-pricing-period-label]', form);
  let period = 'hour';
  // the controls need this script; without it the page shows the hourly price of the default size
  $$('[data-pricing-controls]', form).forEach((el) => { el.hidden = false; });

  // two decimals from one euro up; below that, four significant digits
  const euros = (v) => {
    if (v >= 1) return '€' + v.toFixed(2);
    return '€' + v.toFixed(Math.min(12, 3 - Math.floor(Math.log10(v)))).replace(/0+$/, '');
  };
  const press = (buttons, active) => buttons.forEach((b) => b.setAttribute('aria-pressed', String(b === active)));
  const render = () => {
    const size = Object.fromEntries(NAMES.map((n) => [n, read(n)]));
    let total = 0;
    NAMES.forEach((n) => {
      const cost = size[n] * rates[n] * HOURS[period];
      total += cost;
      $(`[data-pricing-cost="${n}"]`, form).textContent = euros(cost);
      const shown = size[n] + (n === 'cpu' ? ' vCPU' : ' GB');
      $(`[data-pricing-value="${n}"]`, form).textContent = shown;
      inputs[n].setAttribute('aria-valuetext', shown);
    });
    $('[data-pricing-cost="total"]', form).textContent = euros(total);
    shape.textContent = `${size.cpu} vCPU · ${size.memory} GB memory · ${size.disk} GB disk`;
    periodLabel.textContent = 'per ' + period;
    press(presets, presets.find((b) => Number(b.dataset.presetCpu) === size.cpu && Number(b.dataset.presetMemory) === size.memory) || null);
  };
  presets.forEach((b) => b.addEventListener('click', () => { write('cpu', Number(b.dataset.presetCpu)); write('memory', Number(b.dataset.presetMemory)); render(); }));
  periods.forEach((b) => b.addEventListener('click', () => { period = b.dataset.period; press(periods, b); render(); }));
  NAMES.forEach((n) => inputs[n].addEventListener('input', render));
  render();
})();
