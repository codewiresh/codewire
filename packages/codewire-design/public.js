// The public homepage: theme, the steel wire behind the page (WebGL), the grid, and one live diagram per section.
// The wire's fragment shader:
const WIRE_SHADER = `
precision highp float;
uniform vec2  uRes;
uniform float uTime, uTan, uRoll, uSpread, uTwist, uFade, uPulse, uWS;   // uWS: spacing of the wires inside a strand (1 = laid tight)
uniform vec3  uCam, uTgt, uBg, uSteel, uSig, uRim, uRainC, uRainH;
uniform float uSoft, uRain, uRainT, uPx;   // uRainT: rain clock, advanced by the speed setting each frame
uniform vec4  uRainG;    // grid in device pixels: left edge, column width, column pitch, glyphs per column
uniform vec2  uRainR;    // row height, page scroll (device pixels)
uniform float uRainN;    // how many grid columns there are
uniform vec3  uHov;      // the unlay under the pointer: where along the rope, how strong (0..1), how wide
uniform vec4  uTrail[24]; // the pointer's recent path: x, page y (device pixels), age in seconds, live
uniform sampler2D uGlyphs;
#define TAU 6.2831853
#define NS 6.0
const float SN = 0.5;
const float RS0 = 1.0 / (1.0 + SN);
const float RSTR = RS0 * SN;
const float RWW = RSTR / 5.0;
const float OMW = 0.16 / RWW;
const float RF = RWW / 3.0;
float h1(float n) { return fract(sin(n * 127.1) * 43758.5453); }
mat2 rot(float a) { float c = cos(a), s = sin(a); return mat2(c, -s, s, c); }
float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }
// digital rain, as in the rope film: glyphs never move; brightness falls down each glyph column as an uneven
// sawtooth with a bright cursor at each drop's head. The glyph cells are laid on the page grid: a whole number of
// glyphs fills each of the twelve columns, the gutters stay clear, and rows sit on the baseline and scroll with the page.
// Returns (trail, head, ripple).
vec3 rainLayer(vec2 p, float t) {
  float x = p.x - uRainG.x, ci = floor(x / uRainG.z), xin = x - ci * uRainG.z;
  if (ci < 0.0 || ci > uRainN - 1.0 || xin >= uRainG.y) return vec3(0.0);
  vec2  cell = vec2(uRainG.y / uRainG.w, uRainR.x);
  vec2  g  = vec2(ci * uRainG.w + xin / cell.x, (p.y + uRainR.y) / cell.y);
  vec2  id = floor(g), f = fract(g);
  float c  = id.x;
  float spd = 5.0 + 10.0 * h1(c * 3.7);
  float P   = 16.0 + 44.0 * h1(c * 5.3);
  float q   = t * spd - id.y + h1(c * 9.1) * 300.0;
  float seg = floor(q / P), lc = q - seg * P;
  float len = P * mix(0.2, 0.95, h1(seg * 1.7 + c * 0.37));
  float on  = step(h1(seg * 4.3 + c * 1.1), 0.78);
  float b   = on * step(lc, len) * (1.0 - lc / len);
  float cur = on * step(lc, 1.0);
  // the pointer's trail: glyphs light up under it, whole cells at a time, and fade out behind it
  vec2  cc = vec2(uRainG.x + ci * uRainG.z + (id.x - ci * uRainG.w + 0.5) * cell.x, (id.y + 0.5) * cell.y);
  float rp = 0.0;
  for (int i = 0; i < 24; i++) {
    vec4 R = uTrail[i];
    if (R.w > 0.0) { float e = length(cc - R.xy) / (cell.y * 1.1), k = 1.0 - R.z / 0.6; rp = max(rp, exp(-e * e) * k * k); }
  }
  float rate = mix(0.25, 2.2, hash(id)) * (1.0 + 6.0 * max(cur, rp));
  float gi   = floor(hash(id * 1.31 + floor(t * rate + hash(id * 7.7)) * 0.173) * 64.0);
  // flush to the column: the first glyph in a column is moved so its ink starts on the column's left line, the last so
  // its ink ends on the right line; the glyphs between stay centred. The atlas carries each glyph's ink edges in G and B.
  vec2  base = vec2(mod(gi, 8.0), floor(gi / 8.0));
  vec2  lr   = texture2D(uGlyphs, (base + 0.5) / 8.0).gb;
  float k = uRainG.w, ix = mod(id.x, k);
  float sx = ix < 0.5 ? lr.x : (ix > k - 1.5 ? lr.y - 1.0 : 0.0);
  float u  = f.x + sx;
  vec2  mg   = 1.0 / cell;
  float edge = step(0.0, u) * step(u, 1.0) * step(mg.y, f.y) * step(f.y, 1.0 - mg.y);
  vec2  guv  = (base + vec2(clamp(u, 0.02, 0.98), clamp(f.y, 0.03, 0.97))) / 8.0;
  float mask = texture2D(uGlyphs, guv).r * edge;
  return vec3(pow(b, 1.7) * mask, cur * mask, rp * mask);
}
float gWire = 0.5, gFil = 1.0;
float ring(vec2 lo, float n, float R, float b, out float id) {
  float a = atan(lo.y, lo.x), m = floor((a - b) * n / TAU + 0.5), bw = 1e9; id = m;
  for (int dm = -1; dm <= 1; dm++) {
    float ph = b + (m + float(dm)) * TAU / n, l = length(lo - R * vec2(cos(ph), sin(ph)));
    if (l < bw) { bw = l; id = m + float(dm); }
  }
  return bw;
}
// the same 6x19 rope as before: six strands laid around the axis, nineteen wires in each, filaments up close
float rope(vec3 p, float lod, float pixT, out vec4 info) {
  // under the pointer the rope unlays: the strands ease outward and the wires in them part, then lay back as it moves on
  float hx = (p.x - uHov.x) / uHov.z, hb = max(uHov.y, 0.0) * exp(-hx * hx), sp = uSpread + hb * 0.36, ws = uWS + hb * 0.18;
  vec2 cs = p.yz; float r = length(cs), rS = RS0 * sp, rB = RSTR * ws, outer = rS + rB, d;
  info = vec4(p.x, 1.0, 0.0, 1.0);
  if (r > outer + 0.3) return r - outer;
  float base = p.x * 0.42 * uTwist / RS0, ang = atan(cs.y, cs.x), k = floor((ang - base) * NS / TAU + 0.5);
  float best = 1e9, sid = 0.0; vec2 off = vec2(0.0);
  for (int dk = -1; dk <= 1; dk++) {
    float kk = k + float(dk), phi = base + kk * TAU / NS; vec2 o = cs - rS * vec2(cos(phi), sin(phi)); float dd = length(o);
    if (dd < best) { best = dd; sid = kk; off = o; }
  }
  float dStrand = best - rB, dWire = dStrand;
  if (lod < 0.999 && dStrand < RWW * 2.5) {
    vec2 lo = rot(base + sid * TAU / NS) * off;
    float bw = -p.x * OMW + mod(sid, NS) * 1.7, rl = length(lo), io, ii;
    float dOut = ring(lo, 12.0, 4.0 * RWW * ws, bw, io) - RWW;
    float dIn = ring(lo, 6.0, 2.0 * RWW * ws, bw + 0.26, ii) - RWW;
    dWire = min(dOut, min(dIn, rl - RWW));
    float wid = dWire == dOut ? mod(io, 12.0) : dWire == dIn ? 12.0 + mod(ii, 6.0) : 19.0;
    gWire = h1(mod(sid, NS) * 31.7 + wid * 3.13 + 0.5);
    float lodF = smoothstep(0.25, 0.6, pixT / RF); gFil = 1.0;
    if (lodF < 0.999 && dWire < RWW * 0.5) {
      vec2 wc = dWire == dOut ? 4.0 * RWW * ws * vec2(cos(bw + io * TAU / 12.0), sin(bw + io * TAU / 12.0))
              : dWire == dIn ? 2.0 * RWW * ws * vec2(cos(bw + 0.26 + ii * TAU / 6.0), sin(bw + 0.26 + ii * TAU / 6.0)) : vec2(0.0);
      vec2 lf = lo - wc; float fid;
      float dF = min(ring(lf, 6.0, 2.0 * RF, p.x * 0.16 / RF * 1.6 + wid * 0.9, fid) - RF, length(lf) - RF);
      gFil = mix(smoothstep(2.15 * RF, 2.9 * RF, length(lf)), 1.0, lodF);
      dWire = mix(dF, dWire, lodF);
    }
    info.w = mix(clamp((rl - 3.0 * RWW) / (2.0 * RWW), 0.0, 1.0), 1.0, smoothstep(1.0, 1.6, ws));
  }
  d = mix(dWire, dStrand, lod) * (0.8 - 0.25 * hb);   // shorter steps where the lay changes along the rope
  float c1 = clamp((r - (rS - RSTR * 0.1)) / (RSTR * 1.1), 0.0, 1.0);
  info.yz = vec2(mix(c1, 1.0, smoothstep(1.3, 2.2, sp)), mod(sid, NS));
  return d;
}
void main() {
  vec2 uv = (gl_FragCoord.xy - 0.5 * uRes) / uRes.y * 2.0;
  vec3 fw = normalize(uTgt - uCam), rt = normalize(cross(fw, vec3(0.0, 1.0, 0.0))), up = cross(rt, fw);
  vec3 rd = normalize(fw + (uv.x * rt + uv.y * up) * uTan), ro = uCam;
  mat2 R = rot(uRoll); ro.xy = R * ro.xy; rd.xy = R * rd.xy;      // the rope lies at an angle across the page
  float pix = 2.0 * uTan / uRes.y;
  vec3 bg = uBg;
  if (uRain > 0.0) {
    // painted into the paper, so it reads on light and dark alike; the colour's alpha is its strength
    vec3 r = rainLayer(vec2(gl_FragCoord.x, uRes.y - gl_FragCoord.y), uRainT);
    bg = mix(bg, uRainC, clamp(r.x, 0.0, 1.0) * uRain);
    bg = mix(bg, uRainH, clamp(r.y, 0.0, 1.0) * uRain);
    bg = mix(bg, uRainH, clamp(r.z, 0.0, 1.0) * clamp(uRain * 1.5 + 0.1, 0.0, 0.55));   // the pointer's trail, a little above the rain's own strength
  }
  vec3 col = bg;
  float Rb = RS0 * uSpread + RSTR * uWS + 0.35 + max(uHov.y, 0.0) * (RS0 * 0.36 + RSTR * 0.18);
  float a = dot(rd.yz, rd.yz), b = dot(ro.yz, rd.yz), c = dot(ro.yz, ro.yz) - Rb * Rb, disc = b * b - a * c;
  if (disc > 0.0 && uFade < 0.995) {
    float sq = sqrt(disc), t = max(0.0, (-b - sq) / a), tOut = (-b + sq) / a; bool hit = false; vec4 info = vec4(0.0);
    for (int i = 0; i < 170; i++) {
      vec3 p = ro + rd * t;
      float lod = smoothstep(0.3, 0.7, pix * t / RWW), d = rope(p, lod, pix * t, info);
      if (d < 0.0006 * t + 0.0004) { hit = true; break; }
      t += d; if (t > tOut || t > 80.0) break;
    }
    if (hit) {
      vec3 p = ro + rd * t; float lod = smoothstep(0.3, 0.7, pix * t / RWW), e = 0.0007 + 0.0004 * t; vec4 dm;
      const vec2 k = vec2(1.0, -1.0);
      vec3 n = normalize(k.xyy * rope(p + k.xyy * e, lod, pix * t, dm) + k.yyx * rope(p + k.yyx * e, lod, pix * t, dm) +
                         k.yxy * rope(p + k.yxy * e, lod, pix * t, dm) + k.xxx * rope(p + k.xxx * e, lod, pix * t, dm));
      // the same lighting and texture as the rope film: key from the upper left, a coloured rim from behind,
      // every wire a slightly different steel, grime down in the grooves
      vec3 L1 = normalize(vec3(-0.45, 0.85, 0.55)), L2 = normalize(vec3(0.75, 0.1, -0.65)), hv = normalize(L1 - rd), rf = reflect(rd, n);
      float ao = mix(mix(0.2, 0.42, uSoft), 1.0, info.y) * mix(mix(0.28, 0.6, uSoft), 1.0, info.w) * mix(0.45, 1.0, gFil);
      float dif = clamp(dot(n, L1) * 0.6 + 0.4, 0.0, 1.0);
      float sp = pow(max(dot(n, hv), 0.0), mix(110.0, 30.0, uSoft)) * mix(1.6, 0.75, uSoft) + pow(max(dot(n, hv), 0.0), 8.0) * mix(0.1, 0.16, uSoft);
      float rim = pow(clamp(dot(n, L2), 0.0, 1.0), 1.4), fre = pow(1.0 - abs(dot(n, rd)), 3.0);
      vec3 env = mix(vec3(0.016, 0.032, 0.032), uRim * 0.3, smoothstep(-0.2, 0.9, rf.y));
      float wv = gWire;
      vec3 steel = uSteel * (0.8 + 0.34 * wv) * mix(vec3(1.0), vec3(1.06, 1.0, 0.9), step(0.78, fract(wv * 7.3)));
      steel *= 0.9 + 0.1 * sin(p.x * (2.0 + 3.0 * wv) + wv * 40.0);
      sp *= 0.6 + 0.8 * fract(wv * 13.7);
      vec3 cc = steel * (0.03 + 0.78 * dif) * ao * ao + vec3(1.0, 0.98, 0.94) * sp * ao + uRim * rim * 0.45 * ao + env * fre * 0.8 * ao;
      cc *= mix(vec3(0.52, 0.48, 0.42), vec3(1.0), smoothstep(0.02, 0.45, info.y) * 0.85 + 0.15);
      // a live signal now and then, running along one strand
      float ph = fract(p.x * 0.05 - uTime * 0.09 + h1(info.z) * 3.0);
      cc = mix(cc, uSig * (0.6 + 0.6 * dif), uPulse * step(info.z, 0.5) * smoothstep(0.975, 0.99, ph) * (1.0 - smoothstep(0.995, 1.0, ph)) * info.w);
      cc = 1.0 - exp(-cc * 1.35);
      float fog = 1.0 - exp(-max(t - 4.0, 0.0) * 0.035);
      // the rain is the back layer: the wire covers it, and only lets it through as the wire itself fades out
      float fd = clamp(fog + uFade, 0.0, 1.0);
      col = mix(cc, mix(uBg, bg, fd * fd * fd), fd);
    }
  }
  gl_FragColor = vec4(col, 1.0);
}
`;

(async () => {
  document.documentElement.classList.add('js');   // the page's script runs: see html:not(.js) in public.css
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
  // whether a WebGL program linked, once it has: KHR_parallel_shader_compile lets the GPU compile while the page runs,
  // where asking for COMPILE_STATUS or LINK_STATUS at once holds the page until it is done (a quarter second for each shader on a first visit)
  const linked = async (c, pr) => {
    const par = c.getExtension('KHR_parallel_shader_compile');
    if (par) while (!c.getProgramParameter(pr, par.COMPLETION_STATUS_KHR)) await new Promise(requestAnimationFrame);
    return c.getProgramParameter(pr, c.LINK_STATUS);
  };
  const NS_SVG = 'http://www.w3.org/2000/svg';
  const el = (tag, attrs, parent) => { const e = document.createElementNS(NS_SVG, tag); for (const k in attrs) { const v = attrs[k]; if ((k === 'fill' || k === 'stroke') && String(v).startsWith('var(')) e.style[k] = v; else e.setAttribute(k, v); } if (parent) parent.appendChild(e); return e; };
  const css = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
  const INK = 'var(--ink)', GREY = 'var(--grey)', SIG = 'var(--signal)', PAPER = 'var(--paper)';

  /* ---------- theme: system, light, dark ---------- */
  const root = document.documentElement, mqDark = matchMedia('(prefers-color-scheme: dark)');
  const RKEY = 'codewire-rain';
  // theme.js owns the choice (system, light or dark) and sets data-theme; this page only redraws when it changes
  const choice = () => root.getAttribute('data-theme') || 'system';
  const resolved = () => (choice() === 'system' ? (mqDark.matches ? 'dark' : 'light') : choice());
  // the look: layout offsets, box padding and backgrounds, rhythm and effects. These are the shipped defaults.
  // The colours are the stylesheet's (routes/public.css owns the palette); the canvases read them from there.
  const PALETTE = { paper: '--paper', ink: '--ink', signal: '--signal', grid: '--colline', rain: '--wire-rain', steel: '--wire-steel', rim: '--wire-rim' };
  const palette = () => { const cs = getComputedStyle(root); return Object.fromEntries(Object.entries(PALETTE).map(([k, name]) => [k, cs.getPropertyValue(name).trim()])); };
  // colours are #RRGGBB or #RRGGBBAA
  const hex6 = (h) => String(h).slice(0, 7);
  const a01 = (h) => (String(h).length > 7 ? parseInt(String(h).slice(7, 9), 16) / 255 : 1);
  const LAY0 = { wire: 28, text: -88, ledeC: 0, ledeY: 48, specC: 0, specY: -48 }, SIZE0 = 1.18;
  // boxes that can carry padding, and whether they do by default (text boxes yes, graphics no)
  const BOXES = [['lede', '.hero .lede', 1], ['spec', '.specwrap', 0], ['install', '#getrow .getbox', 1], ['sessions', '.sess', 1], ['fig1', '.xs', 0], ['ends', '.ends .note', 1],
    ['fig3', '.net', 0], ['mesh', '.mside', 1], ['fig4', '.iso', 0], ['isolation', '.isoside', 1], ['sdks', '.langs', 1], ['code', '.code', 1], ['licences', '.facts', 1], ['compare', '.cmp', 1], ['footer-install', '.endget .getbox', 1]];
  const PADS0 = Object.fromEntries(BOXES.map(([k, , d]) => [k, d]));
  const RHY0 = { base: 8, gutter: 16, grid: 1, fig: 1, halfY: 0 };
  const FX0 = { rain: 1, rainSize: 23, rainSpeed: 0.7, blur: 11, ripple: 1 };
  const BGS0 = Object.fromEntries(BOXES.map(([k]) => [k, 1])), FIGS = BOXES.filter(([, , d]) => !d).map(([k]) => k);
  const fresh = () => ({ size: SIZE0, soft: 0.7, layout: Object.assign({}, LAY0), pads: Object.assign({}, PADS0), rhythm: Object.assign({}, RHY0), bgs: Object.assign({}, BGS0), fx: Object.assign({}, FX0) });
  const LOOK = fresh();
  try { const r = localStorage.getItem(RKEY); if (r != null) LOOK.fx.rain = +r ? 1 : 0; } catch (e) {}   // the visitor's rain switch
  const onLook = [], onLayout = [];   // renderers redraw on onLook
  const applyLayout = () => {
    const L = LOOK.layout, px = (v) => Math.round(v) + 'px';
    root.style.setProperty('--text-dy', px(L.text)); root.style.setProperty('--lede-c', L.ledeC | 0); root.style.setProperty('--lede-y', px(L.ledeY));
    root.style.setProperty('--spec-c', L.specC | 0); root.style.setProperty('--spec-y', px(L.specY));
    const Rh = LOOK.rhythm;
    root.style.setProperty('--base', Rh.base + 'px');
    const gut = Rh.gutter > 0 ? Math.max(Rh.base, Math.round(Rh.gutter / Rh.base) * Rh.base) : 0;   // gutter in whole baseline units
    if (gut) root.style.setProperty('--gap', gut + 'px'); else root.style.removeProperty('--gap');
    if (Rh.halfY) root.style.setProperty('--pad-y', 'calc(var(--gap) / 2)'); else root.style.removeProperty('--pad-y');
    const FX = LOOK.fx; document.body.classList.toggle('blurbox', FX.blur > 0); root.style.setProperty('--box-blur', FX.blur + 'px');
    const rb = $('#rainBtn'); if (rb) { rb.setAttribute('aria-pressed', String(!!FX.rain)); rb.setAttribute('aria-label', 'Matrix rain: ' + (FX.rain ? 'on' : 'off')); }
    BOXES.forEach(([k, sel]) => { const b = $(sel); if (!b) return; b.classList.add('box'); b.classList.toggle('padded', !!LOOK.pads[k]); b.classList.toggle('nobg', !LOOK.bgs[k]); });
    onLayout.forEach((f) => f());
    requestAnimationFrame(() => { window.cwPlaceMarks && window.cwPlaceMarks(); window.cwRelayout && window.cwRelayout(); window.cwOptical && window.cwOptical(); window.cwRhythm && window.cwRhythm(); });
  };
  const applyLook = () => {
    applyLayout();
    const c = palette();
    onLook.forEach((f) => f(c));
  };
  document.addEventListener('codewire:themechange', () => applyLook());
  mqDark.addEventListener('change', () => { if (choice() === 'system') applyLook(); });
  $('#rainBtn').addEventListener('click', () => { LOOK.fx.rain = LOOK.fx.rain ? 0 : 1; try { localStorage.setItem(RKEY, LOOK.fx.rain); } catch (e) {} applyLook(); });
  applyLook();

  /* ---------- printer's marks on the boxes that carry them ---------- */
  const TARGET = '<svg viewBox="0 0 15 15" fill="none" stroke="currentColor" stroke-width="1"><circle cx="7.5" cy="7.5" r="4.5"/><circle cx="7.5" cy="7.5" r="1.6" fill="currentColor" stroke="none"/><path d="M7.5 0v15M0 7.5h15"/></svg>';
  $$('.reg').forEach((el) => {
    ['tl', 'tr', 'bl', 'br'].forEach((c) => { const m = document.createElement('i'); m.className = 'cm ' + c; m.setAttribute('aria-hidden', 'true'); el.appendChild(m); });
    const t = document.createElement('i'); t.className = 'tg'; t.setAttribute('aria-hidden', 'true'); t.innerHTML = TARGET; el.appendChild(t);
    if (el.dataset.plate) { const pl = document.createElement('i'); pl.className = 'pl'; pl.setAttribute('aria-hidden', 'true'); pl.textContent = el.dataset.plate.toUpperCase(); el.appendChild(pl); }
  });
  // whole-pixel grid: integer column width and gutter, the spare pixels go to the margins (left gets the smaller half); N columns from --cols
  const fitGrid = () => {
    root.style.removeProperty('--col'); root.style.removeProperty('--ml'); root.style.removeProperty('--mr');
    const vw = document.documentElement.clientWidth, pg = getComputedStyle($('.page'));
    const m0 = Math.ceil(parseFloat(pg.paddingLeft)), m1 = Math.ceil(parseFloat(pg.paddingRight));
    const g = Math.round(parseFloat(getComputedStyle($('.cols div')).columnGap) || 0);
    const N = parseInt(getComputedStyle(root).getPropertyValue('--cols')) || 12;
    const col = Math.floor((vw - m0 - m1 - (N - 1) * g) / N), spare = vw - N * col - (N - 1) * g, ml = Math.floor(spare / 2);
    root.style.setProperty('--col', col + 'px'); root.style.setProperty('--ml', ml + 'px'); root.style.setProperty('--mr', (spare - ml) + 'px');
  };
  window.cwFitGrid = fitGrid;
  // grid: read the column lines that are drawn, use them for the drag step and to seat each registration target on a line
  const colEls = $$('.cols i');
  window.cwPlaceMarks = () => {
    fitGrid();
    const cr = colEls.filter((c) => c.offsetWidth > 0).map((c) => c.getBoundingClientRect()), pitch = cr.length > 1 ? cr[1].left - cr[0].left : 100;
    root.style.setProperty('--pitch', pitch.toFixed(3) + 'px');
    const lines = []; cr.forEach((r) => lines.push(r.left + 0.5, r.right - 0.5));
    $$('.reg').forEach((el) => {
      const r = el.getBoundingClientRect(), t = el.querySelector(':scope > .tg'); if (!t || !r.width) return;
      const mid = r.left + r.width / 2, inside = lines.filter((x) => x > r.left + 24 && x < r.right - 24);
      const x = inside.length ? inside.reduce((b, v) => (Math.abs(v - mid) < Math.abs(b - mid) ? v : b)) : mid;
      t.style.left = (x - r.left) + 'px';
    });
  };
  addEventListener('resize', () => window.cwPlaceMarks()); window.cwPlaceMarks();
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => window.cwPlaceMarks());

  /* ---------- rhythm: top up aspect-ratio boxes to whole units so everything below stays on the baseline ---------- */
  {
    const unit = () => LOOK.rhythm.base;
    // aspect-ratio drawings, and heading rows whose labels hang on the heading's baseline
    const SNAP = '[data-snap], .sec .head, .end .ask';
    const snap = () => $$(SNAP).forEach((el) => {
      el.style.paddingBottom = '';
      const h = el.getBoundingClientRect().height, u = unit(), extra = Math.ceil(h / u - 0.001) * u - h;
      if (extra > 0.01) el.style.paddingBottom = (parseFloat(getComputedStyle(el).paddingBottom) + extra).toFixed(2) + 'px';
    });
    const ro = new ResizeObserver(() => { cancelAnimationFrame(snap.f); snap.f = requestAnimationFrame(() => window.cwRhythm()); });
    $$(SNAP).forEach((el) => ro.observe(el));
    window.cwRhythm = () => { snap(); };
    snap(); if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => window.cwRhythm());
  }

  /* ---------- optical alignment: the first letter of each big heading sits on its column line ---------- */
  {
    const cv = document.createElement('canvas').getContext('2d');
    window.cwOptical = () => $$('.sec h2, .end h2, .ends .big').forEach((h) => {
      const cs = getComputedStyle(h), ch = h.textContent.trim().charAt(0); if (!ch) return;
      cv.font = `${cs.fontStyle} ${cs.fontWeight} ${cs.fontSize} ${cs.fontFamily}`;
      const lsb = -cv.measureText(ch).actualBoundingBoxLeft;   // how far the ink starts right of the glyph's origin
      h.style.marginLeft = (Math.abs(lsb) < 0.3 ? 0 : -lsb).toFixed(2) + 'px';
    });
    window.cwOptical(); let ot = 0; addEventListener('resize', () => { clearTimeout(ot); ot = setTimeout(window.cwOptical, 120); });
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(window.cwOptical);
  }

  /* ---------- menu (phones) ---------- */
  const menu = $('#menu'), menuBtn = $('#menuBtn');
  menuBtn.addEventListener('click', () => { const open = !menu.classList.contains('open'); menu.classList.toggle('open', open); menuBtn.setAttribute('aria-expanded', String(open)); });
  $$('#menu a').forEach((a) => a.addEventListener('click', () => { menu.classList.remove('open'); menuBtn.setAttribute('aria-expanded', 'false'); }));

  /* ---------- 2.0 terminals: type the command, run the steps, print what cw prints ---------- */
  {
    const SPIN = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏', PROMPT = '~/my-app $ ';
    const fmt = (v) => (v < 60 ? v.toFixed(1) + 's' : Math.floor(v / 60) + 'm ' + Math.floor(v % 60) + 's');
    // the commands and output are the quickstart's; the step times are its first-run numbers, played back faster
    const SCRIPTS = {
      termL: [
        { c: 'cw create --local --name my-app --path .' },
        { s: 'Preparing sources', t: 0, d: 260 },
        { s: 'Checking the VM runtime', t: 1.2, d: 640 },
        { s: 'Preparing the workspace disk', t: 0, d: 260 },
        { s: 'Pulling the image', t: 87, d: 1900 },
        { s: 'Starting the VM', t: 76, d: 1700 },
        { s: 'Booting the workspace', t: 1.8, d: 720 },
        { o: '✓ Environment my-app created · local VM', k: 'ok' },
        { o: '  2 vCPU · 4 GiB RAM · 20 GiB disk', k: 'd' },
        { c: 'cw run claude --in my-app' },
        { w: 520 },
        { o: '✓ Started Claude Code in my-app/claude · local VM', k: 'ok' },
        { o: '  Detach: Ctrl-B, then D', k: 'd' },
      ],
      termC: [
        { c: 'cw create --name my-app --image workspace' },
        { s: '', d: 1500 },
        { o: 'my-app · cloud VM', k: 'b' },
        { o: '  2 vCPU · 8 GiB RAM · 10 GiB disk', k: 'd' },
        { c: 'cw run claude --in my-app' },
        { w: 520 },
        { o: '✓ Started Claude Code in my-app/claude · cloud', k: 'ok' },
        { o: '  Detach: Ctrl-B, then D · Reconnect: cw --cloud attach my-app --session claude', k: 'd' },
      ],
    };
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const el = (tag, cls, txt) => { const e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; };
    const makeTerm = (box) => {
      const body = box.querySelector('.tbody'), st = box.querySelector('.tst'), script = SCRIPTS[box.id], cur = el('span', 'cur blink');
      const state = (k, t) => { box.dataset.state = k; st.textContent = t; };
      let smooth = false;
      const keep = () => { body.scrollTo({ top: body.scrollHeight, behavior: smooth ? 'smooth' : 'auto' }); };
      const line = (k) => { const l = el('div', 'ln' + (k ? ' ' + k : '')); body.appendChild(l); keep(); return l; };
      const prompt = () => { const l = line(), c = el('span', 'c', ''); l.append(el('span', 'p', PROMPT), c, cur); return c; };
      const reset = () => { body.textContent = ''; state('idle', 'Idle'); prompt(); };
      const run = async (fast) => {
        smooth = !fast; body.textContent = ''; body.scrollTop = 0;
        let c = prompt();
        for (const L of script) {
          if (L.c != null) {
            if (c == null) c = prompt();
            if (!fast) { cur.classList.add('blink'); state('idle', 'Idle'); await sleep(640); cur.classList.remove('blink'); state('run', 'Running'); }
            for (const ch of L.c) { c.textContent += ch; if (!fast) { keep(); await sleep(26 + Math.random() * 46 + (ch === ' ' ? 40 : 0)); } }
            if (!fast) await sleep(260);
            cur.remove(); c = null;
          } else if (L.w) { if (!fast) await sleep(L.w); }
          else if (L.s != null) {
            const l = line('st'), m = el('span', 'm', SPIN[0]), lb = el('span', '', L.s ? ' ' + L.s.padEnd(30) : ''), tm = el('span', 'tm', L.s ? fmt(0) : '');
            l.append(m, lb, tm);
            if (!fast) { const t0 = performance.now(); for (let i = 0; ; i++) { const k = Math.min(1, (performance.now() - t0) / L.d); m.textContent = SPIN[i % SPIN.length]; if (L.s) tm.textContent = fmt(L.t * k); if (k >= 1) break; await sleep(80); } }
            if (!L.s) l.remove(); else { m.textContent = '✓'; tm.textContent = fmt(L.t); }
          } else { const l = line(L.k); if (L.o.startsWith('✓ ')) l.append(el('span', 'm', '✓'), document.createTextNode(L.o.slice(1))); else l.textContent = L.o; if (!fast) await sleep(110); }
        }
        prompt(); cur.classList.add('blink'); state('ready', 'Ready'); keep();
      };
      return { box, body, reset, run };
    };
    const terms = $$('.ends .term').map(makeTerm);
    if (reduce) terms.forEach((t) => t.run(true));
    else {
      terms.forEach((t) => t.reset());
      let vis = false;
      new IntersectionObserver((es) => es.forEach((e) => (vis = e.isIntersecting)), { rootMargin: '-12% 0px -12% 0px' }).observe($('.ends .body'));
      const ready = () => new Promise((r) => { const f = () => (vis && !document.hidden ? r() : setTimeout(f, 250)); f(); });
      (async () => { for (;;) { await ready(); await Promise.all(terms.map((t) => t.run(false))); await sleep(6500); } })();
    }
  }

  /* ---------- the wordmark: hero size at the top, glides into the bar's top-left corner as you scroll ---------- */
  const flogo = $('#flogo'), heroLogo = $('.hero .logo'), slot = $('#slot');
  const placeLogo = () => {
    const a = heroLogo.getBoundingClientRect(), b = slot.getBoundingClientRect();
    const p = Math.min(1, Math.max(0, scrollY / (innerHeight * 0.38))), e = p * p * (3 - 2 * p);
    const x = a.left + (b.left - a.left) * e, y = a.top + (b.top - a.top) * e, w = a.width + (b.width - a.width) * e;
    // the vector is laid out at its real size every frame, so it is drawn sharp at any size (scaling a cached layer pixelates)
    flogo.style.width = w.toFixed(2) + 'px';
    flogo.style.transform = `translate(${x.toFixed(2)}px, ${y.toFixed(2)}px)`;
  };
  addEventListener('scroll', placeLogo, { passive: true }); addEventListener('resize', placeLogo); placeLogo();
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(placeLogo);

  /* ---------- copy ---------- */
  const toast = $('#toast'), say = (t) => { toast.textContent = t; toast.classList.add('on'); clearTimeout(say.t); say.t = setTimeout(() => toast.classList.remove('on'), 1400); };
  /* ---------- the beta sticker: a silver holographic security label, laid straight and wrapped over the page's left edge
     as if the page were the box. Drawn by a WebGL shader: mirror silver foil with diffraction gratings pressed in (rings
     in the seal, a sweep across the field, a dot lattice, microtext), each splitting the light into its spectrum by the
     grating equation, so the colours slide as the label tilts toward the pointer; a thin-film tint over the foil; glitter facets; black
     print; a clear laminate with its glare, scratches and dust. Past the edge the label rolls away and darkens. The masks
     (shape, print, microtext, wear) are drawn once in 2D and handed to the shader as one texture. Without WebGL the same
     label is shaded per pixel on the CPU. ---------- */
  {
    let cv = $('#betaC');
    if (cv) {
      const CW = 272, CH = 84, PADR = 6, OY = 4, VIS = 200, R = 14, U0 = CW - VIS, CS = R + VIS + PADR, HS = CH + 2 * OY, SC = 0.72;   // label units; SC scales the whole label down on the page
      const dpr = Math.min(Math.max(devicePixelRatio || 1, 1), 2) * SC, WL = Math.round(CW * dpr), HL = Math.round(CH * dpr), NL = WL * HL, WS = Math.round(CS * dpr), HSP = Math.round(HS * dpr);
      cv.width = WS; cv.height = HSP; cv.style.width = CS * SC + 'px'; cv.style.height = HS * SC + 'px';
      let gl = null, g = null, img = null, px = null;
      const cs = getComputedStyle(document.documentElement), SANS = cs.getPropertyValue('--f-sans').trim() || 'Helvetica, Arial, sans-serif', MONO = cs.getPropertyValue('--f-mono').trim() || 'monospace';
      // the layers are read back once each, so they stay in CPU memory: a GPU canvas makes each getImageData wait on the GPU
      const layer = () => { const c = document.createElement('canvas'); c.width = WL; c.height = HL; const x = c.getContext('2d', { willReadFrequently: true }); x.scale(dpr, dpr); x.fillStyle = x.strokeStyle = '#000'; return [c, x]; };
      const alpha = (c) => { const d = c.getContext('2d').getImageData(0, 0, WL, HL).data, a = new Float32Array(NL); for (let i = 0; i < NL; i++) a[i] = d[i * 4 + 3] / 255; return a; };
      const rrect = (x, X, Y, w, h, r) => { x.beginPath(); x.moveTo(X + r, Y); x.arcTo(X + w, Y, X + w, Y + h, r); x.arcTo(X + w, Y + h, X, Y + h, r); x.arcTo(X, Y + h, X, Y, r); x.arcTo(X, Y, X + w, Y, r); x.closePath(); };
      const spaced = (x, txt, X, Y, sp, right) => { let w = -sp; for (const ch of txt) w += x.measureText(ch).width + sp; let cx = right ? X - w : X; for (const ch of txt) { x.fillText(ch, cx, Y); cx += x.measureText(ch).width + sp; } };
      const S = { x: CW - 40, y: 42, r: 29 };   // the seal sits at the right end; the left end wraps out of sight
      let shape, ink, micro, scr, gx, gy, zone, fleck, fx, fy, ridge;
      const build = () => {
        const [sc, sx] = layer(); rrect(sx, 0.5, 0.5, CW - 1, CH - 1, 6); sx.fill(); shape = alpha(sc);
        // the print
        const [ic, ix] = layer(); ix.textBaseline = 'alphabetic';
        ix.lineWidth = 0.8; rrect(ix, 3.5, 3.5, CW - 7, CH - 7, 3.5); ix.stroke();
        ix.lineWidth = 0.9; ix.beginPath(); ix.arc(S.x, S.y, S.r, 0, Math.PI * 2); ix.stroke();
        ix.lineWidth = 0.55; ix.beginPath(); ix.arc(S.x, S.y, S.r - 8.6, 0, Math.PI * 2); ix.stroke();
        ix.beginPath(); ix.moveTo(S.x, S.y - 12.5); ix.lineTo(S.x + 13.5, S.y + 10); ix.lineTo(S.x - 13.5, S.y + 10); ix.closePath(); ix.fill();
        ix.globalCompositeOperation = 'destination-out'; ix.fillRect(S.x - 1.5, S.y - 4.5, 3, 8.6); ix.fillRect(S.x - 1.5, S.y + 5.6, 3, 2.7); ix.globalCompositeOperation = 'source-over';
        ix.lineWidth = 0.8; ix.beginPath(); ix.moveTo(CW - 79.5, 11); ix.lineTo(CW - 79.5, CH - 11); ix.stroke();
        ix.font = `800 26px ${SANS}`; spaced(ix, 'BETA', 83, 38, 3.4);
        ix.font = `700 6.9px ${MONO}`; spaced(ix, 'PRE-RELEASE SOFTWARE', 84, 51, 0.95); spaced(ix, 'EXPECT ROUGH EDGES', 84, 61, 0.95);
        ix.font = `500 6.2px ${MONO}`; spaced(ix, 'CW 0.4.1', 84, 74, 0.8); spaced(ix, 'No. 0412', 12, 74, 0.8);
        ink = alpha(ic);
        // microtext, part of the hologram: round the seal, and in rows behind the print
        const [mc, mx] = layer(); mx.textAlign = 'center'; mx.textBaseline = 'middle'; mx.font = `600 3.7px ${MONO}`;
        const ring = [...'BETA · PRE-RELEASE · CODEWIRE · BETA · PRE-RELEASE · CODEWIRE · '], rr2 = S.r - 4.3;
        ring.forEach((ch, k) => { const a = -Math.PI / 2 + (k / ring.length) * Math.PI * 2; mx.save(); mx.translate(S.x + Math.cos(a) * rr2, S.y + Math.sin(a) * rr2); mx.rotate(a + Math.PI / 2); mx.fillText(ch, 0, 0); mx.restore(); });
        mx.textAlign = 'left'; mx.font = `500 3.1px ${MONO}`; for (let k = 0, y = 7.5; y < CH - 4; y += 4.1, k++) mx.fillText('CODEWIRE BETA · '.repeat(14), 4 - (k % 2) * 9, y);
        mx.clearRect(CW - 80, 0, 80, CH);
        micro = alpha(mc);
        // wear on the laminate: hairline scratches and a little dust, seen only where the light glances off
        const [wc, wx] = layer(); let seed = 7; const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
        for (let k = 0; k < 46; k++) { const x0 = rnd() * CW, y0 = rnd() * CH, a = -0.5 + rnd() * 0.9 + (rnd() < 0.3 ? 1.6 : 0), l = 4 + rnd() * 26; wx.globalAlpha = 0.25 + rnd() * 0.55; wx.lineWidth = 0.3 + rnd() * 0.35; wx.beginPath(); wx.moveTo(x0, y0); wx.quadraticCurveTo(x0 + Math.cos(a) * l * 0.5 + rnd() * 2, y0 + Math.sin(a) * l * 0.5 + rnd() * 2, x0 + Math.cos(a) * l, y0 + Math.sin(a) * l); wx.stroke(); }
        for (let k = 0; k < 30; k++) { wx.globalAlpha = 0.4 + rnd() * 0.6; wx.beginPath(); wx.arc(rnd() * CW, rnd() * CH, 0.25 + rnd() * 0.55, 0, Math.PI * 2); wx.fill(); }
        scr = alpha(wc);
      };
      const buildField = () => {
        // (CPU path) the grating vector at each pixel (across the lines), the ridge texture, and the glitter flecks
        gx = new Float32Array(NL); gy = new Float32Array(NL); zone = new Uint8Array(NL); ridge = new Float32Array(NL); fleck = new Uint8Array(NL); fx = new Float32Array(NL); fy = new Float32Array(NL);
        for (let y = 0; y < HL; y++) for (let x = 0; x < WL; x++) {
          const i = y * WL + x, X = x / dpr, Y = y / dpr, dx = X - S.x, dy = Y - S.y, r = Math.hypot(dx, dy);
          let a;
          if (r < S.r) { zone[i] = 1; a = Math.atan2(dy, dx); ridge[i] = Math.cos(r * 4.4); }
          else {
            const q1 = (X + Y) / 12, q2 = (X - Y) / 12, f1 = q1 - Math.round(q1), f2 = q2 - Math.round(q2);
            if (f1 * f1 + f2 * f2 < 0.024) { zone[i] = 2; a = Math.PI / 2 + 0.25; } else { zone[i] = 0; a = 0.12 * Math.sin(Y * 0.09 + X * 0.012); }
            ridge[i] = Math.cos((X * Math.cos(a) + Y * Math.sin(a)) * 3.9);
          }
          gx[i] = Math.cos(a); gy[i] = Math.sin(a);
          if (Math.random() < 0.01 && r > S.r) { fleck[i] = 1; const b = Math.random() * Math.PI * 2; fx[i] = Math.cos(b); fy[i] = Math.sin(b); }
        }
      };
      // each screen column: where it lands on the label, and how far the label has turned there (the bend over the edge)
      const UX = new Float32Array(WS), TC = new Float32Array(WS), TSN = new Float32Array(WS);
      // on the flat part each canvas pixel is exactly one label pixel (whole-pixel offsets), so print and edges stay crisp; only the bend resamples
      const XO = Math.round((R - U0) * dpr), YO = Math.round(OY * dpr), XB = Math.round(R * dpr);
      for (let x = 0; x < WS; x++) { if (x >= XB) { UX[x] = x - XO; TC[x] = 1; TSN[x] = 0; } else { const th = Math.asin(Math.min(0.999, (R - (x + 0.5) / dpr) / R)); UX[x] = (U0 - R * th) * dpr; TC[x] = Math.cos(th); TSN[x] = -Math.sin(th); } }
      const bil = (A, u, v) => { const x0 = Math.floor(u), y0 = Math.floor(v); if (x0 < 0 || y0 < 0 || x0 >= WL - 1 || y0 >= HL - 1) return 0; const fu = u - x0, fv = v - y0, i = y0 * WL + x0; return (A[i] * (1 - fu) + A[i + 1] * fu) * (1 - fv) + (A[i + WL] * (1 - fu) + A[i + WL + 1] * fu) * fv; };
      // colour tables: the metal, from shadow to highlight, and the rainbow
      const GOLD = [[0, 34, 36, 40], [0.32, 104, 107, 113], [0.55, 164, 168, 174], [0.78, 212, 215, 220], [1, 244, 246, 249], [1.3, 255, 255, 255]];   // silver: cool greys, mirror bright
      const gold = (t, o) => { let k = 1; while (k < GOLD.length - 1 && t > GOLD[k][0]) k++; const A = GOLD[k - 1], B = GOLD[k], f = Math.max(0, Math.min(1, (t - A[0]) / (B[0] - A[0]))); for (let c = 0; c < 3; c++) o[c] = A[c + 1] + (B[c + 1] - A[c + 1]) * f; };
      const HUE = new Float32Array(256 * 3); for (let k = 0; k < 256; k++) { const h = k / 256 * 6; HUE[k * 3] = Math.min(1, Math.max(0, Math.abs(h - 3) - 1)); HUE[k * 3 + 1] = Math.min(1, Math.max(0, 2 - Math.abs(h - 2))); HUE[k * 3 + 2] = Math.min(1, Math.max(0, 2 - Math.abs(h - 4))); }
      const ss = (a, b, x) => { const t = Math.max(0, Math.min(1, (x - a) / (b - a))); return t * t * (3 - 2 * t); };
      // L: the light, in the canvas's own pixels. The viewer sits above the middle of the label.
      const L = { x: CS / 2, y: -160, tx: CS / 2, ty: -160 }, G3 = [0, 0, 0], ZL = 140, VX = CS / 2, VY = HS / 2, ZV = 420, E = 1.1 * dpr;
      const shade = () => {
        const lx = L.x, ly = L.y;
        for (let y = 0; y < HSP; y++) {
          const Ys = (y + 0.5) / dpr;
          for (let x = 0; x < WS; x++) {
            const o = (y * WS + x) * 4;
            // where this pixel lands on the label
            const lu = UX[x], lv = y - YO;
            const a = bil(shape, lu, lv);
            if (a <= 0.002) { px[o + 3] = 0; continue; }
            const iu = Math.min(WL - 1, Math.max(0, Math.round(lu))), iv = Math.min(HL - 1, Math.max(0, Math.round(lv))), i = iv * WL + iu;
            const tc = TC[x], tsn = TSN[x], Xs = (x + 0.5) / dpr;
            // light and view, turned into the label's local frame where it bends over the edge
            const vx = lx - Xs, vy = ly - Ys, dl = Math.sqrt(vx * vx + vy * vy + ZL * ZL), wx = VX - Xs, wy = VY - Ys, dvv = Math.sqrt(wx * wx + wy * wy + ZV * ZV);
            const hx = (vx * tc - ZL * tsn) / dl + (wx * tc - ZV * tsn) / dvv, hy = vy / dl + wy / dvv, h2 = hx * hx + hy * hy;
            const spec = Math.exp(-h2 / 0.02), broad = Math.exp(-h2 / 0.4), fall = 0.12 + 0.88 * tc * Math.sqrt(tc);
            gold((0.4 + 0.12 * (1 - iv / HL) + 0.3 * broad + 0.05 * Math.sin(Xs * 0.021 + lx * 0.006)) * fall + spec * 0.75 + ridge[i] * 0.012, G3);
            // first-order diffraction: the part of h along the grating picks the wavelength, the part across it must be small
            let cx = gx[i], cy = gy[i]; const m = micro[i]; if (m > 0) { const c = Math.cos(0.4 * m), sn = Math.sin(0.4 * m), t = cx; cx = cx * c - cy * sn; cy = cy * c + t * sn; }
            const al = Math.abs(hx * cx + hy * cy), pe = -hx * cy + hy * cx;
            const k = ss(0.12, 0.24, al) * (1 - ss(0.88, 1.05, al)) * Math.exp(-pe * pe / 0.09) * (zone[i] === 2 ? 0.6 : 0.82) * (0.4 + 0.6 * tc);
            let r = G3[0], gg = G3[1], b = G3[2];
            if (k > 0.004) {
              const hi = ((0.8 * (1 - Math.min(1, Math.max(0, (al - 0.15) / 0.8)))) * 255) | 0, lum = 0.88 + 0.12 * ridge[i];
              r = r * (1 - k) + (HUE[hi * 3] * 235 * lum + G3[0] * 0.25) * k; gg = gg * (1 - k) + (HUE[hi * 3 + 1] * 235 * lum + G3[1] * 0.25) * k; b = b * (1 - k) + (HUE[hi * 3 + 2] * 245 * lum + G3[2] * 0.25) * k;
            }
            if (fleck[i]) { const hl = Math.sqrt(h2) + 1e-6, f = Math.pow(Math.max(0, (hx * fx[i] + hy * fy[i]) / hl), 30) * ss(0.1, 0.4, hl); r += 230 * f; gg += 230 * f; b += 235 * f; }
            // black ink on top
            const n = bil(ink, lu, lv); if (n > 0) { r = r * (1 - n) + 16 * n; gg = gg * (1 - n) + 16 * n; b = b * (1 - n) + 18 * n; }
            // the clear laminate: a glare where the light mirrors back, and the scratches and dust that only show in it
            // where the label rolls over the edge it picks up a thin bright line, then turns dark as it faces away
            const roll = tsn !== 0 ? Math.exp(-Math.pow((Math.abs(tsn) - 0.42) / 0.16, 2)) * 70 * (0.5 + 0.5 * broad) : 0;
            const glare = spec * 30 + (spec * 150 + broad * 10) * scr[i] + roll;
            r += glare; gg += glare; b += glare;
            // the cut edge: the film's thickness catches light along the top, shades along the bottom
            const up = bil(shape, lu, lv - E), dn = bil(shape, lu, lv + E), rt = bil(shape, lu + E, lv), eT = Math.max(0, a - up), eB = Math.max(0, a - dn), eR = Math.max(0, a - rt);
            const lift = eT * 120, sh = 1 - eB * 0.45 - eR * 0.25; r = (r + lift) * sh; gg = (gg + lift) * sh; b = (b + lift) * sh;
            px[o] = r; px[o + 1] = gg; px[o + 2] = b; px[o + 3] = a * 255;
          }
        }
        g.putImageData(img, 0, 0);
      };
      // ---- the shader ----
      const FS = `precision highp float;
uniform vec2 uRes, uMaskPx, uLab;
uniform float uDpr, uT;
uniform vec4 uGeo;            // flat offset x, y (device px), bend radius, label x at the fold (units)
uniform vec2 uTilt;           // how far the label is turned, left/right and up/down, -1..1
uniform vec3 uPtr;            // the pointer as a torch over the label: x, y (canvas units), strength 0..1
uniform float uAct;           // how awake the hologram is: quiet at rest, full while handled
uniform sampler2D uMask;      // r shape, g print, b microtext, a laminate wear
float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }
float noise(vec2 p) { vec2 i = floor(p), f = fract(p); f = f * f * (3.0 - 2.0 * f); return mix(mix(hash(i), hash(i + vec2(1.0, 0.0)), f.x), mix(hash(i + vec2(0.0, 1.0)), hash(i + vec2(1.0, 1.0)), f.x), f.y); }
vec3 bump3(vec3 x, vec3 y0) { return clamp(1.0 - x * x - y0, 0.0, 1.0); }
// a wavelength in nm as rgb (Zucconi's six-bump fit of the visible spectrum)
vec3 spectrum(float w) {
  float x = clamp((w - 400.0) / 300.0, 0.0, 1.0);
  return bump3(vec3(3.54585104, 2.93225262, 2.41593945) * (x - vec3(0.69549072, 0.49228336, 0.27699880)), vec3(0.02312639, 0.15225084, 0.52607955))
       + bump3(vec3(3.90307140, 3.21182957, 3.96587128) * (x - vec3(0.11748627, 0.86755042, 0.66077860)), vec3(0.84897130, 0.88445281, 0.73949448));
}
// the grating equation: light l reaches the eye v in order m at wavelength d * (l + v) . g / m, if the part across g is near zero
vec3 grating(vec3 l, vec3 v, vec2 g, float d, float spread) {
  vec2 s = l.xy + v.xy;
  float u = abs(dot(s, g)), w = dot(s, vec2(-g.y, g.x));
  vec3 c = vec3(0.0);
  for (int m = 1; m <= 3; m++) {
    float lam = d * u * 1000.0 / float(m);
    c += spectrum(lam) * smoothstep(380.0, 430.0, lam) * (1.0 - smoothstep(660.0, 720.0, lam)) / float(m);
  }
  return c * exp(-w * w / spread);
}
// the room the foil reflects: dim walls brighter toward the ceiling, a softbox up right, a strip light left, a high window, a band of light at eye level
float envf(vec3 r) {
  float e = 0.36 + 0.2 * smoothstep(-0.4, 0.7, -r.y) + 0.06 * sin(r.x * 4.0 + r.y * 2.0);
  e += 0.95 * smoothstep(0.24, 0.1, abs(r.x - 0.3)) * smoothstep(0.24, 0.1, abs(-r.y - 0.36));
  e += 0.8 * smoothstep(0.07, 0.02, abs(r.x + 0.38 + 0.15 * r.y)) * smoothstep(0.8, 0.5, abs(r.y));
  e += 0.4 * smoothstep(0.34, 0.08, length(vec2(r.x + 0.1, -r.y - 0.62)));
  e += 0.32 * smoothstep(0.1, 0.0, abs(r.y + 0.08 - 0.12 * r.x));
  return e;
}
// a thin clear film over the foil: its reflection at three wavelengths, for its thickness t (nm) and the light's angle
vec3 thinFilm(float cosI, float t) {
  float ct = sqrt(max(0.0, 1.0 - (1.0 - cosI * cosI) / 1.9));
  return 0.5 + 0.5 * cos(6.2831853 * 2.0 * 1.38 * t * ct / vec3(650.0, 532.0, 450.0) + 3.14159);
}
void main() {
  vec2 fc = vec2(gl_FragCoord.x, uRes.y - gl_FragCoord.y);
  float xs = fc.x / uDpr, ys = fc.y / uDpr, th = 0.0, ud;
  if (xs < uGeo.z) { th = asin(min(0.999, (uGeo.z - xs) / uGeo.z)); ud = (uGeo.w - uGeo.z * th) * uDpr; } else ud = fc.x - uGeo.x;
  vec2 tuv = vec2(ud, fc.y - uGeo.y) / uMaskPx;
  vec4 M = texture2D(uMask, tuv);
  float a = M.r;
  if (a < 0.003) { gl_FragColor = vec4(0.0); return; }
  vec2 lp = vec2(ud, fc.y - uGeo.y) / uDpr;
  // the frame turns with the bend, then the whole label tilts toward the pointer, the way a sticker turns in the hand
  float st = sin(th), ct = cos(th);
  vec3 n = vec3(-st, 0.0, ct), tx = vec3(ct, 0.0, st), ty = vec3(0.0, 1.0, 0.0);
  float ax = uTilt.x * 0.5, ay = -uTilt.y * 0.4;
  mat3 Rt = mat3(cos(ax), 0.0, -sin(ax), 0.0, 1.0, 0.0, sin(ax), 0.0, cos(ax)) * mat3(1.0, 0.0, 0.0, 0.0, cos(ay), sin(ay), 0.0, -sin(ay), cos(ay));
  n = Rt * n; tx = Rt * tx; ty = Rt * ty;
  // foil is never flat: long soft undulations, and a fine crinkle pressed into the film
  vec2 q1 = lp * 0.035;
  vec2 wob = 0.05 * vec2(noise(q1) - noise(q1 + vec2(3.7, 0.0)), noise(q1 + vec2(0.0, 5.1)) - noise(q1 + vec2(2.3, 1.9)))
           + 0.014 * vec2(sin(dot(lp, vec2(0.37, 0.21)) + 1.3 * sin(dot(lp, vec2(-0.13, 0.41)))), cos(dot(lp, vec2(0.19, -0.33)) + 1.1 * sin(dot(lp, vec2(0.29, 0.17)))))
           + 0.008 * vec2(sin(dot(lp, vec2(0.83, -0.52)) + sin(dot(lp, vec2(0.31, 0.77)))), sin(dot(lp, vec2(-0.61, 0.69)) + sin(dot(lp, vec2(0.71, 0.23)))));
  vec3 nb = normalize(n + tx * wob.x + ty * wob.y);
  vec3 P = vec3(xs, ys, -uGeo.z * (1.0 - ct));
  // a studio: a key light up to the right, a window up to the left; the viewer close enough that the reflection sweeps across the label
  vec3 l1 = normalize(vec3(0.42, -0.55, 0.72)), l2 = normalize(vec3(-0.6, -0.48, 0.64)), v = normalize(vec3(uRes / uDpr * 0.5, 380.0) - P);
  vec3 L1 = vec3(dot(l1, tx), dot(l1, ty), dot(l1, n)), L2 = vec3(dot(l2, tx), dot(l2, ty), dot(l2, n)), V = vec3(dot(v, tx), dot(v, ty), dot(v, n));
  // the gratings: radial rings in the seal (two periods), a dot lattice at right angles, a slow sweep across the field
  vec2 dc = lp - vec2(uLab.x - 40.0, 42.0); float r = length(dc), dots = 0.0, d; vec2 g;
  if (r < 29.0) { g = dc / max(r, 0.001); d = r < 20.4 ? 1.08 : 0.86; }
  else {
    vec2 q = vec2(lp.x + lp.y, lp.x - lp.y) / 12.0, f = q - floor(q + 0.5);
    if (dot(f, f) < 0.024) { g = vec2(cos(1.82), sin(1.82)); d = 0.74; dots = 1.0; }
    else { float an = 0.12 * sin(lp.y * 0.09 + lp.x * 0.012); g = vec2(cos(an), sin(an)); d = 0.88 + 0.22 * (noise(lp * 0.03 + 7.0) - 0.5); }
  }
  float ma = 0.45 * M.b; g = vec2(g.x * cos(ma) - g.y * sin(ma), g.x * sin(ma) + g.y * cos(ma));
  // the pointer is a torch held over the label: a soft glare on the film, its own glints and its own rainbow
  vec3 lP = normalize(vec3(uPtr.xy, 120.0) - P), hP = normalize(lP + v), LP = vec3(dot(lP, tx), dot(lP, ty), dot(lP, n));
  // the hologram wakes as it is handled: quiet at rest, full under the torch
  vec3 dif = ((grating(L1, V, g, d, 0.075) + grating(L2, V, g, d, 0.075) * 0.6) * (0.35 + 0.65 * uAct) + grating(LP, V, g, d, 0.075) * 0.9 * uPtr.z) * (1.0 - 0.35 * dots);
  // the foil is metal flake under the film, between satin and mirror: each tiny flake leans a little its own way,
  // so the reflection breaks into a fine grain that glints as the label turns
  vec2 fcell = floor(lp / 1.1); float fr = hash(fcell + 0.7);
  vec3 nf = normalize(nb + (tx * (hash(fcell) - 0.5) + ty * (hash(fcell + 4.1) - 0.5)) * 0.24);
  vec3 rv = reflect(-v, nb);
  float env = envf(rv) * 0.5 + envf(reflect(-v, nf)) * 0.5;
  vec3 h1 = normalize(l1 + v), h2 = normalize(l2 + v);
  float nh1 = max(dot(nb, h1), 0.0), nh2 = max(dot(nb, h2), 0.0), nhP = max(dot(nb, hP), 0.0);
  float spark = (pow(max(dot(nf, h1), 0.0), 420.0) * 0.9 + pow(max(dot(nf, h2), 0.0), 360.0) * 0.5 + pow(max(dot(nf, hP), 0.0), 300.0) * 1.1 * uPtr.z) * (0.2 + 1.1 * fr * fr * fr);
  vec3 foil = vec3(0.94, 0.95, 0.97) * (env + pow(nh1, 160.0) * 0.9 + pow(nh2, 140.0) * 0.45 + spark);
  foil *= mix(vec3(1.0), thinFilm(max(dot(nb, v), 0.05), 360.0 + 180.0 * noise(lp * 0.02 + 3.0)) * 1.15, 0.05);
  vec3 col = foil * (1.0 - 0.3 * clamp(dot(dif, vec3(0.333)), 0.0, 1.0)) + dif * 0.85;
  // glitter: a few larger tilted mirrors that flash as the label turns or the torch passes
  vec2 cell = floor(lp * 1.4);
  if (r > 29.0 && hash(cell) < 0.014) {
    vec3 ng = normalize(Rt * vec3((hash(cell + 3.1) - 0.5) * 0.9, (hash(cell + 7.7) - 0.5) * 0.9, 1.0));
    float flash = pow(max(dot(ng, h1), 0.0), 900.0) * 2.4 + pow(max(dot(ng, h2), 0.0), 900.0) * 1.1 + pow(max(dot(ng, hP), 0.0), 700.0) * 2.0 * uPtr.z;
    col += smoothstep(0.45, 0.2, length(fract(lp * 1.4) - 0.5)) * flash * mix(vec3(1.0), spectrum(420.0 + 260.0 * hash(cell + 1.3)), 0.5);
  }
  // black print
  col = mix(col, vec3(0.05, 0.05, 0.056) + 0.04 * env, M.g);
  // the clear laminate over everything: its glare, and the scratches and dust that only show in it
  col += pow(nh1, 700.0) * 0.8 + pow(nh2, 500.0) * 0.3 + (pow(nhP, 40.0) * 0.2 + pow(nhP, 420.0) * 0.5) * uPtr.z
       + M.a * (pow(nh1, 45.0) * 0.9 + pow(nh2, 40.0) * 0.3 + pow(nhP, 30.0) * 0.8 * uPtr.z + 0.015);
  // rolling over the edge: a thin bright line, then dark as it faces away
  col = col * mix(0.22, 1.0, pow(ct, 1.3)) + exp(-pow((st - 0.42) / 0.16, 2.0)) * 0.22 * step(0.001, st);
  // the cut edge: the film's thickness lit along the top, shaded along the bottom and the right
  vec2 px1 = 1.15 / uMaskPx;
  float eT = max(0.0, a - texture2D(uMask, tuv - vec2(0.0, px1.y)).r), eB = max(0.0, a - texture2D(uMask, tuv + vec2(0.0, px1.y)).r), eR = max(0.0, a - texture2D(uMask, tuv + vec2(px1.x, 0.0)).r);
  col = (col + eT * 0.45) * (1.0 - eB * 0.45 - eR * 0.25);
  col = col / (1.0 + 0.3 * col) * 1.18;
  gl_FragColor = vec4(clamp(col, 0.0, 1.0) * a, a);
}`;
      const glSetup = () => {
        const c = cv.getContext('webgl', { premultipliedAlpha: true, antialias: false, alpha: true });
        if (!c) return Promise.resolve(null);
        const sh = (type, src) => { const s = c.createShader(type); c.shaderSource(s, src); c.compileShader(s); return s; };
        const vs = sh(c.VERTEX_SHADER, 'attribute vec2 p; void main(){ gl_Position = vec4(p, 0.0, 1.0); }'), fs = sh(c.FRAGMENT_SHADER, FS);
        const pr = c.createProgram(); c.attachShader(pr, vs); c.attachShader(pr, fs); c.linkProgram(pr);
        return linked(c, pr).then((ok) => {
          if (!ok) { [vs, fs].forEach((s) => c.getShaderParameter(s, c.COMPILE_STATUS) || console.warn(c.getShaderInfoLog(s))); return null; }
          c.useProgram(pr);
          const b = c.createBuffer(); c.bindBuffer(c.ARRAY_BUFFER, b); c.bufferData(c.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), c.STATIC_DRAW);
          const loc = c.getAttribLocation(pr, 'p'); c.enableVertexAttribArray(loc); c.vertexAttribPointer(loc, 2, c.FLOAT, false, 0, 0);
          const tex = c.createTexture(); c.activeTexture(c.TEXTURE0); c.bindTexture(c.TEXTURE_2D, tex);
          [c.TEXTURE_WRAP_S, c.TEXTURE_WRAP_T].forEach((k) => c.texParameteri(c.TEXTURE_2D, k, c.CLAMP_TO_EDGE));
          c.texParameteri(c.TEXTURE_2D, c.TEXTURE_MIN_FILTER, c.LINEAR); c.texParameteri(c.TEXTURE_2D, c.TEXTURE_MAG_FILTER, c.LINEAR);
          const U = {}; ['uRes', 'uMaskPx', 'uLab', 'uDpr', 'uT', 'uGeo', 'uTilt', 'uPtr', 'uAct', 'uMask'].forEach((k) => (U[k] = c.getUniformLocation(pr, k)));
          c.uniform1i(U.uMask, 0); c.viewport(0, 0, WS, HSP);
          c.uniform2f(U.uRes, WS, HSP); c.uniform2f(U.uMaskPx, WL, HL); c.uniform2f(U.uLab, CW, CH); c.uniform1f(U.uDpr, dpr);
          c.uniform4f(U.uGeo, XO, YO, R, U0);
          return { c, U };
        });
      };
      const upload = () => {
        const d = new Uint8Array(NL * 4); for (let i = 0; i < NL; i++) { d[i * 4] = shape[i] * 255; d[i * 4 + 1] = ink[i] * 255; d[i * 4 + 2] = micro[i] * 255; d[i * 4 + 3] = scr[i] * 255; }
        gl.c.pixelStorei(gl.c.UNPACK_PREMULTIPLY_ALPHA_WEBGL, false); gl.c.texImage2D(gl.c.TEXTURE_2D, 0, gl.c.RGBA, WL, HL, 0, gl.c.RGBA, gl.c.UNSIGNED_BYTE, d);
      };
      const drawGL = (t) => {
        const { c, U } = gl, prox = pX == null ? 0 : Math.exp(-((G.x - CS / 2) ** 2 + (G.y - HS / 2) ** 2) / (2 * 300 * 300));
        c.uniform1f(U.uT, t); c.uniform2f(U.uTilt, T.x, T.y); c.uniform3f(U.uPtr, G.x, G.y, prox); c.uniform1f(U.uAct, Math.min(1, Math.max(act, prox * 0.5))); c.clearColor(0, 0, 0, 0); c.clear(c.COLOR_BUFFER_BIT); c.drawArrays(c.TRIANGLES, 0, 3); };
      const cpu = () => { const c2 = cv.cloneNode(); cv.replaceWith(c2); cv = c2; g = cv.getContext('2d'); img = g.createImageData(WS, HSP); px = img.data; };
      // T: the label's tilt (sprung), G: the torch (the pointer, in canvas units), act: how awake the hologram is, show: the one showcase pass
      let vis = false, raf = 0, pX = null, pY = null, act = 0, lastT = 0, show = -1, gyro = null; const T = { x: 0.2, y: -0.2, tx: 0.2, ty: -0.2, vx: 0, vy: 0 }, G = { x: CS * 0.7, y: -160 };
      const cl1 = (q) => Math.max(-1, Math.min(1, q));
      const target = () => {
        const r = cv.getBoundingClientRect(), k = r.width / CS, sy = Math.sin(scrollY / 260), cy = Math.cos(scrollY / 380);
        if (pX == null) { L.tx = CS / 2 - 420 * Math.abs(sy) + 120; L.ty = HS / 2 - 160 + 120 * cy; if (gyro) { T.tx = gyro[0]; T.ty = gyro[1]; } else { T.tx = 0.55 * sy; T.ty = -0.2 + 0.4 * cy; } }
        else { L.tx = (pX - r.left) / k + 60 * sy; L.ty = (pY - r.top) / k; const cl = (q) => Math.max(-1, Math.min(1, q)); T.tx = cl((pX - r.left - r.width / 2) / (innerWidth * 0.5)) + 0.15 * sy; T.ty = cl((pY - r.top - r.height / 2) / (innerHeight * 0.5)); }
      };
      const tick = (now) => {
        raf = 0;
        if (gl) {
          const t = now / 1000, dt = Math.min(0.05, lastT ? Math.max(0, t - lastT) : 0.016); lastT = t;
          // one showcase pass the first time the label comes into view: it turns through the light, then settles
          let tx = T.tx, ty = T.ty;
          if (show >= 0) { const u = (t - show) / 2.4; if (u < 1) { const e = u * u * (3 - 2 * u); tx = -0.75 + 1.5 * e; ty = -0.3 + 0.5 * Math.sin(Math.PI * u); act = Math.max(act, 0.9 * Math.sin(Math.PI * u)); } else show = -2; }
          // the tilt on a spring, as a held thing: it lags a touch behind the hand, then settles
          const k = 70, cd = 2 * 0.62 * Math.sqrt(k);
          T.vx += ((tx - T.x) * k - T.vx * cd) * dt; T.vy += ((ty - T.y) * k - T.vy * cd) * dt; T.x += T.vx * dt; T.y += T.vy * dt;
          G.x += (L.tx - G.x) * Math.min(1, dt * 14); G.y += (L.ty - G.y) * Math.min(1, dt * 14);
          act *= Math.exp(-dt * 0.9);
          drawGL(t); if (vis) raf = requestAnimationFrame(tick);
        } else { L.x += (L.tx - L.x) * 0.2; L.y += (L.ty - L.y) * 0.2; shade(); if (Math.abs(L.tx - L.x) + Math.abs(L.ty - L.y) > 0.5) raf = requestAnimationFrame(tick); }
      };
      const go = () => { if (reduce || !vis || !shape) return; target(); if (!raf) raf = requestAnimationFrame(tick); };
      const first = () => { build(); target(); L.x = L.tx; L.y = L.ty; T.x = T.tx; T.y = T.ty; if (gl) { upload(); drawGL(0); } else { buildField(); shade(); } };
      // built once, after the fonts, when the label nears the screen or the page first goes idle: built during load it held the page and the wire's first frames for most of a second
      let started = false;
      const start = () => {
        if (started) return; started = true;
        Promise.all([glSetup(), document.fonts && document.fonts.ready]).then(([c]) => {
          gl = c; if (!gl) cpu();
          first();
          new IntersectionObserver((es) => es.forEach((en) => { vis = en.isIntersecting; if (vis && show === -1 && gl && !reduce) show = performance.now() / 1000; go(); })).observe(cv);
        });
      };
      new IntersectionObserver((es, io) => { if (es.some((en) => en.isIntersecting)) { io.disconnect(); start(); } }, { rootMargin: '100% 0px' }).observe(cv);
      addEventListener('load', () => (window.requestIdleCallback ? requestIdleCallback(start, { timeout: 2000 }) : setTimeout(start, 500)), { once: true });
      addEventListener('pointermove', (e) => {
        if (e.pointerType === 'touch') return;
        // moving near the label wakes the hologram, more the closer and quicker
        const r = cv.getBoundingClientRect(), dd = Math.hypot(e.clientX - (r.left + r.width / 2), e.clientY - (r.top + r.height / 2)), moved = pX == null ? 0 : Math.hypot(e.clientX - pX, e.clientY - pY);
        act = Math.min(1, act + Math.exp(-(dd * dd) / (2 * 240 * 240)) * Math.min(moved, 30) / 30 * 0.3);
        pX = e.clientX; pY = e.clientY; go();
      }, { passive: true });
      // phones: tilting the phone tilts the label, where the browser gives orientation without asking
      addEventListener('deviceorientation', (e) => { if (pX != null || e.gamma == null || e.beta == null) return; gyro = [cl1(e.gamma / 30), cl1((e.beta - 40) / 30)]; act = Math.min(1, act + 0.05); go(); }, { passive: true });
      addEventListener('scroll', go, { passive: true });
    }
  }
  $$('.cw-site-copy').forEach((b) => b.addEventListener('click', async () => {
    const code = b.previousElementSibling, txt = code.textContent;
    let ok = true;
    try { await navigator.clipboard.writeText(txt); }
    catch (e) { ok = false; const r = document.createRange(); r.selectNodeContents(code); const s = getSelection(); s.removeAllRanges(); s.addRange(r); say('Selected, press copy'); }
    if (ok) { b.classList.add('done'); b.setAttribute('aria-label', 'Copied'); clearTimeout(b.t); b.t = setTimeout(() => { b.classList.remove('done'); b.setAttribute('aria-label', 'Copy install command'); }, 1600); }
  }));

  /* ---------- fig 3.1: a geodesic sphere of crimped strands; sessions clip onto nodes, you sit at the centre ---------- */
  const COL = { ink: '#0C0D0D', paper: '#ECEDEA', signal: '#FF4A12', grey: '#73787A' };
  const hexRgb = (h) => { const n = parseInt(h.slice(1, 7), 16); return [n >> 16 & 255, n >> 8 & 255, n & 255]; };
  const mixHex = (a, b, t) => { const A = hexRgb(a), B = hexRgb(b); return 'rgb(' + A.map((v, k) => Math.round(v + (B[k] - v) * t)).join(',') + ')'; };
  const setCol = (c) => { COL.ink = c.ink; COL.paper = c.paper.slice(0, 7); COL.signal = c.signal; COL.grey = mixHex(c.ink, c.paper, 0.48); };
  onLook.push(setCol); setCol(palette());
  const net = (() => {
    // icosahedron, each face split in four, pushed out to the sphere: 42 nodes, 120 links
    const ph = (1 + Math.sqrt(5)) / 2, V = [[-1, ph, 0], [1, ph, 0], [-1, -ph, 0], [1, -ph, 0], [0, -1, ph], [0, 1, ph], [0, -1, -ph], [0, 1, -ph], [ph, 0, -1], [ph, 0, 1], [-ph, 0, -1], [-ph, 0, 1]];
    let F = [[0, 11, 5], [0, 5, 1], [0, 1, 7], [0, 7, 10], [0, 10, 11], [1, 5, 9], [5, 11, 4], [11, 10, 2], [10, 7, 6], [7, 1, 8], [3, 9, 4], [3, 4, 2], [3, 2, 6], [3, 6, 8], [3, 8, 9], [4, 9, 5], [2, 4, 11], [6, 2, 10], [8, 6, 7], [9, 8, 1]];
    const nrm = (v) => { const l = Math.hypot(...v); return v.map((x) => x / l); };
    const verts = V.map(nrm), mid = {};
    const midpt = (a, b) => { const k = a < b ? a + '_' + b : b + '_' + a; if (mid[k] == null) { mid[k] = verts.length; verts.push(nrm(verts[a].map((x, i) => (x + verts[b][i]) / 2))); } return mid[k]; };
    const F2 = []; F.forEach(([a, b, c]) => { const ab = midpt(a, b), bc = midpt(b, c), ca = midpt(c, a); F2.push([a, ab, ca], [b, bc, ab], [c, ca, bc], [ab, bc, ca]); });
    const eset = new Set(), edges = [], adj = verts.map(() => []);
    F2.forEach((f) => [[f[0], f[1]], [f[1], f[2]], [f[2], f[0]]].forEach(([a, b]) => { const k = a < b ? a + '_' + b : b + '_' + a; if (!eset.has(k)) { eset.add(k); edges.push([a, b]); adj[a].push(b); adj[b].push(a); } }));
    // eight sessions, spread out over the sphere
    const NAMES = ['auth', 'api', 'billing', 'docs', 'web', 'infra', 'queue', 'search'];
    const pick = [0]; while (pick.length < NAMES.length) { let best = -1, bd = -1; verts.forEach((v, i) => { if (pick.includes(i)) return; const md = Math.min(...pick.map((q) => 1 - (v[0] * verts[q][0] + v[1] * verts[q][1] + v[2] * verts[q][2]))); if (md > bd) { bd = md; best = i; } }); pick.push(best); }
    const node = {}; NAMES.forEach((n, i) => (node[n] = pick[i]));
    const path = (a, b) => { const prev = new Array(verts.length).fill(-1), q = [a], seen = new Set([a]); while (q.length) { const v = q.shift(); if (v === b) break; adj[v].forEach((w) => { if (!seen.has(w)) { seen.add(w); prev[w] = v; q.push(w); } }); } const out = [b]; while (out[0] !== a) out.unshift(prev[out[0]]); return out; };
    const slerp = (a, b, t) => { const d = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2])), om = Math.acos(d), so = Math.sin(om); if (so < 1e-5) return a.slice(); const ka = Math.sin((1 - t) * om) / so, kb = Math.sin(t * om) / so; return a.map((x, i) => x * ka + b[i] * kb); };
    return { verts, edges, adj, node, path, slerp, NAMES };
  })();

  const MSG_MESH = [
    ['api', 'auth', "cw msg auth --session codex 'token ttl?'"], ['auth', 'api', 'reply · ttl is 15m'],
    ['api', 'billing', "cw msg billing --session claude 'use backoff v2'"], ['billing', 'infra', "cw msg infra --session claude 'raise webhook timeout'"],
    ['infra', 'billing', 'reply · timeout now 30s'], ['web', 'docs', "cw msg docs --session codex 'document retry ui'"],
    ['docs', 'web', 'reply · docs merged'], ['queue', 'search', "cw msg search --session claude 'reindex after retry'"], ['search', 'api', 'reply · index rebuilt'],
  ];
  const MSG_IND = [
    ['you', 'auth', "cw msg auth --session codex 'fix session expiry'"], ['auth', 'you', 'inbox · expiry fixed'],
    ['you', 'docs', "cw msg docs --session codex 'update quickstart'"], ['docs', 'you', 'inbox · quickstart updated'],
    ['you', 'billing', "cw msg billing --session claude 'trace failed invoice'"], ['billing', 'you', 'inbox · root cause found'],
  ];
  const netc = $('#netc'), ng = netc.getContext('2d'), log = $('#log'), lines = [];
  let NW = 0, NH = 0, NDPR = 1;
  const fitNet = () => { const r = netc.getBoundingClientRect(); NDPR = Math.min(devicePixelRatio || 1, 2); NW = r.width; NH = r.height; netc.width = Math.round(NW * NDPR); netc.height = Math.round(NH * NDPR); };
  new ResizeObserver(fitNet).observe(netc); fitNet();
  let netVisible = true; new IntersectionObserver((es) => es.forEach((e) => (netVisible = e.isIntersecting)), { rootMargin: '200px' }).observe(netc);

  // mode: switches by itself; a click takes over for a while
  let mode = 'ind', mval = 0, manualUntil = 0, phaseStart = performance.now(), mi = 0, nextMsg = 0;
  const PHASE = { ind: 8000, mesh: 12000 };
  const setMode = (m, manual) => {
    if (m !== mode) { mode = m; mi = 0; nextMsg = 0; }
    phaseStart = performance.now(); if (manual) manualUntil = performance.now() + 25000;
    $('#mA').setAttribute('aria-pressed', String(m === 'ind')); $('#mB').setAttribute('aria-pressed', String(m === 'mesh'));
    $('#netcap').textContent = m === 'ind' ? 'Fig. 3.1 · Independent. Each sandbox is wired only to you.' : 'Fig. 3.1 · Mesh. Sandboxes reach each other hop by hop over encrypted links.';
  };
  $('#mA').addEventListener('click', () => setMode('ind', true)); $('#mB').addEventListener('click', () => setMode('mesh', true));
  const flights = [], pulses = [];
  const pushLog = (m) => {
    const t = new Date().toTimeString().slice(3, 8);
    lines.push([t, m[0] + ' → ' + m[1], m[2]]); while (lines.length > 6) lines.shift();
    log.innerHTML = lines.map((l, k) => `<li class="${k === lines.length - 1 ? 'now' : ''}"><span>${l[0]}</span><span>${l[1]}</span><span>${l[2].replace(/</g, '&lt;')}</span></li>`).join('');
  };
  const launch = (now) => {
    const list = mode === 'mesh' ? MSG_MESH : MSG_IND, m = list[mi++ % list.length];
    let route;
    if (m[0] === 'you' || m[1] === 'you') route = { spoke: true, v: net.node[m[0] === 'you' ? m[1] : m[0]], out: m[0] === 'you' };
    else route = { spoke: false, path: net.path(net.node[m[0]], net.node[m[1]]) };
    const hops = route.spoke ? 2.2 : route.path.length - 1;
    flights.push({ m, route, t0: now, dur: 450 + hops * 380 });
    pushLog(m);
  };
  for (let k = 0; k < 4; k++) pushLog(MSG_IND[k]);

  const drawNet = (now) => {
    if (!netVisible || !NW) return;
    const t = reduce ? 0 : now / 1000;
    if (!reduce && now > manualUntil && now - phaseStart > PHASE[mode]) setMode(mode === 'ind' ? 'mesh' : 'ind', false);
    const auto = now > manualUntil;
    $('#autoBar').style.width = (auto ? Math.min(1, (now - phaseStart) / PHASE[mode]) * 100 : 100) + '%';
    $('#autoLbl').textContent = auto ? 'Auto' : 'Manual';
    mval += ((mode === 'mesh' ? 1 : 0) - mval) * Math.min(1, reduce ? 1 : 0.06);
    if (!reduce && now > nextMsg) { launch(now); nextMsg = now + (mode === 'mesh' ? 1500 : 1900); }

    const g = ng, W = NW, H = NH, cx = W / 2, cy = H / 2, R = Math.min(W, H) * 0.4;
    g.setTransform(NDPR, 0, 0, NDPR, 0, 0); g.clearRect(0, 0, W, H);
    const yaw = t * 0.12 + 0.6, tilt = 0.32, c1 = Math.cos(yaw), s1 = Math.sin(yaw), c2 = Math.cos(tilt), s2 = Math.sin(tilt);
    const rot = (v) => { const x = v[0] * c1 + v[2] * s1, z0 = -v[0] * s1 + v[2] * c1, y = v[1] * c2 - z0 * s2, z = v[1] * s2 + z0 * c2; return [x, y, z]; };
    const proj = (p) => { const k = R * (1 + 0.14 * p[2]); return [cx + p[0] * k, cy - p[1] * k, p[2]]; };
    const P = net.verts.map((v) => proj(rot(v)));
    const arc = (a, b, n) => { const pts = []; for (let i = 0; i <= n; i++) pts.push(proj(rot(net.slerp(net.verts[a], net.verts[b], i / n)))); return pts; };
    const depthA = (z) => 0.16 + 0.84 * Math.min(1, Math.max(0, (z + 0.55) / 1.1));
    const live = new Map();   // edges carrying a message right now
    flights.forEach((f) => { if (!f.route.spoke) for (let i = 0; i < f.route.path.length - 1; i++) { const a = f.route.path[i], b = f.route.path[i + 1]; live.set(a < b ? a + '_' + b : b + '_' + a, 1); } });

    // links, back to front; in independent mode they recede to a faint guide
    const E = net.edges.map(([a, b]) => ({ a, b, z: (P[a][2] + P[b][2]) / 2 })).sort((x, y) => x.z - y.z);
    const drawEdge = (e, front) => {
      if ((e.z >= 0) !== front) return;
      const pts = arc(e.a, e.b, 8), da = depthA(e.z), key = e.a < e.b ? e.a + '_' + e.b : e.b + '_' + e.a, on = live.has(key);
      const strength = 0.14 + 0.86 * mval;
      g.beginPath(); pts.forEach((p, i) => (i ? g.lineTo(p[0], p[1]) : g.moveTo(p[0], p[1])));
      g.lineCap = 'round'; g.strokeStyle = on ? COL.signal : COL.ink; g.globalAlpha = on ? 0.95 : da * strength;
      g.lineWidth = (on ? 3.2 : 1 + 1.9 * da * (0.4 + 0.6 * mval)); g.stroke();
      if (!on && front && mval > 0.5) { g.setLineDash([2, 3]); g.strokeStyle = COL.paper; g.globalAlpha = da * 0.8 * mval; g.lineWidth = 0.8; g.stroke(); g.setLineDash([]); }
      g.globalAlpha = 1;
    };
    const drawCrimps = (front) => P.forEach((p, i) => {
      if ((p[2] >= 0) !== front || Object.values(net.node).includes(i)) return;
      const da = depthA(p[2]), s = (3 + 3 * da) * (0.5 + 0.5 * mval), n = net.adj[i][0], ang = Math.atan2(P[n][1] - p[1], P[n][0] - p[0]);
      g.save(); g.translate(p[0], p[1]); g.rotate(ang); g.globalAlpha = da * (0.25 + 0.75 * mval); g.fillStyle = COL.ink; g.fillRect(-s * 1.4, -s, s * 2.8, s * 2);
      g.globalAlpha = 1; g.restore();
    });
    // spokes: you to each session, strong when independent
    const spokes = (front) => net.NAMES.forEach((nm) => {
      const v = net.node[nm], p = P[v]; if ((p[2] >= 0) !== front) return;
      const da = depthA(p[2] * 0.5), flying = flights.some((f) => f.route.spoke && f.route.v === v);
      g.beginPath(); g.moveTo(cx, cy); g.lineTo(p[0], p[1]);
      g.strokeStyle = flying ? COL.signal : COL.ink; g.globalAlpha = flying ? 0.95 : da * (0.12 + 0.78 * (1 - mval)); g.lineWidth = flying ? 3 : 1 + 1.6 * (1 - mval);
      g.setLineDash(mval > 0.5 && !flying ? [3, 5] : []); g.stroke(); g.setLineDash([]); g.globalAlpha = 1;
    });
    const chip = (x, y, s, you, label, hot, da) => {
      g.globalAlpha = 0.35 + 0.65 * da;
      g.fillStyle = you ? COL.ink : COL.paper; g.fillRect(x - s / 2, y - s / 2, s, s);
      g.strokeStyle = hot ? COL.signal : COL.ink; g.lineWidth = hot ? 2.4 : 1.4; g.strokeRect(x - s / 2, y - s / 2, s, s);
      const ins = s * 0.42; g.strokeStyle = you ? COL.signal : COL.ink; g.lineWidth = 1; if (you) { g.fillStyle = COL.signal; g.fillRect(x - ins / 2, y - ins / 2, ins, ins); } else g.strokeRect(x - ins / 2, y - ins / 2, ins, ins);
      g.fillStyle = hot ? COL.signal : COL.grey; g.fillRect(x + s / 2 - 6, y + s / 2 - 6, 3.5, 3.5);
      if (da > 0.45) {
        g.font = `500 ${you ? 12 : 11}px ${getComputedStyle(root).getPropertyValue('--f-mono')}`; g.fillStyle = COL.ink; g.textBaseline = 'middle';
        const tw = g.measureText(label).width, flip = x + s / 2 + 7 + tw > W - 4, ty = Math.min(H - 8, Math.max(8, y - s / 2 + 5));
        g.textAlign = flip ? 'right' : 'left'; g.fillText(label, flip ? x - s / 2 - 7 : x + s / 2 + 7, ty); g.textAlign = 'left';
      }
      g.globalAlpha = 1;
    };
    const hotNames = new Set(); flights.forEach((f) => { const u = (now - f.t0) / f.dur; if (u < 0.25) hotNames.add(f.m[0]); if (u > 0.75) hotNames.add(f.m[1]); });
    const chips = (front) => net.NAMES.forEach((nm) => { const p = P[net.node[nm]]; if ((p[2] >= 0) !== front) return; const da = depthA(p[2]); chip(p[0], p[1], 16 + 14 * da, false, nm, hotNames.has(nm), da); });

    E.forEach((e) => drawEdge(e, false)); drawCrimps(false); spokes(false); chips(false);
    chip(cx, cy, 36, true, 'you', hotNames.has('you'), 1);
    E.forEach((e) => drawEdge(e, true)); drawCrimps(true); spokes(true); chips(true);

    // messages in flight: a dot with a short trail and its text riding beside it; a ring where it lands
    for (let q = flights.length - 1; q >= 0; q--) {
      const f = flights[q], u = (now - f.t0) / f.dur;
      if (u >= 1) { const to = f.m[1] === 'you' ? [cx, cy] : P[net.node[f.m[1]]]; pulses.push({ x: to[0], y: to[1], t0: now }); flights.splice(q, 1); continue; }
      const e = u < 0.5 ? 2 * u * u : 1 - Math.pow(-2 * u + 2, 2) / 2;
      const at = (uu) => {
        if (f.route.spoke) { const p = P[f.route.v], k = f.route.out ? uu : 1 - uu; return [cx + (p[0] - cx) * k, cy + (p[1] - cy) * k]; }
        const n = f.route.path.length - 1, x = uu * n, i = Math.min(n - 1, Math.floor(x)), pts = arc(f.route.path[i], f.route.path[i + 1], 6), k = (x - i) * 6, j = Math.min(5, Math.floor(k)), r = k - j;
        return [pts[j][0] + (pts[j + 1][0] - pts[j][0]) * r, pts[j][1] + (pts[j + 1][1] - pts[j][1]) * r];
      };
      g.strokeStyle = COL.signal; g.lineWidth = 3; g.lineCap = 'round'; g.beginPath();
      for (let k = 0; k <= 10; k++) { const pt = at(Math.max(0, e - 0.12 + k * 0.012)); k ? g.lineTo(pt[0], pt[1]) : g.moveTo(pt[0], pt[1]); } g.stroke();
      const d = at(e); g.fillStyle = COL.signal; g.beginPath(); g.arc(d[0], d[1], 5.5, 0, 7); g.fill();
      const txt = f.m[2].startsWith('cw msg') ? f.m[2].replace(/^cw msg \S+ --session \S+ /, '') : f.m[2];
      g.font = `400 11px ${getComputedStyle(root).getPropertyValue('--f-mono')}`; const tw = Math.min(W - 8, g.measureText(txt).width + 12), bx = Math.min(W - tw - 4, Math.max(4, d[0] + 10)), by = Math.min(H - 22, Math.max(4, d[1] - 26));
      g.fillStyle = COL.paper; g.fillRect(bx, by, tw, 18); g.strokeStyle = COL.signal; g.lineWidth = 1; g.strokeRect(bx + 0.5, by + 0.5, tw - 1, 17);
      g.fillStyle = COL.ink; g.textBaseline = 'middle'; g.fillText(txt, bx + 6, by + 9.5);
    }
    for (let q = pulses.length - 1; q >= 0; q--) {
      const pu = pulses[q], u = (now - pu.t0) / 700; if (u >= 1) { pulses.splice(q, 1); continue; }
      g.strokeStyle = COL.signal; g.globalAlpha = 1 - u; g.lineWidth = 1.5; g.beginPath(); g.arc(pu.x, pu.y, 10 + 22 * u, 0, 7); g.stroke(); g.globalAlpha = 1;
    }
  };
  setMode('ind', false);

  /* ---------- fig 4.1: one sandbox, exploded. A parts diagram with registration pins and callouts.
     It builds part by part when it first scrolls into view, then breathes; every few seconds a write traces
     down through its own stack. Confidential mode adds the encrypted memory layer and seals the VM boundary. ---------- */
  let confOn = false;
  const isoCv = $('#isoc'), isoBox = isoCv.parentNode, ig = isoCv.getContext('2d');
  const IT = {}; const isoTok = () => { const cs = getComputedStyle(root); ['paper', 'ink', 'grey', 'signal'].forEach((k) => (IT[k] = cs.getPropertyValue('--' + k).trim())); IT.sans = cs.getPropertyValue('--f-sans'); IT.mono = cs.getPropertyValue('--f-mono'); };
  isoTok(); onLook.push(() => requestAnimationFrame(isoTok));
  const rgbT = (c) => { c = String(c).trim(); if (c[0] === '#') { const n = parseInt(c.slice(1, 7), 16); return [n >> 16 & 255, n >> 8 & 255, n & 255]; } const m = c.match(/[\d.]+/g); return m ? m.slice(0, 3).map(Number) : [0, 0, 0]; };
  const mixT = (a, b, t) => { const A = rgbT(a), B = rgbT(b); return `rgb(${A.map((v, i) => Math.round(v + (B[i] - v) * t)).join(',')})`; };
  const easeT = (x) => (x <= 0 ? 0 : x >= 1 ? 1 : x * x * (3 - 2 * x));
  const ISOC = { w: 0, h: 0, k: 1, conf: 0, t0: null, oy: null, hover: -1, hoverKey: null, rects: [], keys: [], vis: false };
  let isoW = 0; const isoFit = (force) => { const w = isoBox.clientWidth; if (force !== true && Math.abs(w - isoW) < 0.5) return; isoW = w; const h = Math.round(w * (w < 560 ? 1.2 : 0.95)), d = Math.min(devicePixelRatio || 1, 2); isoCv.style.height = h + 'px'; isoCv.width = Math.round(w * d); isoCv.height = Math.round(h * d); ISOC.w = w; ISOC.h = h; ig.setTransform(d, 0, 0, d, 0, 0); ISOC.oy = null; };
  new ResizeObserver(() => isoFit()).observe(isoBox); isoFit(true); window.cwRelayout = () => isoFit();
  new IntersectionObserver((es) => es.forEach((e) => { ISOC.vis = e.isIntersecting; if (e.isIntersecting && ISOC.t0 == null) ISOC.t0 = performance.now() / 1000; }), { threshold: 0.3 }).observe(isoCv);
  isoCv.addEventListener('pointermove', (e) => { const r = isoCv.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top; ISOC.hover = ISOC.rects.findIndex((q) => x >= q[0] - 4 && x <= q[2] + 4 && y >= q[1] - 4 && y <= q[3] + 4); isoCv.style.cursor = ISOC.hover >= 0 ? 'pointer' : 'default'; });
  isoCv.addEventListener('pointerleave', () => { ISOC.hover = -1; });
  // the list beside it points at the same parts
  const ROWKEYS = ['hw', 'host', 'hyp', 'ker', 'ses', 'mem'];
  $$('.layers > div').forEach((row, i) => { row.dataset.k = ROWKEYS[i]; row.addEventListener('mouseenter', () => (ISOC.hoverKey = ROWKEYS[i])); row.addEventListener('mouseleave', () => (ISOC.hoverKey = null)); });
  const STEPS = ['auth writes a file', 'its own guest kernel takes the call', 'the hypervisor passes the write on', 'the host kernel queues it', 'the disk stores it'];
  const STEPS_C = ['auth writes a file', 'its kernel encrypts the page with its own key', 'the hypervisor passes on ciphertext', 'the host kernel sees only ciphertext', 'the disk stores ciphertext'];

  const isoDraw = (now) => {
    const g = ig, { w, h } = ISOC, t = reduce ? 0 : now / 1000, dt = Math.min(0.1, (now - (ISOC.last || now)) / 1000); ISOC.last = now;
    const Cc = Math.cos(Math.PI / 6), Sn = Math.sin(Math.PI / 6);
    const bt = reduce || ISOC.t0 == null ? 99 : t - ISOC.t0, built = bt > 4.4;
    const target = reduce ? 1 : !built ? 1 : 0.5 + 0.5 * Math.cos((bt - 4.4) * 0.5);
    ISOC.k += (target - ISOC.k) * (reduce ? 1 : Math.min(1, 3 * dt)); ISOC.conf += ((confOn ? 1 : 0) - ISOC.conf) * (reduce ? 1 : Math.min(1, 4 * dt));
    const k = easeT(ISOC.k), cf = easeT(ISOC.conf), gap = 0.5 + 2.2 * k;
    const fs = w < 560 ? 11 : 12, sub = 'auth · codex · 8 GB', shared = confOn ? 'shared · sees ciphertext' : 'shared';
    // label column: measured, so labels are never clipped; the drawing takes the rest
    g.font = `500 ${fs}px ${IT.sans}`; let lw = Math.max(...['VM boundary', 'Encrypted memory', 'Session', 'Guest kernel', 'Hypervisor', 'Host kernel', 'Hardware'].map((n) => g.measureText(n).width));
    g.font = `400 ${Math.round(fs * 0.85)}px ${IT.mono}`; [sub, 'shared · sees ciphertext', 'shared'].forEach((x) => (lw = Math.max(lw, g.measureText(x).width)));
    const mk = 26, colW = Math.ceil(lw + mk + 10 + 18), drawW = w - colW;
    const u = Math.min(drawW / 18, (h - 44) / 28), R = 8.5 * Cc * u, lead = Math.min(48, Math.max(24, drawW - 2 * R - 6)), shift = Math.max(0, (w - (2 * R + 6 + lead + colW)) / 2);
    const ox = R + 6 + shift, colX = Math.min(ox + R + lead + 14, w - colW + 14);
    let oy = 0; const P = (x, y, z) => [ox + (x - y) * Cc * u, oy + (x + y) * Sn * u - z * u];
    g.clearRect(0, 0, w, h);
    const L = [
      { key: 'hw', x: -5, y: -3.5, dx: 10, dy: 7, dz: 0.8 },
      { key: 'host', x: -5, y: -3.5, dx: 10, dy: 7, dz: 0.45 },
      { key: 'hyp', x: -5, y: -3.5, dx: 10, dy: 7, dz: 0.45 },
      { key: 'mem', x: -3, y: -2, dx: 6, dy: 4, dz: 0.3 * cf },
      { key: 'ker', x: -3, y: -2, dx: 6, dy: 4, dz: 0.45 },
      { key: 'ses', x: -3, y: -2, dx: 6, dy: 4, dz: 0.75 },
    ];
    const order = { hw: 0, host: 1, hyp: 2, mem: 3, ker: 3, ses: 4 };
    let z = 0; L.forEach((l) => { if (l.key === 'mem') z += gap * 0.25; if (l.key === 'mem' && cf < 0.01) { l.z = z; l.a = 0; l.drop = 0; return; } l.z = z; z += l.dz + (l.key === 'mem' ? gap * 0.6 * cf : gap); l.a = easeT((bt - order[l.key] * 0.55) / 0.6) * (l.key === 'mem' ? cf : 1); l.drop = (1 - easeT((bt - order[l.key] * 0.55) / 0.6)) * 3; });
    const S = L.find((l) => l.key === 'ses'), K = L.find((l) => l.key === 'ker'), M = L.find((l) => l.key === 'mem');
    const zTop = S.z + S.dz, vmZ = (cf > 0.01 ? M.z : K.z) - gap * 0.3, vmTop = zTop + 0.3;
    const zMax = Math.max(...L.map((l) => l.z + l.drop + l.dz)) + 0.9, oyT = (h - 22) / 2 + (zMax * u) / 2;
    ISOC.oy = ISOC.oy == null || reduce ? oyT : ISOC.oy + (oyT - ISOC.oy) * Math.min(1, dt * 4); oy = ISOC.oy;
    const hover = ISOC.hover >= 0 ? ISOC.keys[ISOC.hover] : ISOC.hoverKey, hiKey = hover || ISOC.flash || null;
    const slab = (l) => {
      if (l.a <= 0.001 || l.dz <= 0.001) return;
      const z0 = l.z + l.drop, cc = (i, j, kk) => P(l.x + i * l.dx, l.y + j * l.dy, z0 + kk * l.dz), ink = l.key === 'ses', mem = l.key === 'mem';
      const hi = hiKey === l.key, dim = hover && hover !== l.key;
      g.globalAlpha = l.a * (dim ? 0.28 : 1);
      const stroke = hi || mem ? IT.signal : IT.ink, lw2 = hi ? 1.6 : 1;
      const face = (pts, fill) => { g.beginPath(); pts.forEach((p, i) => (i ? g.lineTo(p[0], p[1]) : g.moveTo(p[0], p[1]))); g.closePath(); g.fillStyle = fill; g.fill(); g.strokeStyle = stroke; g.lineWidth = lw2; g.stroke(); };
      face([cc(1, 0, 0), cc(1, 1, 0), cc(1, 1, 1), cc(1, 0, 1)], ink ? mixT(IT.ink, IT.paper, 0.35) : mem ? mixT(IT.paper, IT.signal, 0.35) : mixT(IT.paper, IT.ink, 0.14));
      face([cc(1, 1, 0), cc(0, 1, 0), cc(0, 1, 1), cc(1, 1, 1)], ink ? mixT(IT.ink, IT.paper, 0.2) : mem ? mixT(IT.paper, IT.signal, 0.22) : mixT(IT.paper, IT.ink, 0.07));
      if (l.key === 'hw') { const o = cc(0, 1, 1); g.save(); g.transform(Cc, Sn, 0, 1, o[0], o[1]); g.strokeStyle = mixT(IT.paper, IT.ink, 0.45); g.lineWidth = 1; for (let x = u * 0.6; x < l.dx * u - u * 0.4; x += Math.max(4, u * 0.35)) { g.beginPath(); g.moveTo(x, l.dz * u * 0.25); g.lineTo(x, l.dz * u * 0.75); g.stroke(); } g.restore(); }
      const top = [cc(0, 0, 1), cc(1, 0, 1), cc(1, 1, 1), cc(0, 1, 1)];
      face(top, ink ? IT.ink : mem ? mixT(IT.paper, IT.signal, 0.12) : IT.paper);
      const o = cc(0, 0, 1), W = l.dx * u, D = l.dy * u, fpx = Math.max(7, u * 0.42);
      g.save(); g.beginPath(); top.forEach((p, i) => (i ? g.lineTo(p[0], p[1]) : g.moveTo(p[0], p[1]))); g.closePath(); g.clip();
      g.transform(Cc, Sn, -Cc, Sn, o[0], o[1]);   // the face's own coordinates: 1px along each edge
      const faint = mixT(IT.paper, IT.ink, 0.2), print = (txt, x, y, size, col, weight = 500) => { g.fillStyle = col; g.font = `${weight} ${size}px ${IT.mono}`; g.textAlign = 'left'; g.textBaseline = 'alphabetic'; g.fillText(txt, x, y); };
      g.lineWidth = 1;
      if (l.key === 'hw') {
        g.strokeStyle = faint; for (let i = -D; i < W; i += Math.max(5, u * 0.4)) { g.beginPath(); g.moveTo(i, D); g.lineTo(i + D, 0); g.stroke(); }
        const part = (x, y, ww, hh, label, col) => { g.fillStyle = IT.paper; g.fillRect(x, y, ww, hh); g.strokeStyle = col || IT.ink; g.strokeRect(x, y, ww, hh); if (label) print(label, x + u * 0.25, y + hh - u * 0.25, fpx * 0.9, col || IT.ink); };
        part(u * 0.8, u * 0.9, u * 3, u * 3, cf > 0.5 ? 'SEV-SNP' : 'CPU', cf > 0.5 ? IT.signal : IT.ink);
        for (let i = 0; i < 4; i++) part(u * 4.4 + i * u * 0.7, u * 0.8, u * 0.4, u * 3.2, '');
        print('MEM', u * 4.4, u * 4.6, fpx * 0.9, IT.ink); part(u * 7.6, u * 0.9, u * 1.6, u * 2.2, ''); print('DISK', u * 7.6, u * 3.7, fpx * 0.9, IT.ink);
        print('HARDWARE', u * 0.4, D - u * 0.45, fpx, IT.grey);
      } else if (l.key === 'host') {
        g.fillStyle = mixT(IT.paper, IT.ink, 0.35); const st = Math.max(5, u * 0.5);
        for (let x = st / 2; x < W; x += st) for (let y = st / 2; y < D; y += st) { g.beginPath(); g.arc(x, y, Math.max(0.7, u * 0.05), 0, 7); g.fill(); }
        print('HOST KERNEL', u * 0.4, D - u * 0.45, fpx, IT.grey);
      } else if (l.key === 'hyp') {
        g.strokeStyle = faint; for (let y = u * 0.35; y < D; y += Math.max(4, u * 0.35)) { g.beginPath(); g.moveTo(0, y); g.lineTo(W, y); g.stroke(); }
        g.fillStyle = IT.paper; g.fillRect(u * 1.6, u * 1.1, u * 6.8, u * 4.8); g.setLineDash([3, 3]); g.strokeStyle = IT.signal; g.strokeRect(u * 1.6, u * 1.1, u * 6.8, u * 4.8); g.setLineDash([]);
        print('VM SLOT', u * 1.85, u * 1.1 + fpx * 1.3, fpx * 0.9, IT.signal);
        print('HYPERVISOR', u * 0.4, D - u * 0.45, fpx, IT.grey);
      } else if (l.key === 'ker') {
        g.strokeStyle = faint; for (let x = u * 0.3; x < W; x += Math.max(4, u * 0.3)) { g.beginPath(); g.moveTo(x, 0); g.lineTo(x, D); g.stroke(); }
        g.fillStyle = IT.paper; g.fillRect(u * 0.25, D - u * 1.05, u * 3.6, u * 0.8); print('GUEST KERNEL', u * 0.4, D - u * 0.45, fpx, IT.ink);
      } else if (mem) {
        print('ENCRYPTED · KEY 0x7F3A…', u * 0.4, D - u * 0.45, fpx * 0.9, IT.signal);
        g.fillStyle = mixT(IT.paper, IT.signal, 0.5); for (let i = 0; i < 18; i++) { const x = u * 0.4 + (i % 9) * u * 0.6, y = u * (0.8 + Math.floor(i / 9) * 0.6); print(((i * 2654435761 + Math.floor(t * 2)) >>> 0).toString(16).slice(0, 2).toUpperCase(), x, y, fpx * 0.8, mixT(IT.paper, IT.signal, 0.6), 400); }
      } else {
        print('auth', u * 0.45, u * 1.3, Math.max(10, u * 0.9), IT.paper);
        print('codex · 8 GB', u * 0.45, u * 2.05, fpx, mixT(IT.ink, IT.paper, 0.6), 400);
        g.fillStyle = mixT(IT.ink, IT.paper, 0.55);
        for (let i = 0; i < 3; i++) { const wv = reduce ? 0.6 : 0.35 + 0.5 * (0.5 + 0.5 * Math.sin(t * (1.3 + i * 0.7) + i * 2)); g.fillRect(u * 0.45, u * (2.6 + i * 0.42), u * 4.6 * wv, Math.max(1.5, u * 0.14)); }
      }
      g.restore(); g.globalAlpha = 1;
    };
    const hyp = L.find((l) => l.key === 'hyp'), pinP = easeT((bt - 3.6) / 0.7);
    const pin = (x, y, p) => {
      if (p <= 0) return; const top = zTop + 0.9, bot = hyp.z + hyp.dz, z0 = top - (top - bot) * p;
      const a = P(x, y, z0), b = P(x, y, top); g.setLineDash([2, 4]); g.strokeStyle = IT.grey; g.lineWidth = 1; g.beginPath(); g.moveTo(a[0], a[1]); g.lineTo(b[0], b[1]); g.stroke(); g.setLineDash([]);
      g.fillStyle = IT.paper; g.strokeStyle = IT.grey; g.beginPath(); g.arc(b[0], b[1], 2.6, 0, 7); g.fill(); g.stroke();
      if (p >= 1) { g.fillStyle = IT.grey; g.beginPath(); g.arc(a[0], a[1], 1.8, 0, 7); g.fill(); }
    };
    ['hw', 'host', 'hyp'].forEach((key) => slab(L.find((l) => l.key === key)));
    [[-3, -2], [3, -2], [-3, 2]].forEach(([x, y]) => pin(x, y, pinP));
    ['mem', 'ker', 'ses'].forEach((key) => slab(L.find((l) => l.key === key)));
    // the VM boundary: dashed and slowly marching; sealed solid in confidential mode
    const vmP = easeT((bt - 2.9) / 0.9);
    if (vmP > 0) {
      const vx = -3.4, vy = -2.4, vdx = 6.8, vdy = 4.8, vdz = vmTop - vmZ, q = (i, j, kk) => P(vx + i * vdx, vy + j * vdy, vmZ + kk * vdz);
      const E = [[0,0,0,1,0,0],[1,0,0,1,1,0],[1,1,0,0,1,0],[0,1,0,0,0,0],[0,0,1,1,0,1],[1,0,1,1,1,1],[1,1,1,0,1,1],[0,1,1,0,0,1],[0,0,0,0,0,1],[1,0,0,1,0,1],[1,1,0,1,1,1],[0,1,0,0,1,1]];
      g.globalAlpha = hover && hover !== 'vm' ? 0.3 : 1; g.strokeStyle = IT.signal; g.lineWidth = hiKey === 'vm' || cf > 0.5 ? 1.6 : 1;
      g.setLineDash(cf > 0.5 ? [] : [4, 3]); g.lineDashOffset = reduce ? 0 : -t * 10;
      E.forEach((e) => { const a2 = q(e[0], e[1], e[2]), b2 = q(e[3], e[4], e[5]); g.beginPath(); g.moveTo(a2[0], a2[1]); g.lineTo(a2[0] + (b2[0] - a2[0]) * vmP, a2[1] + (b2[1] - a2[1]) * vmP); g.stroke(); });
      g.setLineDash([]); g.lineDashOffset = 0;
      if (vmP >= 1) [[0, 0], [1, 0], [1, 1], [0, 1]].forEach(([i, j]) => { const p = q(i, j, 1); g.fillStyle = IT.signal; g.fillRect(p[0] - 2, p[1] - 2, 4, 4); });
      g.globalAlpha = 1;
    }
    pin(3, 2, pinP);
    // a write, traced down through its own stack
    ISOC.flash = null; let stepNow = -1;
    if (!reduce && built) {
      const pt = t % 6.5;
      if (pt < 3.6) {
        const stops = [S, K, hyp, L[1], L[0]].map((l) => l.z + l.dz), f = pt / 3.6, sg = Math.min(3.999, f * 4), i = Math.floor(sg), zz = stops[i] + (stops[i + 1] - stops[i]) * easeT(sg - i);
        const head = P(1.6, 0.6, zz + 0.05), from = P(1.6, 0.6, stops[0] + 0.05);
        g.strokeStyle = IT.signal; g.lineWidth = 2; g.beginPath(); g.moveTo(from[0], from[1]); g.lineTo(head[0], head[1]); g.stroke();
        g.fillStyle = IT.signal; g.beginPath(); g.moveTo(head[0], head[1] - 5); g.lineTo(head[0] + 5, head[1]); g.lineTo(head[0], head[1] + 5); g.lineTo(head[0] - 5, head[1]); g.closePath(); g.fill();
        stepNow = sg - i < 0.35 ? i : i + 1; if (pt > 3.3) stepNow = 4;
        ISOC.flash = ['ses', 'ker', 'hyp', 'host', 'hw'][Math.min(4, stepNow)];
      }
    }
    // callouts: numbered to match the list beside the figure (4.1 to 4.6), each appearing as its part arrives
    const at = (l) => P(l.x + l.dx, l.y, l.z + l.drop + l.dz / 2);
    const items = [{ key: 'vm', n: 'VM', name: 'VM boundary', at: P(3.4, -2.4, vmTop), vm: true, a: vmP }];
    if (cf > 0.01) items.push({ key: 'mem', n: '4.6', name: 'Encrypted memory', at: at(M), vm: true, a: cf * easeT((bt - 1.65) / 0.6) });
    items.push({ key: 'ses', n: '4.5', name: 'Session', sub, at: at(S), a: S.a }, { key: 'ker', n: '4.4', name: 'Guest kernel', at: at(K), a: K.a },
      { key: 'hyp', n: '4.3', name: 'Hypervisor', sub: shared, at: at(hyp), a: hyp.a }, { key: 'host', n: '4.2', name: 'Host kernel', sub: shared, at: at(L[1]), a: L[1].a }, { key: 'hw', n: '4.1', name: 'Hardware', sub: 'shared', at: at(L[0]), a: L[0].a });
    items.sort((p, q) => p.at[1] - q.at[1]);   // labels follow the drawing top to bottom, so leaders never cross
    ISOC.keys = items.map((x) => x.key);
    const lh = fs + 6, minGap = lh * 2 + 2, ys = items.map((x) => x.at[1]);
    for (let i = 1; i < ys.length; i++) ys[i] = Math.max(ys[i], ys[i - 1] + minGap);
    const over = ys[ys.length - 1] + lh * 1.5 - (h - 24); if (over > 0) for (let i = 0; i < ys.length; i++) ys[i] -= over;
    for (let i = 1; i < ys.length; i++) ys[i] = Math.max(ys[i], ys[i - 1] + minGap);
    ISOC.rects = [];
    items.forEach((it, i) => {
      const y = ys[i], on = hiKey === it.key, col = it.vm || on ? IT.signal : IT.ink;
      g.globalAlpha = (it.a == null ? 1 : Math.max(0, it.a)) * (hover && hover !== it.key ? 0.35 : 1);
      g.strokeStyle = col; g.lineWidth = 1; g.beginPath(); g.moveTo(it.at[0], it.at[1]); g.lineTo(colX - 12, y); g.lineTo(colX, y); g.stroke();
      g.font = `500 ${Math.round(fs * 0.8)}px ${IT.mono}`; const nw = Math.max(mk, g.measureText(it.n).width + 8);
      g.fillStyle = on ? col : IT.paper; g.fillRect(colX, y - 8, nw, 16); g.strokeRect(colX + 0.5, y - 7.5, nw - 1, 15);
      g.fillStyle = on ? IT.paper : col; g.textAlign = 'center'; g.textBaseline = 'middle'; g.fillText(it.n, colX + nw / 2, y + 0.5);
      g.textAlign = 'left'; g.fillStyle = col; g.font = `500 ${fs}px ${IT.sans}`; g.fillText(it.name, colX + nw + 8, y);
      let wid = g.measureText(it.name).width;
      if (it.sub) { g.fillStyle = IT.grey; g.font = `400 ${Math.round(fs * 0.85)}px ${IT.mono}`; g.fillText(it.sub, colX + nw + 8, y + lh); wid = Math.max(wid, g.measureText(it.sub).width); }
      ISOC.rects.push([colX, y - lh / 2, colX + nw + 8 + wid, y + (it.sub ? lh * 1.5 : lh / 2)]);
      g.globalAlpha = 1;
    });
    // the step being traced, under the drawing
    g.textAlign = 'left'; g.textBaseline = 'alphabetic'; g.font = `400 11px ${IT.mono}`; g.fillStyle = stepNow >= 0 ? IT.signal : IT.grey;
    g.fillText(stepNow >= 0 ? `${stepNow + 1}/5 · ${(confOn ? STEPS_C : STEPS)[stepNow]}` : (built || reduce ? 'hover a label to pick out its part' : ''), 0, h - 6);
    // the list beside the figure lights the same part
    $$('.layers > div').forEach((row) => row.classList.toggle('lit', row.dataset.k === hiKey));
  };
  const isoLoop = (now) => { if (ISOC.vis || ISOC.oy == null) isoDraw(now); requestAnimationFrame(isoLoop); };
  requestAnimationFrame(isoLoop);
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => isoDraw(performance.now()));
  const setConf = (on) => {
    confOn = on;
    $('#iA').setAttribute('aria-pressed', String(!on)); $('#iB').setAttribute('aria-pressed', String(on)); $('#confRow').classList.toggle('on', on);
    $('#isocap').textContent = on ? 'Fig. 4.1 · Confidential. Its memory is encrypted with its own key; the hypervisor and host see only ciphertext.' : 'Fig. 4.1 · One sandbox, taken apart. Its own session, kernel and VM; three shared layers below.';
  };
  $('#iA').addEventListener('click', () => setConf(false)); $('#iB').addEventListener('click', () => setConf(true));
  setConf(false);

  /* ---------- fig 1.1: sized to the work. Six VM columns on two trays, local and cloud. Each column's height follows
     its memory limit, ruled every 2 GB, with live use filling it; now and then one hits its limit and holds there
     while the others carry on. Each column carries its own label, printed up its front face. ---------- */
  {
    const SESS = [['1.1', 'auth', 'codex', 8], ['1.2', 'api', 'claude', 32], ['1.3', 'billing', 'claude', 16], ['1.4', 'docs', 'codex', 2], ['1.5', 'web', 'codex', 8], ['1.6', 'infra', 'claude', 16]];
    const POS = { auth: -11, docs: -7, api: -1.5, billing: 2.5, web: 6.5, infra: 10.5 }, ORDER = ['auth', 'docs', 'api', 'billing', 'web', 'infra'];
    const PER = 0.16; // column height = BASE + GB x PER, in grid units; BASE is taller on phones so the shortest face still holds its label
    const cv = $('#szc'), box = cv.parentNode, g = cv.getContext('2d');
    const Z = { w: 0, h: 0, vis: false, t0: null, mx: -1, my: -1, hits: [], hoverRow: -1, hT: null, hk: 0 };
    const ph = SESS.map(() => Math.random() * 10), use = SESS.map(() => 0.4), HOGS = [1, 4, 0, 2, 5, 3];
    let zW = 0; const fit = (force) => { const w = box.clientWidth; if (force !== true && Math.abs(w - zW) < 0.5) return; zW = w; const h = Math.round(w * 0.64 + 16), d = Math.min(devicePixelRatio || 1, 2); cv.style.height = h + 'px'; cv.width = Math.round(w * d); cv.height = Math.round(h * d); Z.w = w; Z.h = h; g.setTransform(d, 0, 0, d, 0, 0); };
    new ResizeObserver(() => fit()).observe(box); fit(true);
    new IntersectionObserver((es) => es.forEach((e) => { Z.vis = e.isIntersecting; if (e.isIntersecting && Z.t0 == null) Z.t0 = performance.now() / 1000; }), { threshold: 0.3 }).observe(cv);
    cv.addEventListener('pointermove', (e) => { const r = cv.getBoundingClientRect(); Z.mx = e.clientX - r.left; Z.my = e.clientY - r.top; });
    cv.addEventListener('pointerleave', () => { Z.mx = Z.my = -1; });
    const rows = $$('#sessions tbody tr'); rows.forEach((row, i) => { row.addEventListener('mouseenter', () => (Z.hoverRow = i)); row.addEventListener('mouseleave', () => (Z.hoverRow = -1)); });
    // isometric helpers
    const Cc = Math.cos(Math.PI / 6), Sn = 0.5;
    const iso = (ox, oy, u) => {
      const P = (x, y, z) => [ox + (x - y) * Cc * u, oy + (x + y) * Sn * u - z * u];
      const poly = (pts, fill, stroke, lw = 1) => { g.beginPath(); pts.forEach((p, i) => (i ? g.lineTo(p[0], p[1]) : g.moveTo(p[0], p[1]))); g.closePath(); if (fill) { g.fillStyle = fill; g.fill(); } if (stroke) { g.strokeStyle = stroke; g.lineWidth = lw; g.stroke(); } };
      const box3 = (x, y, z, dx, dy, dz, o = {}) => { const c = (i, j, k) => P(x + i * dx, y + j * dy, z + k * dz), st = o.stroke || IT.ink, lw = o.lw || 1;
        poly([c(1, 0, 0), c(1, 1, 0), c(1, 1, 1), c(1, 0, 1)], o.sideR || mixT(IT.paper, IT.ink, 0.14), st, lw);
        poly([c(1, 1, 0), c(0, 1, 0), c(0, 1, 1), c(1, 1, 1)], o.sideF || mixT(IT.paper, IT.ink, 0.07), st, lw);
        poly([c(0, 0, 1), c(1, 0, 1), c(1, 1, 1), c(0, 1, 1)], o.top || IT.paper, st, lw); };
      const onTop = (x, y, z, fn) => { const o = P(x, y, z); g.save(); g.transform(Cc, Sn, -Cc, Sn, o[0], o[1]); fn(); g.restore(); };
      const onFront = (x, y, z, fn) => { const o = P(x, y, z); g.save(); g.transform(Cc, Sn, 0, 1, o[0], o[1]); fn(); g.restore(); };
      const wire = (x, y, z, dx, dy, dz, t) => { const c = (i, j, k) => P(x + i * dx, y + j * dy, z + k * dz);
        const E = [[0,0,0,1,0,0],[1,0,0,1,1,0],[1,1,0,0,1,0],[0,1,0,0,0,0],[0,0,1,1,0,1],[1,0,1,1,1,1],[1,1,1,0,1,1],[0,1,1,0,0,1],[0,0,0,0,0,1],[1,0,0,1,0,1],[1,1,0,1,1,1],[0,1,0,0,1,1]];
        g.setLineDash([4, 3]); g.lineDashOffset = -t * 8; g.strokeStyle = IT.signal; g.lineWidth = 1;
        E.forEach((e) => { const a2 = c(e[0], e[1], e[2]), b2 = c(e[3], e[4], e[5]); g.beginPath(); g.moveTo(a2[0], a2[1]); g.lineTo(b2[0], b2[1]); g.stroke(); });
        g.setLineDash([]); g.lineDashOffset = 0; };
      return { P, poly, box3, onTop, onFront, wire };
    };
    const inPoly = (pts, px, py) => { let c = false; for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) { const [xi, yi] = pts[i], [xj, yj] = pts[j]; if ((yi > py) !== (yj > py) && px < ((xj - xi) * (py - yi)) / (yj - yi) + xi) c = !c; } return c; };
    const draw = (now) => {
      const { w, h } = Z, t = reduce ? 0 : now / 1000, bt = reduce || Z.t0 == null ? (reduce ? 99 : 0) : t - Z.t0;
      if (Z.hT == null && bt > 3) Z.hT = t;
      let lt = Z.hT == null || reduce ? 2.5 : t - Z.hT; if (lt > 9) { Z.hT = t; Z.hk = (Z.hk + 1) % 6; lt = 0; }
      const hog = HOGS[Z.hk];
      // the drawing runs from the top of auth's boundary (the left end sits highest) to the cloud tray's front corner
      const BASE = w < 560 ? 1.7 : 1.1, topU = 9.23 + BASE, u = Math.min(w / 31, (h - 20) / (topU + 8.5)), oy = h / 2 + (topU - 8.5) / 2 * u, J = iso(w / 2 - 0.65 * Cc * u, oy, u);
      const fs = Math.max(8, Math.min(12, u * 0.42)), pad = u * 0.18;
      let hi = Z.hoverRow; for (let k = Z.hits.length - 1; k >= 0; k--) if (inPoly(Z.hits[k].pts, Z.mx, Z.my)) { hi = Z.hits[k].i; break; }
      g.clearRect(0, 0, w, h);
      const tray = (x0, x1, txt) => { J.box3(x0, -3, 0, x1 - x0, 6, 0.5); J.onTop(x0, -3, 0.5, () => { g.fillStyle = IT.grey; g.font = `500 ${Math.max(7, u * 0.38)}px ${IT.mono}`; g.textAlign = 'left'; g.textBaseline = 'alphabetic'; g.fillText(txt, u * 0.35, 6 * u - u * 0.35); }); };
      tray(-12.5, -3.6, 'LOCAL'); tray(-2.9, 14, 'CLOUD');
      Z.hits = [];
      ORDER.forEach((nm) => {
        const i = SESS.findIndex((x) => x[1] === nm), S = SESS[i], gb = S[3], x = POS[nm], y = -1.5, d = 3, rise = reduce ? 1 : easeT((bt - i * 0.3) / 0.9);
        const H = (BASE + gb * PER) * rise, z0 = 0.5, dim = hi >= 0 && hi !== i;
        const calm = 0.3 + 0.15 * Math.sin(t * 0.8 + ph[i]) + 0.07 * Math.sin(t * 2.1 + ph[i] * 2), spike = i === hog ? (lt < 1.2 ? easeT(lt / 1.2) : lt < 5 ? 1 : 1 - easeT((lt - 5) / 1.4)) : 0;
        use[i] = reduce ? (i === hog ? 1 : 0.42) : Math.min(1, calm + (1 - calm) * spike);
        const atCap = use[i] > 0.995 && rise >= 1, lit = atCap || hi === i, al = dim ? 0.3 : 1;
        g.globalAlpha = al;
        J.box3(x, y, z0, d, d, H, { stroke: lit ? IT.signal : IT.ink, lw: lit ? 1.6 : 1 });
        const fillH = H * use[i] * (rise >= 1 ? 1 : 0);
        if (fillH > 0.01) { J.poly([J.P(x + d, y, z0), J.P(x + d, y + d, z0), J.P(x + d, y + d, z0 + fillH), J.P(x + d, y, z0 + fillH)], mixT(IT.paper, IT.signal, atCap ? 0.55 : 0.3)); J.poly([J.P(x + d, y + d, z0), J.P(x, y + d, z0), J.P(x, y + d, z0 + fillH), J.P(x + d, y + d, z0 + fillH)], mixT(IT.paper, IT.signal, atCap ? 0.4 : 0.18)); }
        // a tick every 2 GB down the face's outer edge
        J.onFront(x, y + d, z0 + H, () => { g.strokeStyle = mixT(IT.paper, IT.ink, 0.35); g.lineWidth = 1; for (let k = 2; k < gb; k += 2) { const yy = (gb - k) * PER * u * rise; g.beginPath(); g.moveTo(0, yy); g.lineTo(u * 0.5, yy); g.stroke(); } });
        const c2 = (a2, b2, k) => J.P(x + a2 * d, y + b2 * d, z0 + k * H); g.strokeStyle = lit ? IT.signal : IT.ink; g.lineWidth = lit ? 1.6 : 1;
        [[c2(1, 0, 0), c2(1, 0, 1)], [c2(1, 1, 0), c2(1, 1, 1)], [c2(0, 1, 0), c2(0, 1, 1)]].forEach(([p, q]) => { g.beginPath(); g.moveTo(p[0], p[1]); g.lineTo(q[0], q[1]); g.stroke(); });
        const capZ = z0 + H + 0.25 * rise;
        J.box3(x, y, capZ, d, d, 0.45, { top: IT.ink, sideR: mixT(IT.ink, IT.paper, 0.35), sideF: mixT(IT.ink, IT.paper, 0.2), stroke: IT.ink });
        J.onTop(x, y, capZ + 0.45, () => { g.fillStyle = IT.paper; g.font = `500 ${Math.max(8, u * 0.5)}px ${IT.mono}`; g.textAlign = 'left'; g.textBaseline = 'alphabetic'; g.fillText(S[0], u * 0.3, u * 1.0); });
        // the label, turned 90 degrees and printed up the front face; on a face too short for it, it stands on the cap in the same plane
        if (rise > 0.6) {
          const sub = `${gb} GB`; g.font = `500 ${fs}px ${IT.sans}`; const nW = g.measureText(nm).width; g.font = `400 ${fs * 0.9}px ${IT.mono}`; const sW = g.measureText(sub).width;
          const fits = Math.max(nW, sW) + pad * 2 <= H * u, zb = fits ? z0 : capZ + 0.6;
          g.globalAlpha = al * Math.min(1, (rise - 0.6) / 0.4);
          J.onFront(x, y + d, zb, () => { g.rotate(-Math.PI / 2); g.textAlign = 'left'; g.textBaseline = 'top';
            g.fillStyle = lit ? IT.signal : IT.ink; g.font = `500 ${fs}px ${IT.sans}`; g.fillText(nm, pad, u * 0.75);
            g.fillStyle = lit ? IT.signal : IT.grey; g.font = `400 ${fs * 0.9}px ${IT.mono}`; g.fillText(sub, pad, u * 0.75 + fs * 1.3); });
          g.globalAlpha = al;
        }
        if (rise >= 1) J.wire(x - 0.3, y - 0.3, z0, d + 0.6, d + 0.6, H + 0.9, t);
        g.globalAlpha = 1;
        // the column's outline, for hover
        const zt = capZ + 0.45; Z.hits.push({ i, pts: [J.P(x, y + d, z0), J.P(x + d, y + d, z0), J.P(x + d, y, z0), J.P(x + d, y, zt), J.P(x, y, zt), J.P(x, y + d, zt)] });
      });
      rows.forEach((row, i) => row.classList.toggle('lit', i === hi));
    };
    let drawn = false; const loop = (now) => { if (Z.vis || !drawn) { draw(now); drawn = true; } requestAnimationFrame(loop); };
    requestAnimationFrame(loop);
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => draw(performance.now()));
  }

  /* ---------- the wire behind the page ---------- */
  const canvas = $('#wire'), gl = canvas.getContext('webgl', { antialias: false, alpha: false, powerPreference: 'high-performance' });
  const ST = {
    top:      { cam: [0.0, 0.0, 8.6],  tgt: [0.0, -0.9, 0],  roll: -0.03,  spread: 1.0, twist: 1.0, fade: 0.0,  fov: 40, ws: 1.0 },
    sessions: { cam: [5.2, 1.2, 4.6],  tgt: [-0.6, 0.0, 0],   roll: 0.42,  spread: 1.9, twist: 0.45, fade: 0.55, fov: 42, ws: 1.0 },
    ends:     { cam: [0.0, 0.0, 9.0],  tgt: [0.0, 0.0, 0],    roll: 1.5708, spread: 1.0, twist: 1.0, fade: 0.25, fov: 44, ws: 1.0 },
    mesh:     { cam: [-1.0, 1.2, 15],  tgt: [0.6, -0.4, 0],   roll: 0.32,  spread: 5.2, twist: 0.32, fade: 0.42, fov: 44, ws: 2.6 },   // pulled apart: strands far out, wires spaced
    iso:      { cam: [3.0, 1.4, 5.0],  tgt: [-1.4, -0.2, 0],  roll: -0.55, spread: 1.0, twist: 1.0, fade: 0.55, fov: 42, ws: 1.0 },
    sdk:      { cam: [-1.2, 0.9, 1.9], tgt: [1.4, 0.15, -0.2], roll: 0.0,  spread: 1.0, twist: 1.0, fade: 0.15, fov: 40, ws: 1.0 },
    open:     { cam: [0.0, 0.0, 12],   tgt: [0.0, 2.6, 0],    roll: 0.06,  spread: 1.0, twist: 1.0, fade: 0.7,  fov: 44, ws: 1.0 },
    end:      { cam: [0.0, 0.0, 8.0],  tgt: [0.0, 1.2, 0],    roll: -0.1,  spread: 1.0, twist: 1.0, fade: 0.1,  fov: 40, ws: 1.0 },
  };
  if (!gl) { canvas.remove(); return; }
  const sh = (type, src) => { const s = gl.createShader(type); gl.shaderSource(s, src); gl.compileShader(s); return s; };
  const prog = gl.createProgram(), vs = sh(gl.VERTEX_SHADER, 'attribute vec2 p; void main(){ gl_Position = vec4(p, 0.0, 1.0); }'), fs = sh(gl.FRAGMENT_SHADER, WIRE_SHADER);
  gl.attachShader(prog, vs); gl.attachShader(prog, fs); gl.linkProgram(prog);
  // the rest of the wire waits here for its shader, while the page carries on
  if (!(await linked(gl, prog))) [vs, fs].forEach((s) => gl.getShaderParameter(s, gl.COMPILE_STATUS) || console.error(gl.getShaderInfoLog(s)));
  gl.useProgram(prog);
  const buf = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, buf); gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const loc = gl.getAttribLocation(prog, 'p'); gl.enableVertexAttribArray(loc); gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
  const U = {}; ['uRes', 'uTime', 'uTan', 'uRoll', 'uSpread', 'uTwist', 'uFade', 'uPulse', 'uWS', 'uCam', 'uTgt', 'uBg', 'uSteel', 'uSig', 'uRim', 'uSoft', 'uRainC', 'uRainH', 'uRain', 'uRainT', 'uPx', 'uRainG', 'uRainR', 'uRainN', 'uHov'].forEach((n) => (U[n] = gl.getUniformLocation(prog, n)));
  // glyph atlas for the rain: mirrored half-width kana, digits and symbols
  {
    const N = 8, S2 = 64, cv = document.createElement('canvas'); cv.width = cv.height = N * S2;
    const g = cv.getContext('2d'); g.fillStyle = '#000'; g.fillRect(0, 0, cv.width, cv.height);
    g.fillStyle = '#fff'; g.textAlign = 'center'; g.textBaseline = 'middle';
    g.font = '600 44px "MS Gothic","Hiragino Kaku Gothic ProN","Hiragino Sans","Noto Sans JP","Yu Gothic",monospace';
    const set = Array.from('ｦｱｳｴｵｶｷｹｺｻｼｽｾｿﾀﾂﾃﾅﾆﾇﾈﾊﾋﾎﾏﾐﾑﾒﾓﾔﾕﾗﾘﾜ0123456789Z:."=*+-<>¦|_');
    for (let i = 0; i < N * N; i++) { g.save(); g.translate((i % N) * S2 + 32, Math.floor(i / N) * S2 + 33); g.scale(-1, 1); g.fillText(set[i % set.length], 0, 0); g.restore(); }   // mirrored, true proportions
    // measure each glyph's ink and store its left and right edge (0..1 of the cell) in the cell's G and B channels
    const img = g.getImageData(0, 0, cv.width, cv.height), d = img.data, W2 = cv.width;
    for (let i = 0; i < N * N; i++) {
      const x0 = (i % N) * S2, y0 = Math.floor(i / N) * S2; let L = S2, R = -1;
      for (let y = y0; y < y0 + S2; y++) for (let x = x0; x < x0 + S2; x++) if (d[(y * W2 + x) * 4] > 60) { if (x - x0 < L) L = x - x0; if (x - x0 > R) R = x - x0; }
      const l = R < 0 ? 0.5 : L / S2, r = R < 0 ? 0.5 : (R + 1) / S2;
      for (let y = y0; y < y0 + S2; y++) for (let x = x0; x < x0 + S2; x++) { const o = (y * W2 + x) * 4; d[o + 1] = Math.round(l * 255); d[o + 2] = Math.round(r * 255); }
    }
    g.putImageData(img, 0, 0);
    const tex = gl.createTexture(); gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, tex);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, cv); gl.generateMipmap(gl.TEXTURE_2D);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR_MIPMAP_LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE); gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.uniform1i(gl.getUniformLocation(prog, 'uGlyphs'), 0);
  }
  const rgb = (h) => { const n = parseInt(h.slice(1, 7), 16); return [(n >> 16 & 255) / 255, (n >> 8 & 255) / 255, (n & 255) / 255]; };
  const setColours = (c) => {
    const pa = rgb(c.paper), st = rgb(c.steel), sa = a01(c.steel), ra = a01(c.rim);
    gl.uniform3f(U.uBg, ...pa); gl.uniform3f(U.uSteel, ...st.map((v, i) => pa[i] + (v - pa[i]) * sa)); gl.uniform3f(U.uSig, ...rgb(c.signal)); gl.uniform3f(U.uRim, ...rgb(c.rim).map((v) => v * ra));
    const FX = LOOK.fx, rc = rgb(c.rain), hc = resolved() === 'dark' ? rc.map((v) => v + (1 - v) * 0.6) : rc.map((v, i) => v + (rgb(c.ink)[i] - v) * 0.45);   // the drop's head: lighter on dark paper, deeper on light
    gl.uniform3f(U.uRainH, ...hc); gl.uniform3f(U.uRainC, ...rc); gl.uniform1f(U.uRain, FX.rain ? a01(c.rain) : 0);
  };
  onLook.push(setColours); setColours(palette());

  let scale = Math.min(devicePixelRatio || 1, 2);
  const resize = () => { canvas.width = Math.max(2, Math.floor(innerWidth * scale)); canvas.height = Math.max(2, Math.floor(innerHeight * scale)); gl.viewport(0, 0, canvas.width, canvas.height); };
  addEventListener('resize', resize); resize();

  const secs = $$('[data-st]'), keys = secs.map((s) => s.id), logoEl = $('.hero .logo'), footEl = $('.hero .foot'), getrow = $('#getrow'); let getrowMT = -1;
  const lerp = (a, b, k) => a + (b - a) * k, ss = (a, b, x) => { const t = Math.min(1, Math.max(0, (x - a) / (b - a))); return t * t * (3 - 2 * t); };
  const P = JSON.parse(JSON.stringify(ST.top));
  const rainCols = $$('.cols i'), pageEl = $('.page');
  const TR = [], trU = gl.getUniformLocation(prog, 'uTrail'), trV = new Float32Array(96); let trLast = null;
  // unlay under the pointer, as physics. Pushing into the rope kicks the opening open in proportion to how fast the pointer
  // moved; a stiff, well-damped spring then lays it back within about a third of a second, like steel giving under a finger. Holding still adds
  // nothing; every new push kicks it again. Each move is tested against the rope with the camera as last drawn.
  const HV = { px: null, py: null, x: 0, s: 0, v: 0, t: 0 }, CAMS = { ok: false };
  const nz = (v) => { const l = Math.hypot(...v) || 1; return v.map((q) => q / l); };
  const ropeAt = (px, py) => {
    if (!CAMS.ok) return null;
    const { W, H, th, cam, tgt, roll, outer, fade } = CAMS, ux = (px * scale - 0.5 * W) / H * 2, uy = (0.5 * H - py * scale) / H * 2;
    const fw = nz([tgt[0] - cam[0], tgt[1] - cam[1], tgt[2] - cam[2]]), rt = nz([-fw[2], 0, fw[0]]), up = [rt[1] * fw[2] - rt[2] * fw[1], rt[2] * fw[0] - rt[0] * fw[2], rt[0] * fw[1] - rt[1] * fw[0]];
    const c = Math.cos(roll), sn = Math.sin(roll), rot = (v) => [c * v[0] + sn * v[1], -sn * v[0] + c * v[1], v[2]];
    const ro = rot(cam), rd = rot(nz([0, 1, 2].map((k) => fw[k] + (ux * rt[k] + uy * up[k]) * th)));
    const den = rd[1] * rd[1] + rd[2] * rd[2], t = den > 1e-6 ? -(ro[1] * rd[1] + ro[2] * rd[2]) / den : -1;
    const d0 = Math.hypot(ro[1] + rd[1] * t, ro[2] + rd[2] * t);
    return t > 0 && d0 < outer + 0.2 && fade < 0.9 ? ro[0] + rd[0] * t : null;
  };
  addEventListener('pointermove', (e) => {
    if (e.pointerType === 'touch' || reduce) return;
    const moved = HV.px == null ? 0 : Math.hypot(e.clientX - HV.px, e.clientY - HV.py);
    HV.px = e.clientX; HV.py = e.clientY;
    const x0 = moved > 0 ? ropeAt(HV.px, HV.py) : null;
    if (x0 != null) { HV.x = HV.s < 0.05 ? x0 : HV.x + (x0 - HV.x) * 0.5; HV.v = Math.min(9, HV.v + Math.min(moved, 30) * 0.28); }
  }, { passive: true });
  document.addEventListener('pointerleave', () => { HV.px = null; });
  addEventListener('blur', () => { HV.px = null; });
  addEventListener('pointermove', (e) => {
    if (reduce || !LOOK.fx.rain || !LOOK.fx.ripple || e.pointerType === 'touch') return;
    const x = e.clientX, y = e.clientY - pageEl.getBoundingClientRect().top, add = (px, py) => { TR.push({ x: px, y: py, t0: time }); if (TR.length > 24) TR.shift(); };
    if (!trLast || time - trLast[2] > 0.3) { add(x, y); trLast = [x, y, time]; return; }
    const dx = x - trLast[0], dy = y - trLast[1], dd = Math.hypot(dx, dy); if (dd < 12) return;
    const n = Math.min(8, Math.floor(dd / 12)); for (let k = 1; k <= n; k++) add(trLast[0] + dx * k / n, trLast[1] + dy * k / n);
    trLast = [x, y, time];
  }, { passive: true });
  let time = 0, rainT = 0, last = performance.now(), acc = 0, frames = 0;
  function frame(now) {
    const dt = Math.min(0.05, (now - last) / 1000); last = now; if (!reduce) { time += dt; rainT += dt * LOOK.fx.rainSpeed; }   // speed changes the rate only, never jumps the pattern
    acc += dt; frames++;
    if (acc > 2) { const fps = frames / acc; if (fps < 28 && scale > 1) { scale = Math.max(1, scale * 0.85); resize(); } else if (fps > 52 && scale < Math.min(devicePixelRatio || 1, 2)) { scale = Math.min(Math.min(devicePixelRatio || 1, 2), scale / 0.85); resize(); } acc = 0; frames = 0; }
    // which section owns the screen, and how far towards the next one
    const mid = innerHeight * 0.55; let i = 0, prog = 0;
    secs.forEach((s, k) => { const r = s.getBoundingClientRect(); if (r.top <= mid) { i = k; prog = Math.min(1, Math.max(0, (mid - r.top) / r.height)); } });
    {
      // the wordmark sits on the wire: size the rope from the logo, its top edge a little above the logo's baseline
      const lr = logoEl.getBoundingClientRect(), H = innerHeight, th = Math.tan(ST.top.fov * Math.PI / 360);
      const R = H * 0.15 * LOOK.size, yc = lr.bottom + 5 + R + LOOK.layout.wire;   // rope 30% of the window tall; the wordmark rests on its top edge
      // the install box sits centred just under the wire
      // measure what is drawn (the headline and spec list may be dragged below their row), leave room for the marks
      const fr = footEl.getBoundingClientRect().bottom, fb = Math.max(fr, ...[...footEl.children].map((c) => c.getBoundingClientRect().bottom));
      const bu = LOOK.rhythm.base, mt = Math.ceil((Math.max(fb + 48, yc + R + 32) - fr) / bu) * bu;
      if (mt !== getrowMT) { getrowMT = mt; getrow.style.marginTop = mt + 'px'; }
      const d = H / (2 * th * R), ty = (yc - H / 2) * (2 * th * d / H);
      ST.top.cam = [0, ty, d]; ST.top.tgt = [0, ty, 0];
    }
    const A = ST[keys[i]], B = ST[keys[Math.min(keys.length - 1, i + 1)]], k = ss(0.55, 1, prog), f = reduce ? 1 : Math.min(1, dt * 2.4);
    for (let j = 0; j < 3; j++) { P.cam[j] = lerp(P.cam[j], lerp(A.cam[j], B.cam[j], k), f); P.tgt[j] = lerp(P.tgt[j], lerp(A.tgt[j], B.tgt[j], k), f); }
    ['roll', 'spread', 'twist', 'fade', 'fov', 'ws'].forEach((n) => (P[n] = lerp(P[n], lerp(A[n], B[n], k), f)));
    const drift = reduce ? 0 : Math.sin(time * 0.3) * 0.04;
    gl.uniform2f(U.uRes, canvas.width, canvas.height); gl.uniform1f(U.uTime, time);
    gl.uniform1f(U.uTan, Math.tan(P.fov * Math.PI / 360)); gl.uniform1f(U.uRoll, P.roll + drift * 0.5);
    gl.uniform1f(U.uSpread, P.spread); gl.uniform1f(U.uWS, P.ws); gl.uniform1f(U.uTwist, P.twist); gl.uniform1f(U.uFade, P.fade); gl.uniform1f(U.uPulse, 1); gl.uniform1f(U.uSoft, LOOK.soft); gl.uniform1f(U.uPx, scale); gl.uniform1f(U.uRainT, rainT);
    if (LOOK.fx.rain) {
      const c0 = rainCols[0].getBoundingClientRect(), c1 = rainCols[1].getBoundingClientRect(), bu = LOOK.rhythm.base;
      const rowH = Math.max(1, Math.round(LOOK.fx.rainSize / bu)) * bu, n = Math.max(1, Math.round(c0.width / rowH));   // near-square cells that fill the column edge to edge
      const pageTop = pageEl.getBoundingClientRect().top;
      gl.uniform4f(U.uRainG, c0.left * scale, c0.width * scale, (c1.left - c0.left) * scale, n);
      gl.uniform2f(U.uRainR, rowH * scale, -pageTop * scale); gl.uniform1f(U.uRainN, rainCols.filter((c) => c.offsetWidth > 0).length);
      trV.fill(0); TR.forEach((r, k) => { const age = time - r.t0; if (age < 0.6) trV.set([r.x * scale, r.y * scale, age, 1], k * 4); }); gl.uniform4fv(trU, trV);
    }
    gl.uniform3f(U.uCam, P.cam[0] + drift, P.cam[1], P.cam[2]); gl.uniform3f(U.uTgt, ...P.tgt);
    {
      // the camera as drawn this frame, for the pointer tests
      Object.assign(CAMS, { ok: true, W: canvas.width, H: canvas.height, th: Math.tan(P.fov * Math.PI / 360), cam: [P.cam[0] + drift, P.cam[1], P.cam[2]], tgt: P.tgt.slice(), roll: P.roll + drift * 0.5, outer: 0.6667 * P.spread + 0.3333 * P.ws, fade: P.fade });
      // the spring: stiffness 90, damping ratio 0.8 (gives, then settles without wobbling), stepped in real time
      const nowS = now / 1000, sdt = Math.min(0.05, HV.t ? Math.max(0, nowS - HV.t) : 0.016); HV.t = nowS;
      HV.v += (-90 * HV.s - 2 * 0.8 * Math.sqrt(90) * HV.v) * sdt; HV.s += HV.v * sdt;
      if (HV.s > 1) { HV.s = 1; HV.v = Math.min(HV.v, 0); }
      const rest = Math.abs(HV.s) < 0.002 && Math.abs(HV.v) < 0.02; if (rest) { HV.s = 0; HV.v = 0; }
      gl.uniform3f(U.uHov, HV.x, HV.s, 1.15);
    }
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    drawNet(now);
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
})();
