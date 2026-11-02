// The theme: system (the default), light or dark. One choice for the whole origin: the public site, the
// sign-in pages and the dashboard. Every page loads this in <head> without defer, so the choice applies
// before the first paint. The stylesheets read data-theme on <html>; with none they follow the system.
(() => {
  const KEY = 'codewire-theme';
  const NEXT = { system: 'light', light: 'dark', dark: 'system' };
  const NAMES = { system: 'System', light: 'Light', dark: 'Dark' };
  const root = document.documentElement;
  let choice = 'system';
  try { const saved = localStorage.getItem(KEY); if (saved in NEXT) choice = saved; } catch (e) {}
  const apply = () => { if (choice === 'system') root.removeAttribute('data-theme'); else root.setAttribute('data-theme', choice); };
  apply();

  // A switch is any [data-theme-switch] button. One with a [data-theme-label] shows its state as text, which is
  // also its name; an icon-only switch is named by aria-label. data-theme-current picks the icon in CSS.
  const sync = () => document.querySelectorAll('[data-theme-switch]').forEach((button) => {
    button.dataset.themeCurrent = choice;
    const label = button.querySelector('[data-theme-label]');
    if (label) label.textContent = 'Theme: ' + NAMES[choice];
    else button.setAttribute('aria-label', 'Theme: ' + NAMES[choice] + '. Switch theme');
  });
  document.addEventListener('click', (event) => {
    const button = event.target instanceof Element ? event.target.closest('[data-theme-switch]') : null;
    if (!button) return;
    choice = NEXT[choice];
    try { localStorage.setItem(KEY, choice); } catch (e) {}
    apply();
    sync();
    document.dispatchEvent(new CustomEvent('codewire:themechange', { detail: { choice } }));
  });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', sync); else sync();
  // htmx can replace the sidebar; its new switch starts at the template's default until synced
  document.addEventListener('htmx:afterSettle', sync);
})();
