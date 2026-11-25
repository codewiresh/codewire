// The before-send hook drops every same-origin referrer, a path-token one included (infra#2677).
import { beforeAll, expect, test } from 'bun:test';

let hook;

beforeAll(async () => {
  globalThis.window = globalThis;
  globalThis.location = new URL('https://codewire.sh/pricing');
  await import('./analytics.js');
  hook = window.codewireAnalyticsBeforeSend;
});

const sent = (referrer) => hook('event', { url: '/pricing', referrer, title: 'Pricing' });

test('a same-origin referrer with a token in its path is dropped', () => {
  const marker = 'path-marker-from-an-emailed-link';
  const payload = sent(`https://codewire.sh/login/link/${marker}`);
  expect(payload.referrer).toBe('');
  expect(JSON.stringify(payload)).not.toContain(marker);
});

test('a relative or unparseable referrer is dropped', () => {
  expect(sent('/reset-password/abc').referrer).toBe('');
  expect(sent('http://[bad').referrer).toBe('');
});

test('another site is kept, and the rest of the event is unchanged', () => {
  const payload = sent('https://example.org/a/post');
  expect(payload).toEqual({ url: '/pricing', referrer: 'https://example.org/a/post', title: 'Pricing' });
});

test('the same host on another scheme or port is still dropped', () => {
  expect(sent('http://codewire.sh/accept-invite/abc').referrer).toBe('');
  expect(sent('https://codewire.sh:8443/x').referrer).toBe('');
});

test('a subdomain is dropped too, and a look-alike host is not one', () => {
  expect(sent('https://preview-3000.example.codewire.sh/t/abc').referrer).toBe('');
  expect(sent('https://notcodewire.sh/x').referrer).toBe('https://notcodewire.sh/x');
});

test('an event without a referrer passes through', () => {
  expect(hook('event', { url: '/' })).toEqual({ url: '/' });
});

// A page inside the account (the server marked the hook's script with its route pattern) sends only
// that pattern and a fixed title, never its own address or title.
const onPage = (route, send) => {
  globalThis.document = {
    querySelector: (selector) =>
      selector === 'script[data-analytics-route]' && route ? { dataset: { analyticsRoute: route } } : null,
  };
  try { return send(); } finally { delete globalThis.document; }
};

test('a page inside the account sends its route pattern and a fixed title', () => {
  const payload = onPage('/:slug/:environment_id/', () =>
    hook('event', { url: 'https://codewire.sh/acme-corp/sandbox-0123/', title: 'payments-api · Acme Corp', referrer: '' }));
  expect(payload.url).toBe('https://codewire.sh/:slug/:environment_id/');
  expect(payload.title).toBe('Codewire');
  expect(JSON.stringify(payload)).not.toContain('acme');
  expect(JSON.stringify(payload)).not.toContain('payments-api');
});

test('a public page, with no route on its script, keeps its address and title', () => {
  const payload = onPage(null, () => hook('event', { url: 'https://codewire.sh/pricing', title: 'Pricing' }));
  expect(payload).toEqual({ url: 'https://codewire.sh/pricing', title: 'Pricing' });
});
