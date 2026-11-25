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
