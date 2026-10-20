// A flaky Kind dashboard test leaves the blocking suite only through this
// helper. It names the issue that owns the fix and the last day of the
// quarantine, at most 30 days ahead. Until then the test carries @quarantine:
// the Kind browser gate runs it after the blocking suite and reports its
// result without failing (scripts/ci/verify/kind/common.sh
// dashboard_browser_e2e). From the next day it blocks again by itself (#2975).
//
//   test("title", quarantine(2990, "2026-11-03"), async ({ page }) => { ... });

export const QUARANTINE_TAG = "@quarantine";
export const QUARANTINE_MAX_DAYS = 30;

type Details = { tag: string[]; annotation: { type: string; description: string }[] };

const day = 24 * 60 * 60 * 1000;

export function quarantine(issue: number, until: string, tags: string[] = [], today = new Date()): Details {
  if (!Number.isInteger(issue) || issue <= 0) {
    throw new Error(`quarantine needs the issue that owns the fix, not ${issue}`);
  }
  const end = /^\d{4}-\d{2}-\d{2}$/.test(until) ? Date.parse(`${until}T00:00:00Z`) : Number.NaN;
  if (Number.isNaN(end) || new Date(end).toISOString().slice(0, 10) !== until) {
    throw new Error(`quarantine of #${issue} needs its last day as YYYY-MM-DD, not ${until}`);
  }
  const start = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate());
  if (end - start > QUARANTINE_MAX_DAYS * day) {
    throw new Error(`quarantine of #${issue} ends ${until}, more than ${QUARANTINE_MAX_DAYS} days ahead`);
  }
  if (tags.includes(QUARANTINE_TAG)) {
    throw new Error(`quarantine of #${issue} adds ${QUARANTINE_TAG} itself`);
  }
  const active = start <= end;
  return {
    tag: active ? [...tags, QUARANTINE_TAG] : [...tags],
    annotation: [{
      type: "quarantine",
      description: active ? `#${issue} until ${until}` : `#${issue} ended ${until}; blocking again`,
    }],
  };
}
