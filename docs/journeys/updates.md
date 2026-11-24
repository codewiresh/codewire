# Updates

The public `/updates` page lists the posts of one Liminal CMS site, newest
first, and the console sidebar links it above Documentation. The contract is
the dashboard row of [`SPEC.md`, section 3](../../SPEC.md#3-components) and
[docs/CONFIGURATION.md, Updates page](../CONFIGURATION.md#updates-page). The
format is in [README.md](README.md). Written first. The page's empty state and
the sidebar link are observed; a published post and the failure states are
not yet observed.

## U1. Reading the posts

- **Entry points:** `/updates` signed in or out; the sidebar's Updates link
  in the console.
- **States to exercise:** posts published; no post published; the CMS down
  after a first read; the CMS down since the dashboard started; the
  deployment without `LIMINAL_ORIGIN` and `LIMINAL_API_KEY`.
- **Driving it:**
  1. With both values set, open `/updates` signed out. Each published post
     shows its title, its date and its body, newest first, at desktop and
     phone widths, in light and dark themes.
  2. Open the console. The sidebar's Updates link sits above Documentation and
     opens the same page.
  3. Publish a post in Liminal. Within five minutes `/updates` shows it.
  4. Make the CMS unreachable from the dashboard. `/updates` still shows the
     posts it last read.
  5. Restart the dashboard while the CMS is unreachable. `/updates` answers
     503 with "Updates can’t be loaded right now."
  6. Unset both values. `/updates` answers 404 and the sidebar has no Updates
     link.
- **Proof:** the post's title on the page matches the title in Liminal, and
  its date is the post's publication date; the 503 and 404 status codes in
  steps 5 and 6.
- **Gotchas:** the dashboard keeps the posts it read for five minutes, so a
  new post can take that long to appear. A post's HTML is cleaned
  again by the dashboard: scripts, styles, forms, frames, relative links and
  images from anywhere but `LIMINAL_MEDIA_ORIGIN` do not appear, by design.
- **Observed:**
  - 2026-11-18 on Dev, source 0ffa5af7aa (#5324 comment 115925): step 1
    signed out with no post published. `/updates` answered 200 with "Nothing
    posted yet.", which shows only after the CMS read succeeds.
  - 2026-11-21 on Production, v0.4.26 (#5324 comment 127888): step 1 signed
    out with no post published, as on Dev.
  - 2026-11-23 on Dev, source a398f53b3c (#5324 comment 135203): step 2
    signed in. The sidebar links Updates to `/updates` directly above
    Documentation, and `/updates` answers 200.
  - Not yet observed: a published post (steps 1 and 3; the site has none),
    step 2 on Production, and steps 4 to 6.
