# Public-site buttons and segmented controls

The public site shares the dashboard's pill treatment for text action buttons.
Independent/Mesh, isolation and pricing selections have a rounded
track and rounded selected segment. The public-site styles and design fixtures
share the same implementation.

## Acceptance journey

Run the design fixture server with `make design-system` and open the homepage
and pricing fixtures at desktop and mobile widths, in light and dark themes.

| Step | Expected behavior | Observation |
| --- | --- | --- |
| Inspect the navigation and closing Request cloud access links on the homepage | Both have fully rounded ends; labels, focus outlines and links remain usable | Local Chromium review and fixture focus/contrast checks passed at desktop/mobile widths in both themes, 2026-11-17 |
| Switch Independent to Mesh and back | The track and both selections have fully rounded ends; the selected fill is inset from the track; one `aria-pressed` value is true, and the diagram caption follows it | Observed in the local Rust application at both widths and themes, 2026-11-17 |
| Change the isolation selection | It uses the same rounded track and selection treatment without hiding its focus outline | Hypervisor/Confidential selection switched in the local application; fixture focus checks passed, 2026-11-17 |
| Change pricing sizes and billing periods | The selected pills remain clear; all presets fit on mobile; the displayed cost changes with the selection | Observed 8 vCPU preset and month selection updating the cost at 390px in the local application; both-width/theme fixture checks passed, 2026-11-17 |
| Tab through action buttons and segmented controls | Focus remains visible, Enter or Space activates buttons, and selection remains readable in both themes | Existing fixture keyboard-focus walk passed at both widths and themes, 2026-11-17. Enter/Space activation was not separately exercised |

The dashboard's existing pill buttons are unchanged. The homepage's column grid,
registration marks and frosted surfaces remain unchanged.

Small command-copy buttons in the docs use `--icon-size-sm` for both the copy
and confirmation glyphs, retaining their existing hit area. Verify that the
smaller glyph is readable before and after copying a quickstart command.

The pricing page's install and prompt copy controls use the same direct-copy
fallback as the homepage. They confirm copying on the control itself and
remain retryable after a failure, without selecting text for a manual copy.

## Local review evidence

On 2026-11-17, the existing design-contract checks for `home.html` and
`pricing.html` passed in Chromium at desktop and mobile widths (four tests).
They checked scale, contrast, horizontal overflow and visible keyboard focus
in both themes. The design-token guard also passed. These static-fixture
checks are supplemented by the local Rust application observations above;
Dev and Production delivery remain unobserved.
