# Arkhon Suite design language

`dashboard.html` is the reference prototype for the Command (home) screen, and `tokens.css` is
what the Tauri app imports in Phase 5.

## Source
The tokens come from arkhonindustries.com. Its live `:root` CSS variables were captured on
2026-11-06: graphite `#2b2b2e`, ink `#111113`, mist and steel neutrals, sage `#2f7a55`, the
five-color chart palette, a 0.875rem radius, the brand easing curve and timings, and the
SF Pro/Geist type stack. Nothing here is invented beyond the dark-console extension described below.

## Signature elements (what makes it Arkhon, not a generic dashboard)
| Element | Derived from | Meaning in the product |
|---|---|---|
| **Horizon gauge** | The arc under the logo mark | Draft acceptance rate (N4/N7), flanked by hours returned (N5) and bytes sent to the cloud (N1) |
| **Skyline chart** | The mark's antenna towers | Hours returned per day. An antenna marks a day with zero send-errors |
| **Chrome gradient** | The mark's brushed-metal finish | Used only for brand marks, the gauge, and the current or peak data point |
| **Pill buttons, letter-spaced eyebrows** | Site controls and labels | Primary actions and section labels |
| **"Approve & send" on every item** | Site promise "approve before pay" | Review queue (N9). Nothing leaves without approval |
| **Severity stripe + "Not found in your data" chip** | Site status chips | Honest uncertainty (N4) |
| **Network activity log** | — | Privacy proof shown on the home screen (N1) |

## Rules
- Dark-first console, with a full light theme that matches the site's light tokens one-to-one.
- Semantic colors (sage/amber/red) are for state only and never decorative.
- Numbers use Geist Mono tabular figures.
- Every citation links to its source document. Example data is always labelled.
- Motion: one entrance stagger (70 ms, brand ease). It is fully disabled under `prefers-reduced-motion`.

## Open questions
- An official vector logo. The prototype redraws the mark as SVG from `brand/arkhon-mark-mist.png`. Replace it with the master SVG when one is available.
- Whether Geist is the licensed brand face or only a fallback (the site lists SF Pro Text first; Geist is OFL).
