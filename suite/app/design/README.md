# Arkhon Suite design language

`dashboard.html` is the reference prototype (v2) for the Command (home) screen, and `tokens.css` is
what the Tauri app imports in Phase 5.

## Source
The tokens come from arkhonindustries.com. Its live `:root` CSS variables were captured on
2026-11-06: graphite `#2b2b2e`, ink `#111113`, mist and steel neutrals, sage `#2f7a55`, the
five-color chart palette, a 0.875rem radius, the brand easing curve and timings, and the
SF Pro/Geist type stack. Nothing here is invented beyond the dark-console extension described below.

## Direction (v2, 2026-11-06)
The owner asked for a look much closer to modern developer and AI products: monochrome,
hairline-bordered, dense, with a conversational composer as the centerpiece. We borrow that
*design language* only, with no third-party logos, names or assets. Arkhon's own identity comes
through the brand tokens, Geist type, and the chrome mark.

| Element | Role |
|---|---|
| Top bar: mark / company switcher, underline workspace tabs | Navigation (N3: one suite) |
| **Composer** ("Ask about your jobs, customers, bills or files…") with a scope chip and an "On this PC" indicator | Ask the company (N2: no blank-chat expertise, thanks to suggestions; N1) |
| Grounded answer card with citations | N4 |
| One-box metric strip with hairline dividers | Value Dashboard (N5) and cloud bytes = 0 (N1) |
| Dense review-queue rows: tag, title, state dot, mono citations, Approve | N9, N4 |
| **Skyline** chart (the mark's antenna bars, chrome on peak and today) | Hours returned (N5) |
| Network log | Privacy Center preview (N1) |

## Rules
- Pure black/white surfaces, neutral greys, 1px hairlines. Color is used only for state (ok/warn/bad/info).
- The chrome gradient appears only on the mark, avatars, and the highlighted data points.
- Numbers, citations and logs use Geist Mono with tabular figures.
- Example data is always labelled. The composer answer in the prototype is a canned example.
- Motion: a 4px rise on load and bar growth. Both are disabled under `prefers-reduced-motion`.

## Open questions
- An official vector logo. The prototype redraws the mark as SVG from `brand/arkhon-mark-mist.png`. Replace it with the master SVG when one is available.
- Whether Geist is the licensed brand face or only a fallback (the site lists SF Pro Text first; Geist is OFL).
