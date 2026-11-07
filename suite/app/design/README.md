# Arkhon Suite design language

`dashboard.html` is the reference prototype (v3 of the layout, Horizon v3 visuals) for the Command (home) screen, and `tokens.css` is
what the Tauri app imports in Phase 5.

## Source
The tokens come from arkhonindustries.com. Its live `:root` CSS variables were captured on
2026-11-06: graphite `#2b2b2e`, ink `#111113`, mist and steel neutrals, sage `#2f7a55`, the
five-color chart palette, a 0.875rem radius, the brand easing curve and timings, and the
SF Pro/Geist type stack. Nothing here is invented beyond the dark-console extension described below.

## Direction (v3, 2026-11-06): calm and plain-language
Owner direction: lots of empty space, nothing cluttered, and as non-technical and easy to use as possible.

**Principles**
1. **One idea per band, lots of air.** Home has three bands: greeting + ask box, *Needs you*, *This week*. Each band is separated by 64px or more.
2. **At most three items in "Needs you".** Everything else is handled quietly or lives in its workspace.
3. **No jargon.** No engine names, bytes, TPM, logs, mono type or file paths on the main screens. "Everything stayed on this computer" replaces network stats. Sources read as "Based on your price list and warranty policy".
4. **Big, friendly controls.** 44px+ pill buttons, 17px base type, verbs that say what happens ("Send", "File it", "Answer").
5. **Honest states.** Urgent, Matches order and Not sure pills. "Not sure" means Arkhon didn't guess (N4).
6. **Technical detail is still there, one click away.** The Privacy Center, sources and activity history sit behind links for those who want them.

**Company settings (People · Roles · Teams)** use the rules in `crates/arkhon-org` (ADR-0005):
the seat meter, invites that hold a seat, the plain-language role cards with ✓/– lists, custom roles
(Business+), and teams that add tools without new roles. The prototype mirrors the last-owner and
seat-limit rules and their exact error sentences.

## Wiring (2026-11-06)
Company settings (People, Roles, Teams, Connections, Activity) is wired to the engine:
- `cargo run -p arkhon-suite-dev` serves this page and the engine's API. Every button sends a command, and the engine's rules decide.
- Opened without the server (for example a shared preview link), the page shows a read-only snapshot exported from the engine (`--dump-view`).
- Home, and every customer page, render from the engine view: Email (`#inbox`), Customer replies (`#desk`), Documents (`#docs`), Company answers (`#knowledge`, via `/api/ask`), Meeting notes (`#meetings`), Quotes & marketing (`#growth`), Reports (`#insights`), Value report (`#report`, via `/api/report`), Privacy Center (`#privacy`), Set-up guide (`#welcome`) and Help (`#help`). Workspaces the viewer can't use are absent from the view; every Send / File / Answer is a review-queue command. The example company's content is labelled as sample data.

## Horizon (v4, 2026-11-07): Arkhon's own design system
Built on the Arkhon mark: the split peak, the skyline of antenna bars, and the horizon arc.

**Architecture**
- **Stages.** Every route is a *stage*: an animated hero band, then calm content beneath it.
- **Floating dock.** Navigation lives in a floating dock (bottom centre, icon plus label). It shows only the workspaces the viewer may use. Chat, Company, Help and Search are always there.
- **Command palette.** ⌘K / Ctrl+K jumps to any page, person or action.

**Heroes.** Canvas 2D, DPR-aware, drawn from each page's real numbers:
- a curved horizon with light rising behind it;
- skyline bars, with the busiest day picked out in chrome;
- a slow chrome sheen and drifting grain.

Heroes pause when off screen or when the tab is hidden. Measured: a steady 60 fps (16.7 ms frame interval, headless Chromium). Under `prefers-reduced-motion` the hero is a single still frame (verified pixel-identical).

**Motion**
- A "horizon wipe" between pages (View Transitions API, with a fallback when it isn't available).
- Shared-element morphs.
- Staggered spring-eased entrances, using `cubic-bezier(.22,1,.36,1)` at 560–700 ms.
- All of it off under reduced motion, and content is always readable at rest.

**Chat (`#chat`).** A general assistant like ChatGPT:
- conversations stored in this browser only;
- streaming replies, Stop, Regenerate and Copy;
- markdown with code blocks;
- attaching a text file, which is read on this computer.

`/api/chat` (Server-Sent Events) forwards to the Arkhon runtime's local model when `ARKHON_RUNTIME_URL` is set. Otherwise it answers from company data (with sources) or streams clearly labelled **Demo replies**. Chat content never leaves the computer.

## Horizon v2 (2026-11-07): scenes, reactive heroes, delight
v2 keeps everything above and adds the following. Every new animation follows the same rules: the
first still frame looks finished, nothing moves under `prefers-reduced-motion`, and the hero
pauses when it's off screen or the tab is hidden.

**Scenes.** One hero engine draws a different scene on each page, always from that page's own data:

| Page | Scene | Drawn from |
|---|---|---|
| Home | Skyline of the week, busiest day in chrome | hours given back per day |
| Email | Envelopes arcing over the horizon into a ring with the count | replies waiting / threads |
| Customer replies | Speech glyphs rising; waiting ones in chrome | one glyph per question |
| Documents | A page outline; a light line scans down and each field lights up | fields Arkhon read on the next document to file |
| Company answers | A constellation of source files linking up; the most-cited glows | sources behind the saved answers |
| Meeting notes | A waveform along the horizon with a moving playhead | meeting lengths |
| Quotes & marketing | Bars climbing a rising arc; the biggest line item in chrome | quote line totals |
| Reports | A line chart drawing itself, to scale | the count question (jobs per week) |
| Value report | Skyline of the month by week + count-up totals | weekly hours |
| Privacy Center | A closed dome over the horizon; dots bounce inside, nothing leaves | connections in the activity list |
| Chat | A soft orb breathing on the horizon; faster while a reply streams | streaming state |
| Company pages | A skyline of people: one bar per seat, initials on seats in use | seats and people |
| Set-up guide, Help | The Arkhon mark's skyline | – |

Measured (headless Chromium, 1280×800, 2 s per page): median frame interval 16.7 ms on every
scene (p95 ≤ 16.8 ms); drawing a frame averages 0.17–0.41 ms (worst 3.2 ms). Reduced motion: two
captures 700 ms apart are pixel-identical on all 18 routes.

**Reactive heroes**
- *Pointer light and parallax:* a soft light follows a desktop mouse; the scene shifts by at most 5 px. Off for touch and reduced motion.
- *Time of day:* `dawn` 5–8, `day` 8–17, `dusk` 17–20:30, `night` after that. It tints the hero sky (stars at night) and picks the Home greeting (Good morning / afternoon / evening). Text colours never change, so contrast is unaffected. The example company uses a fixed demo time (9:30), and `?t=HH:MM` overrides the clock, so screenshots and tests are stable.

**Delight**
- Approving a "Needs you" item flies a small copy of the card into the hero horizon (820 ms). It lands with a ring on the horizon, and only then does the count change. This plays only after the engine accepted the command (never in the read-only preview).
- Numbers count up the first time they're shown, and from their old value when they change (900 ms).
- Clearing the last "Needs you" item brings the hero into view and plays a brief chrome-light burst (1.5 s).
- Buttons sink on press and spring back on release. Cards lift 2 px on hover.
- A skeleton shimmer shows while the first view loads.

**Dock and palette**
- The dock's active item is one indicator that glides between items. On a desktop, items near the pointer magnify (up to 1.2×). Tooltips name every item.
- The palette shows *Recent* (the last five things you opened), then *Pages*, *People* and *Actions*. It matches fuzzily (letters in order, e.g. "qts" → Quotes) and highlights the matched letters. A footer shows the keys.

**Chat**
- "Thinking…" shimmers until the first word arrives, then a blinking caret follows the text.
- New messages slide in.
- Code blocks get lightweight syntax colours, from a small inline tokenizer (no libraries).
- You can search your chats, pin them (pinned chats stay on top), and chats get a short automatic title from the first message.
- A scroll-to-bottom button appears when the newest message is out of view.
- *Demo replies* stays labelled whenever no local model is connected.

**Motion tokens (v2)**

| Token | Value | Use |
|---|---|---|
| `--ease` | `cubic-bezier(.22,1,.36,1)` | entrances, wipes |
| `--spring` | `cubic-bezier(.34,1.36,.64,1)` | list entrances, presses |
| `--spring-soft` | `cubic-bezier(.3,1.25,.5,1)` | dock / nav indicator glide, card hover |
| `--dur-press` / `--dur-quick` | 140 / 220 ms | press, hover |
| `--dur-enter` / `--stagger` | 560 / 55 ms | staggered entrances |
| `--dur-wipe` | 760 ms | horizon wipe between pages |
| `--dur-glide` | 420 ms | dock and nav indicator |
| `--dur-count` | 900 ms | count-ups |
| `--dur-fly` | 820 ms | approval fly-in |
| `--dur-burst` | 1500 ms | all-clear burst |

**Horizon everywhere.** The Operator Console (`server/console/index.html`) and the customer portal
(`server/portal/index.html`) use the same tokens, type and motion. Each has:
- a hero band drawn from real numbers: on the console, customers (licenses each) and seats per license; on the portal, computer slots per license, seats, computers by last check-in, and the team;
- a pill nav with the gliding indicator, count-ups, staggered entrances and the horizon wipe.

Both stay inline-only under their strict CSP.

## Horizon v3 (2026-11-07): a world you move through
v3 keeps v1/v2 and puts every page on one place: a lit landscape with the Arkhon mark standing on
its horizon. Each page is a *place* on that horizon, its numbers are built into the land, and moving
between pages flies the camera there. Nothing here changes wording, labels or text colours.

**World model**
- One fixed, full-bleed canvas (`#world`) behind the page. Hero sections are transparent windows onto
  it; below the hero the page content sits on a *veil* (the page colour at 90%) that feathers in over
  160 px, so the land seems to pass under the content.
- The camera has three inputs: *place* (pan along the horizon, one stop per page, 2.4 world units
  apart), *scroll* (the horizon climbs at 0.55× the page speed = a downward tilt, and the ridges dolly
  closer) and, on desktop pointers only, a small parallax from the pointer. Phones get a static camera
  (no gyroscope).
- The *monument* (the mark, extruded) stands far off on the horizon, so it barely moves while the
  camera flies; the data stands on the near land and rides with it.

**Shader pipeline** (hand-written, no libraries; one full-screen triangle, one fragment pass, GLSL ES
1.00 so the same source runs on WebGL2 and WebGL1)
1. *Sky*: the theme's sky tokens, tinted by time of day (dawn / day / dusk / night, same hours and
   `?t=HH:MM` override as v2); sun or crescent moon disc with limb darkening; a Mie-like halo around
   it and a Rayleigh-like band low on the sky; stars with twinkle and slow parallax at night.
2. *Monument*: the mark's two polygons as signed-distance fields (viewBox 120×104). Depth is faked by
   sweeping the shape along the turn (four samples = the side faces); bevel normals come from the SDF
   gradient. The front is the brand's brushed-chrome ramp (#f4f5f7 → #9aa0ab → #3a3d44 → #c9ccd3)
   mixed with a reflection of the same sky (bright horizon line, dark land), fine brushing, a slow
   sheen and a rim light. It turns ±24° every ~37 s and breathes 0.6%.
3. *Terrain*: 3–5 ridge layers of fbm value noise receding to a curved horizon (curvature
   x²/(3·aspect)); aerial haze by depth, a sunlit rim on every ridge, engraved strata lines, and the
   land fades into the page colour.
4. *Haze*: a drifting volumetric band along the horizon (2D noise).
5. *Data as architecture* (from each page's real numbers, via the same `ArkHero.set` calls as v2):

   | Page | In the world |
   |---|---|
   | Home, Value report, Set-up, Help, Company | Antenna towers, one per bar; the busiest day in chrome with a blinking sage tip |
   | Email | One tower per thread; replies waiting are lit |
   | Customer replies, Company answers, Quotes | Towers from tickets / cited sources / quote lines |
   | Documents | One tower per field read; a scan beam sweeps the land and lights each field as it passes |
   | Meeting notes | The nearest ridge becomes the waveform of meeting lengths |
   | Reports | A light trail draws the series across the land, with a comet head |
   | Chat | An aurora (three curtains with rays) that brightens while a reply streams |
   | Privacy Center | A translucent dome closes over the land; activity dots bounce inside it |

   Data light is sage on dark themes and dark sage / graphite on light ones, so it reads on any sky.
   Data height scales with the room between the top of the screen and the horizon, so it never climbs
   into the title.
6. *Events*: the approval fly-in lands with a ring on the horizon; clearing "Needs you" sends a burst.
7. *Post*: film grain and a chromatic vignette (slightly warm-red falloff, cool blue lift).

**Quality tiers** (adaptive; DPR is capped at 1.5 before the tier scale)

| Tier | Resolution | fbm octaves | Ridge layers | Haze | Frame rate |
|---|---|---|---|---|---|
| 0 | 1.0 × DPR (≤1.5) | 5 | 5 | on | 60 |
| 1 | 0.75 × | 4 | 4 | on | 60 |
| 2 | 0.5 × (upscaled by the browser) | 3 | 3 | off | 60 |
| 3 | 0.5 × | 3 | 3 | off | 30 |

Software renderers (SwiftShader, llvmpipe) start at tier 2. Every 45 frames the engine checks the
median GPU time (`EXT_disjoint_timer_query`, where available) against a 12 ms budget, or, without a
timer, the median frame interval against 19 ms, and drops one tier if it's over. It never climbs back
during a visit (no flicker). The loop stops when the tab is hidden, when the page is scrolled past the
hero (the veil covers it; a still frame stays) and under reduced motion. `?q=N` pins a tier (for
screenshots and measurements); `?gl=0` forces the fallback.

**Fallback chain.** WebGL2 → WebGL1 → the v2 Canvas-2D heroes → a static CSS sky gradient on `.hero`.
`html.gl` is only set while the world runs; every v3 world/glass rule is scoped to it, so the
fallbacks look exactly like v2. A lost WebGL context drops back to the 2D heroes.

**Materials**
- *Glass*: cards, the ask box and idea chips are `--glass` (the card colour at 72%) with a 22 px blur
  and 165% saturation, so they pick up the scene's colour.
- *Chrome hairline*: a 1 px masked border (`::after`) with a fixed diagonal sheen plus a radial light
  that follows the pointer (`--mx/--my`, set per card).
- *Embossed numerals*: `--emboss` (one light and one dark 1 px shadow) on hero stats and KPIs.
- *Dock*: a glass capsule (46% card, 26 px blur, 190% saturation) that reflects the world behind it,
  with an inner top highlight, an inner bottom edge, a layered drop shadow and a soft contact shadow.
- *Palette*: a cinematic glass sheet (86% card, 34 px blur) that falls in with a 14° tilt over 520 ms.
- *Cursor*: a soft glow dot that grows into a ring over anything pressable and hides over text fields
  (the native caret cursor shows there). Desktop mouse only; never on touch or under reduced motion.
- *Magnetic buttons*: primary buttons, the ask/send buttons and New chat drift up to 7 px toward the
  pointer (using `translate`, so the press `scale` still works).
- *Type*: hero display 42–80 px, line height 0.98, tracking −0.048em, weight 640, balanced wrapping;
  compact heroes 36–56 px.

**Motion tokens (v3, adds to v2)**

| Token | Value | Use |
|---|---|---|
| camera fly | exponential ease, rate 3.4/s (~1.4 s to settle) | page-to-page flight |
| `--dur-intro` | 2500 ms | first-launch sunrise |
| fold range | scroll 0 → 75vh | hero title folds away |
| rise range | view() entry 0 → 30vh | content bands rise |
| `--magnet` | 7 px | magnetic buttons |
| palette sheet | 520 ms `--ease` | palette entrance |

**Scroll choreography.** The hero title block folds back (perspective 1000 px, up to 32° and −9vh,
fading out) over the first 75vh of scroll; content bands rise 56 px with a slight scale as they enter.
Both use CSS scroll-driven animations (`animation-timeline: scroll()` / `view()`); where those aren't
supported a passive scroll listener sets `--sp` for the fold and the bands simply stay put. Scrolling is
never captured or delayed; at rest (scroll 0) everything is in its final, readable state, and a band in
view is fully opaque (verified).

**Intro (Home, first launch).** A 2.5 s sunrise: the scene starts at pre-dawn exposure, the sun crests
the horizon, the horizon line draws outward from the centre, the towers rise in a stagger and the mark
assembles from light (a noise dissolve with a glowing edge). Then the title and dock fade in. It plays
once (`localStorage['arkhon-intro']`, wrapped in try/catch), only on Home, never under reduced motion.
Skip (a button), any key or any click ends it at once. `?intro=1` replays it, `?intro=0` suppresses it.
The intro clock starts on the first frame actually drawn, and a stalled frame doesn't eat into it.

**Accessibility**
- Hero text sits on a scrim (a soft radial wash of the page colour, 80% light / 76% dark at its core).
  Measured contrast of the hero title and lede against the rendered pixels behind the words (text
  hidden, every 3rd pixel of the text's ink box, minimum reported), Home at dawn/day/dusk/night and
  Email, Documents, Reports, Privacy and Chat, at 1280 and 390, light and dark: title ≥ 9.0:1, lede ≥
  4.8:1.
- Reduced motion: one still frame of the world, no intro, no cursor, no magnet, no fold or rise; two
  captures 700 ms apart are pixel-identical on every route.
- Reduced transparency: cards, ask box, dock, palette and Skip are solid (`--card`, no blur), and the
  page under the hero is solid.
- Focus rings stay visible over glass: the focus outline plus a 6 px page-colour halo.
- "Example company · sample data" and "Demo replies" are unchanged.

**Console and portal (lite).** The same engine (copied inline; no external resources, the strict CSP
is unchanged) runs behind the title band in `lite` mode: towers from the page's numbers, the monument,
terrain and sky, a place per page; glass cards with the pointer-lit edge and embossed KPIs. Without
WebGL the v2 2D band runs as before.

**Sources.** The engine lives in `dashboard.html` between `ark-world:begin` / `ark-world:end`, and the
identical block is inlined in `server/console/index.html` and `server/portal/index.html`. Change all
three together.

## Open questions
- An official vector logo. The prototype redraws the mark as SVG from `brand/arkhon-mark-mist.png`. Replace it with the master SVG when one is available.
- Whether Geist is the licensed brand face or only a fallback (the site lists SF Pro Text first; Geist is OFL).
