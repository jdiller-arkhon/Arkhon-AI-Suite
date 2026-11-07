# Arkhon Suite design language

`dashboard.html` is the reference prototype (v3) for the Command (home) screen, and `tokens.css` is
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

## Open questions
- An official vector logo. The prototype redraws the mark as SVG from `brand/arkhon-mark-mist.png`. Replace it with the master SVG when one is available.
- Whether Geist is the licensed brand face or only a fallback (the site lists SF Pro Text first; Geist is OFL).
