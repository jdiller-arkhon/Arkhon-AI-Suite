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

## Open questions
- An official vector logo. The prototype redraws the mark as SVG from `brand/arkhon-mark-mist.png`. Replace it with the master SVG when one is available.
- Whether Geist is the licensed brand face or only a fallback (the site lists SF Pro Text first; Geist is OFL).
