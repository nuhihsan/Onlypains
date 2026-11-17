# OnlyPains: rules for every change

## Version and patch notes (required on every update)

Every change that ships to users must, in the same PR:

1. Bump `APP_VERSION` in `index.html`.
   - Minor bump (1.4 -> 1.5) for new features or several changes.
   - Patch bump (1.4 -> 1.4.1) for a bug fix or small tweak only.
   - Major bump (1.x -> 2.0) only for a redesign or a change to how data is stored.
2. Add a new entry at the TOP of `PATCH_NOTES` in `index.html`: `{ v, date: "YYYY-MM-DD", items: [...] }`.
   - Plain, user-facing language, one line per change, no em dashes.
   - Say what the user will notice, not how it was coded.
3. Bump the cache name in `sw.js` (`onlypains-vN` -> `onlypains-vN+1`).

If several PRs are open at once, merge them into one branch so they ship as one version rather than conflicting.

## App basics

- Single file app: `index.html` holds all HTML, CSS and JavaScript. No build step.
- Data lives in the browser (`localStorage`). Never change stored data shapes without a migration in `normCfg`.
- Phone first: check layouts at about 390 px wide.
- Hosted on GitHub Pages from `main`.
