# OnlyPains

A phone-first web app for logging gym splits, runs, food and body measurements. It is a single HTML page with no build step, no server and no sign-up.

## What it does

- **Log:** Upper and Lower day workouts with your last weights filled in, a "go up a step" hint when you hit every rep, a weekly day tracker and week streaks.
- **Run:** manual entry or import from Strava (GPX or `activities.csv`) and Garmin (TCX). Shows distance, pace, heart rate, cadence, weekly km and pace trend.
- **Food:** type what you ate ("2 roti canai, teh tarik") and calories and protein are estimated from a built-in list of about 180 Malaysian and gym foods. Foods you add yourself are remembered.
- **Progress:** lift charts, personal records, milestones, this period vs last, workout vs workout, run vs run.
- **Body:** weight, height, waist, body fat, BMI (Asian cut-offs), plus the details used to suggest daily calories (Mifflin-St Jeor) and protein by goal.

## Where your data lives

Everything is saved in your browser on your own device (`localStorage`). Nothing is sent anywhere. Clearing browser data or switching phones loses it, so use **Setup > Your data > Download backup** now and then, and **Restore** to move to another device.

Each friend who opens the link gets their own separate, private log on their own phone.

## Hosting on GitHub Pages

1. Repo **Settings > Pages**.
2. Under **Build and deployment**, set Source to **Deploy from a branch**, Branch **main**, folder **/ (root)**, then **Save**.
3. After a minute the app is live at `https://nuhihsan.github.io/onlypains/`.

On your phone, open that link and use **Add to Home Screen** (Safari share menu, or Chrome's menu) so it opens like an app and works offline.

## Files

| File | Purpose |
|---|---|
| `index.html` | The whole app (HTML, CSS and JavaScript) |
| `manifest.webmanifest`, `icon*` | Home screen name and icon |
| `sw.js` | Offline support |

Calorie and nutrition figures are rough estimates for typical portions, not medical advice.
