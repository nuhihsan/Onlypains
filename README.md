# OnlyPains

A phone-first web app for logging gym splits, runs, food and body measurements. It is a single HTML page with no build step, no server and no sign-up.

## What it does

- **Log:** Upper and Lower day workouts with your last weights filled in, a "go up a step" hint when you hit every rep, a weekly day tracker and week streaks.
- **Programs:** Upper/Lower, Full body and Push/Pull/Legs, plus Beginner (full body 3x), Intermediate (upper/lower 4x) and Advanced (PPL 6x) programs with per-exercise sets and reps, built on evidence-based volume, frequency and effort guidelines. The exercise library covers chest, back, shoulders, arms, forearms, legs, glutes and core.
- **Run:** manual entry or import from Strava (GPX or `activities.csv`) and Garmin (TCX). Shows distance, pace, heart rate, cadence, weekly km and pace trend.
- **Food:** type what you ate ("2 roti canai, teh tarik") and calories and protein are estimated from a built-in list of about 180 Malaysian and gym foods. Foods you add yourself are remembered.
- **Progress:** tappable lift charts (top set, est. 1RM or volume over 1M to All, with trend line), hard sets per muscle vs your target, sets and volume per week, personal records, milestones, this period vs last, workout vs workout, run vs run.
- **Friends and groups:** add friends with a code or invite link, make groups for your gym crew, see a feed of each other's workouts, PRs and runs, open a friend's profile, and compete on a weekly group leaderboard. You choose what friends can see; food is never shared. Needs an account.
- **5Ha! and profile photos:** friends give each other a 5Ha! (a high five) on workouts, runs and milestones in the Feed. Add a profile photo under Friends > Your profile.
- **Notifications:** a bell for friend requests (accept or decline right there, or from the pop-up), answers to your requests and people joining your groups. Optional phone notifications even when the app is closed (on iPhone, from the home screen app on iOS 16.4 or later).
- **Versions:** the app shows its version and patch notes in Setup, and a "What's new" card after each update.
- **Body:** weight, height, waist, body fat, BMI (Asian cut-offs), plus the details used to suggest daily calories (Mifflin-St Jeor) and protein by goal.

## Where your data lives

Everything is saved in your browser on your own device (`localStorage`), so the app works offline. Sign in under **Setup > Account** to back your log up to the cloud (a Cloudflare Worker and D1 database, see `worker/README.md`) and use it on any device. Without an account, use **Setup > Your data > Download backup** now and then.

Each friend who opens the link gets their own separate, private log on their own phone. If you add each other as friends (or join the same group), you see a summary of each other's stats: recent workouts, PRs, streak, runs and weekly totals, and body weight only if that person switches it on. Nobody sees your full log or your food.

## Hosting on GitHub Pages

1. Repo **Settings > Pages**.
2. Under **Build and deployment**, set Source to **Deploy from a branch**, Branch **main**, folder **/ (root)**, then **Save**.
3. After a minute the app is live at `https://nuhihsan.github.io/Onlypains/`.

On your phone, open that link and use **Add to Home Screen** (Safari share menu, or Chrome's menu) so it opens like an app and works offline.

## Files

| File | Purpose |
|---|---|
| `index.html` | The whole app (HTML, CSS and JavaScript) |
| `manifest.webmanifest`, `icon*` | Home screen name and icon |
| `sw.js` | Offline support |

Calorie and nutrition figures are rough estimates for typical portions, not medical advice.
