# OnlyPains Worker

`onlypains-worker.js` runs on Cloudflare Workers (free plan) and does three things:

- **Accounts:** sign in with Google, or with a username and password (stored only as salted PBKDF2 hashes). One account can have both.
- **Cloud sync:** keeps each user's log in the D1 database `onlypains`, so data survives deleting the app or changing phones.
- **Friends and groups:** friend codes and requests, groups with invite codes, a feed and a weekly leaderboard. Each phone publishes a small summary of its own stats, and the Worker only hands it to that person's friends and group-mates, with whatever they've switched off removed. The tables for this are created automatically the first time someone opens Friends.
- **Notifications:** friend requests, accepted and declined requests and group joins go to the in-app bell (kept 30 days) and, for phones that switched them on, out as phone notifications using standard Web Push. The signing key for Web Push is made automatically the first time and kept in D1, so there are no extra secrets to set.
- **Feedback:** forwards the Feedback tab to Telegram through your bot, tagged with the sender's username and app version.

## Set up (one time)

The D1 database `onlypains` and its tables already exist (`schema.sql` has the table definitions if you ever need to recreate them).

1. **Replace the code.** Cloudflare dashboard > Workers & Pages > `onlypains-feedback` > Edit code. Replace everything with `onlypains-worker.js`, then Deploy.
2. **Connect the database.** Worker > Settings > Bindings > Add > D1 database. Variable name `DB`, database `onlypains`. Save and deploy.
3. **Check the secrets.** Worker > Settings > Variables and Secrets should have `BOT_TOKEN` and `CHAT_ID` (type Secret). To find your chat id: message your bot `/start`, then open `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` and copy the number after `"chat":{"id":`.
4. **Point the app at it.** Put the Worker URL (e.g. `https://onlypains-feedback.<you>.workers.dev`, shown on the Worker's overview page) in `WORKER_URL` in `index.html`.

### Sign in with Google (optional, free)

1. Go to https://console.cloud.google.com and create a project called `OnlyPains`.
2. Open **Google Auth Platform** (APIs & Services > OAuth consent screen) > **Get started**. App name `OnlyPains`, your email as support and contact email, audience **External**. Create.
3. Under **Audience**, press **Publish app** so anyone can sign in (the basic email and profile scopes need no Google review).
4. Under **Clients** > **Create client**: type **Web application**, name `OnlyPains web`, **Authorized JavaScript origins** `https://nuhihsan.github.io`. Create and copy the **Client ID** (ends in `.apps.googleusercontent.com`).
5. In the Worker > Settings > Variables and Secrets, add `GOOGLE_CLIENT_ID` (type Text) with that Client ID, and put the same value in `GOOGLE_CLIENT_ID` in `index.html`.

On the iPhone home screen app, Google's sign-in window can fail to open. Users can sign in with Google once in Safari, add a password under Setup > Account, and use that password in the home screen app.

Only requests from `https://nuhihsan.github.io` are accepted. If you move the app, add the new address to `ALLOWED_ORIGINS`.

## Updating the Worker

When `onlypains-worker.js` changes, repeat step 1 above (Edit code, paste, Deploy). Deploy the Worker **before** merging the app change that needs it, so the app never calls routes that aren't there yet.

## Looking after it

- **Forgotten password:** there is no email reset. Delete the user's sessions and set a new password by signing them up again under a new name, or ask Claude to reset it in D1.
- **Bot token leaked:** send `/revoke` to BotFather and update the `BOT_TOKEN` secret.
- **Free plan limits:** 100,000 Worker requests a day and 5 GB of D1 storage, far more than a group of friends will use.
