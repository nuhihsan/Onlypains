# Feedback relay

`feedback-worker.js` runs on Cloudflare Workers and forwards feedback from the app's Feedback tab to your Telegram through your bot. The bot token stays in Cloudflare as a secret and is never in the app or this repo.

## Set up

1. **Create the Worker.** Cloudflare dashboard > Workers & Pages > Create > Create Worker. Name it `onlypains-feedback`, Deploy, then Edit code. Replace everything with `feedback-worker.js` and Deploy.
2. **Let the bot message you.** In Telegram, open your bot and send it `/start`.
3. **Find your chat id.** In a browser, open `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` (your token in place of `<YOUR_TOKEN>`). Find `"chat":{"id":123456789` and copy the number.
4. **Add the secrets.** Worker > Settings > Variables and Secrets > Add, type **Secret**: `BOT_TOKEN` (from BotFather) and `CHAT_ID` (from step 3). Deploy.
5. **Point the app at it.** Put the Worker URL (e.g. `https://onlypains-feedback.<you>.workers.dev`) in `FEEDBACK_URL` in `index.html`.

Only requests from `https://nuhihsan.github.io` are accepted. If you move the app to another address, add it to `ALLOWED_ORIGINS`.

If the token ever leaks, send `/revoke` to BotFather and update the `BOT_TOKEN` secret.
