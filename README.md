# Timezone App

A small Node.js + Express app that:

- Shows the visitor's current local date/time in the browser.
- Provides `GET /time/:zip` to look up the current date/time for a U.S. ZIP code.
- Provides `GET /health` for a simple health check.

## Run locally

```bash
npm install
npm start
```

Then open:

```text
http://localhost:3000
```

Example API endpoint:

```text
http://localhost:3000/time/84107
```
