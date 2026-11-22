# Subjedi

Subjedi is a small web application for passive subdomain discovery from public Certificate Transparency and DNS lookup sources, with optional HTTP status checks.

> Use it only for domains you own or are explicitly authorized to assess.

## Features

- Combines results from crt.sh, Cert Spotter, and HackerTarget.
- Normalizes and deduplicates subdomains and shows first-seen dates when available.
- Checks HTTP(S) status for discovered hosts.
- Provides JSON and plain-text search responses.
- Works with any valid apex domain; no allowlist configuration is required.

## Local development

Requirements: Node.js 22 and npm.

```powershell
npm install
```

Then run:

```powershell
npm run dev
```

Open `http://localhost:3000`. To create the production static build, run `npm run build`; `npm start` starts the local server.

## Deploy to Vercel

1. Push this project to GitHub and import the repository in Vercel.
2. Keep the project root at the repository root. Vercel uses `vercel.json` to build the static UI and route `/v1/*` requests to the Node serverless function.
3. Deploy the project. No environment variables are required.

No Google AI Studio, Gemini SDK, or AI API key is used. The UI loads fonts from Google Fonts; this is only a visual styling dependency and is unrelated to Google AI. Searches still require access to the listed passive data providers; no AI service is involved.

The app uses SQLite for caching. Vercel stores this cache under `/tmp`, which is temporary and isolated to a serverless instance; cache entries and statistics are not durable across instance restarts. The app still works without a persistent database.

## API

- `GET /v1/search?apex=example.com&format=json&dates=1`
- `POST /v1/probe` with `{"subdomains":["api.example.com"]}`
- `GET /v1/stats`

Search and probe accept any valid apex domain. Use the tool only for domains you own or are authorized to assess.
