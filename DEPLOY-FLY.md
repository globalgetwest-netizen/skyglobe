# Deploy Skyglobe to Fly.io

> Reality check: Fly.io has NO permanent free tier. After a 2-hour / 7-day trial you
> must add a credit card. A tiny always-on machine costs ~$1.94/month. Your database
> stays on Neon — you are only moving where `node server.js` runs.

## Part A — Register
1. Go to https://fly.io and sign up (GitHub or email).
2. Add a credit card when prompted (required after the short trial).

## Part B — Install the CLI (flyctl)
On Windows PowerShell:
```powershell
pwsh -Command "iwr https://fly.io/install.ps1 -useb | iex"
```
Then restart your terminal and check:
```powershell
fly version
fly auth login
```

## Part C — Prepare the app (one-time fix)
Prisma must generate its client during the Docker build. Add a postinstall script so
it runs automatically on every host. In `package.json` add to "scripts":
```json
"postinstall": "prisma generate"
```

## Part D — Launch
From the project folder:
```powershell
cd C:\Users\HP\Skyglobe
fly launch
```
`fly launch` detects Next.js and generates a **Dockerfile** and **fly.toml**. When asked:
- App name: `skyglobe` (or anything free)
- Region: pick one near your Neon DB (Neon here is `us-east-1` -> choose `iad` / US East)
- Postgres/Redis: **No** (your DB is on Neon already)
- Deploy now: **No** (set secrets first)

### Fix the port in fly.toml
Your `server.js` listens on `process.env.PORT` (default 3000). Make sure fly.toml has:
```toml
[http_service]
  internal_port = 3000
  force_https = true
  auto_stop_machines = true    # scale to zero to save money (adds cold starts)
  auto_start_machines = true
  min_machines_running = 0
```
And set `PORT` so it's explicit (Part E).

## Part E — Set secrets (never commit these)
```powershell
fly secrets set `
  DATABASE_URL="postgresql://neondb_owner:...@...neon.tech/neondb?sslmode=require" `
  NEXTAUTH_SECRET="u5eShy36xNIyA5T9MvGVQTjDoPSNDiE7F00W6Ixvqn0=" `
  PORT="3000"
```
Deploy once to learn your URL, then set the login URL and redeploy:
```powershell
fly secrets set NEXTAUTH_URL="https://skyglobe.fly.dev"
```

## Part F — Deploy
```powershell
fly deploy
```
Watch it build (~3-5 min). Then:
```powershell
fly open
```
Socket.IO / WebSockets work over Fly's proxy with no extra config.

## Part G — Connect GitHub (auto-deploy on every push)
Fly has no dashboard git-connect; you use GitHub Actions.

1. Create a deploy token:
   ```powershell
   fly tokens create deploy
   ```
2. In your GitHub repo: Settings -> Secrets and variables -> Actions -> New secret
   - Name: `FLY_API_TOKEN`
   - Value: the token from step 1
3. Add this file to your repo at `.github/workflows/fly-deploy.yml`:
   ```yaml
   name: Deploy to Fly.io
   on:
     push:
       branches: [main]
   jobs:
     deploy:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: superfly/flyctl-actions/setup-flyctl@master
         - run: flyctl deploy --remote-only
           env:
             FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}
   ```
4. Commit and push. From now on, every push to `main` auto-deploys — just like Render.

## Cost control
- `auto_stop_machines = true` + `min_machines_running = 0` = pay only when visited (cold starts).
- Keep it always-on (`min_machines_running = 1`) = ~$1.94/mo, no cold starts.
- Check spend anytime: `fly dashboard` -> Billing.

## Security follow-up
- Rotate your Neon DB password (it was in plaintext), then update the `DATABASE_URL` secret.
- Delete the stray `.env.txt` file.
