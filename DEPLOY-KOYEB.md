# Deploy Skyglobe to Koyeb (free, no card, no sleep)

Your database already lives on **Neon** — you are only moving where `node server.js` runs.
Nothing about your data changes.

## Step 0 — Push code to GitHub (one time)
Koyeb deploys from a GitHub repo, just like Render did.

```bash
cd C:/Users/HP/Skyglobe
git init
git add .
git commit -m "Skyglobe app"
# create an empty repo on github.com first, then:
git remote add origin https://github.com/<your-username>/skyglobe.git
git push -u origin main
```

The updated `.gitignore` keeps `.env`, `.env.txt`, and secrets OUT of the push. Good.

## Step 1 — Create the Koyeb service
1. Go to https://app.koyeb.com and sign up with GitHub (no credit card).
2. **Create Web Service** -> **GitHub** -> pick your `skyglobe` repo.
3. Builder: **Buildpack** (auto). Set:
   - **Build command:** `npm install && npx prisma generate && npm run build`
   - **Run command:** `npm start`
4. Instance: **Free** (Nano).

## Step 2 — Port
Koyeb sets the `PORT` env var automatically (default 8000). Your `server.js` already
reads `process.env.PORT`, so it just works. In the Koyeb "Exposing your service"
section, make sure the port matches what Koyeb injects (leave default 8000).

## Step 3 — Environment variables (add these in Koyeb dashboard)
| Name | Value |
|------|-------|
| `DATABASE_URL` | your Neon connection string (same as local `.env`) |
| `NEXTAUTH_SECRET` | `u5eShy36xNIyA5T9MvGVQTjDoPSNDiE7F00W6Ixvqn0=` |
| `NEXTAUTH_URL` | your Koyeb app URL, e.g. `https://skyglobe-<org>.koyeb.app` |

> Deploy once first to learn your `*.koyeb.app` URL, then set `NEXTAUTH_URL`
> to that exact URL and redeploy. NextAuth login breaks if this is wrong.

## Step 4 — Deploy
Click **Deploy**. First build ~3-5 min. Every future `git push` auto-deploys,
same as Render.

---

## IMPORTANT security follow-ups
- Your Neon DB password (`npg_Lb9dyg8UYDOh...`) was sitting in plaintext files.
  Rotate it in the Neon dashboard (Roles -> reset password), then update
  `DATABASE_URL` locally and in Koyeb.
- You can delete the stray `.env.txt` file — it duplicates `.env` and only
  adds leak risk. `.env` is all you need.
