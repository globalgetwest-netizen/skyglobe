Run SkyGlobe locally on your laptop (with Ollama, free)
This runs the FULL academy on your own computer, using your local Ollama
model instead of Gemini. Zero cost, no quota limits.
One-time setup
1. Install Node.js
Download and install from: https://nodejs.org  (choose the "LTS" version)
2. Make sure Ollama is running
Open PowerShell and run:
```
ollama run llama3.2:3b
```
Leave it running (or it auto-starts as a background service after install).
3. Get the project on your laptop
Download your project folder from GitHub (Code -> Download ZIP), unzip it.
4. Create your .env file
In the project folder, find the file `.env.example`
Make a COPY of it and rename the copy to exactly `.env`
Open `.env` in Notepad and fill in your Supabase values
(copy SUPABASE_URL, SUPABASE_KEY, SESSION_SECRET, ADMIN_PASSWORD
from your Render dashboard -> your service -> Environment tab)
Leave OLLAMA_URL and OLLAMA_MODEL as they are.
5. Install and start
Open PowerShell INSIDE the project folder (Shift + Right-click the folder
-> "Open PowerShell window here"), then run:
```
npm install
npm start
```
You'll see: `Server running on port 3000`
Use it
Open your browser and go to:
```
http://localhost:3000/academy
```
The academy now runs on your laptop, powered by your local Ollama. Free, offline.
To switch back
On Render (the live site), do NOT set OLLAMA_URL -> it keeps using Gemini.
Locally, OLLAMA_URL is set -> it uses Ollama.
The same code automatically picks the right engine.
