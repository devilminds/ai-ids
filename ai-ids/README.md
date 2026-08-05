# AI-IDS — AI-Powered Intrusion Detection System

A working full-stack IDS: FastAPI backend with JWT auth, a RandomForest
classifier that scores network flows in real time, automatic alert
generation, and a single-file dashboard.

This is a **real, runnable MVP**, deliberately scoped down from a full
CICIDS2017 + CNN/LSTM + packet-capture system so that every part of it
actually works out of the box. See "Extending this" below for the upgrade
path to the fuller spec.

## What's included

- `backend/app/main.py` — FastAPI app (auth, traffic, alerts, prediction, live WebSocket)
- `backend/app/ml/` — model training (`train.py`) + inference (`predict.py`)
- `backend/app/packet_capture/sniffer.py` — real Scapy capture, run locally
- `backend/app/ws_manager.py` — WebSocket broadcast for the live feed
- `frontend/index.html` — single-file dashboard (no build step, no npm)
- `frontend/config.js` — the one setting to edit when you deploy (backend URL)
- `render.yaml` — one-click backend + Postgres deploy on Render
- `frontend/vercel.json` — frontend deploy config for Vercel

## Live feed and prediction timing

Click **"Start live feed"** in the dashboard: the backend starts a background
loop that generates and scores a new flow every ~2 seconds, and pushes each
one to the dashboard instantly over a WebSocket (`/ws/live`) — no polling
delay. Every prediction is timed (model inference only, not network/DB
overhead) and shown per-flow and as a running average in the "Avg Prediction
Time" stat card. On typical hardware this is single-digit to low-double-digit
milliseconds for the RandomForest baseline.

## Quickstart (local, no Docker)

```bash
cd backend
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Train the ML model (generates a synthetic labeled dataset and trains
# a RandomForest — takes a few seconds, writes app/ml/model.joblib)
python -m app.ml.train

# Start the API (SQLite by default, no config needed)
uvicorn app.main:app --reload --port 8000
```

Open `frontend/index.html` directly in a browser (or `python -m http.server`
from the `frontend/` folder). Log in with the seeded admin account:

- username: `admin`
- password: `Admin@12345`

Click **"Simulate traffic"** to generate flows through the live detection
pipeline and watch alerts/charts populate. Change the admin password before
using this anywhere beyond your own machine.

## Quickstart (Docker)

```bash
cp .env.example .env      # edit JWT_SECRET_KEY and POSTGRES_PASSWORD
docker-compose up --build
```

- API: http://localhost:8000 (docs at `/docs`)
- Dashboard: http://localhost:8080

## Deploying so others can use it (Vercel + Render)

Vercel is great for the static frontend but can't run a persistent Python
WebSocket server, so the split is: **backend on Render, frontend on Vercel.**

### 1. Push to GitHub
Both platforms deploy from a Git repo.
```bash
cd ai-ids
git init && git add . && git commit -m "AI-IDS"
# create a repo on github.com, then:
git remote add origin https://github.com/<you>/ai-ids.git
git push -u origin main
```

### 2. Deploy the backend on Render
- Render Dashboard → New → **Blueprint** → connect your repo.
- Render reads `render.yaml` and provisions the backend + a free Postgres
  database automatically.
- You'll be prompted to set `ADMIN_PASSWORD` — do this now, it won't be
  shown again after.
- Once deployed, copy the backend's URL (e.g. `https://ai-ids-backend.onrender.com`).
- **Check the deploy logs once** on first boot: if you didn't set `ADMIN_PASSWORD`,
  a random one was generated and printed there ONCE — copy it down.

### 3. Point the frontend at the backend
Edit `frontend/config.js`:
```js
: "https://ai-ids-backend.onrender.com";   // <- your actual Render URL
```
Commit and push.

### 4. Deploy the frontend on Vercel
- Vercel Dashboard → Add New → Project → import the same repo.
- Set **Root Directory** to `frontend`.
- Framework preset: "Other" (it's static HTML, no build step).
- Deploy. You'll get a URL like `https://ai-ids.vercel.app`.

### 5. Lock down CORS
Back in Render, set the backend's `CORS_ORIGINS` env var to your exact Vercel
URL instead of `*` (Render Dashboard → your backend service → Environment),
then redeploy. This stops other sites from calling your API.

### Notes
- Render's free tier spins down after inactivity — the first request after
  idling takes ~30-60s to wake back up. Fine for friends/testers, not for
  something that needs to always be instantly available.
- The live feed's WebSocket needs the backend awake — if it's spun down,
  "Start live feed" will fail until the backend wakes up (try again after
  ~30s, or hit the backend's `/health` URL first to nudge it awake).

## API endpoints

| Method | Path                     | Auth | Description                          |
|--------|--------------------------|------|---------------------------------------|
| POST   | `/api/auth/register`     | no   | Create a user, returns a token        |
| POST   | `/api/auth/login`        | no   | Log in, returns a token               |
| GET    | `/api/auth/me`           | yes  | Current user info                     |
| GET    | `/api/traffic/`          | yes  | Recent flows (filter by protocol/label)|
| GET    | `/api/traffic/stats`     | yes  | Dashboard aggregate stats             |
| GET    | `/api/alerts/`           | yes  | Recent alerts (filter by threat_level)|
| POST   | `/api/alerts/{id}/resolve`| yes | Mark an alert resolved                |
| POST   | `/api/predict`           | yes  | Score one flow, logs it, may alert    |
| POST   | `/api/simulate?count=20` | yes  | Generate N demo flows through predict |
| POST   | `/api/live/start`        | yes  | Start the background live-flow generator |
| POST   | `/api/live/stop`         | yes  | Stop the live generator               |
| GET    | `/api/live/status`       | yes  | Whether the live generator is running |
| WS     | `/ws/live?token=<jwt>`   | yes  | Live push of new flows/alerts         |
| GET    | `/api/traffic/top-attackers` | yes | Top source IPs by alert count     |
| GET    | `/api/traffic/timeline`  | yes  | Flow counts per minute, normal vs malicious |

Full interactive docs: `http://localhost:8000/docs`.

## About the ML model

`app/ml/train.py` generates a synthetic dataset with distributions modeled
on real attack shapes (DoS = high packet rate/short duration, port scan =
tiny packets across many low ports, brute force = repeated small requests
to auth ports, etc.) and trains a RandomForest on it. It's a genuinely
working classifier, not a mock — but it's trained on synthetic, well-separated
data, so its ~100% accuracy in testing reflects that, not real-world
performance.

**To train on real data:** download CICIDS2017
(https://www.unb.ca/cic/datasets/ids-2017.html), put a CSV with columns
matching `FEATURES` in `train.py` plus a `label` column into `backend/dataset/`,
then run:

```bash
python -m app.ml.train --csv dataset/your_file.csv
```

## Extending this toward the full original spec

- **Live packet capture**: `app/packet_capture/sniffer.py` is real working
  Scapy code — run it locally with `sudo python -m app.packet_capture.sniffer
  --iface eth0` (needs root + libpcap/npcap). It aggregates packets into
  flows and posts them to `/api/predict`, same pipeline as `/api/simulate`.
- **CNN/LSTM models**: add them alongside the RandomForest in `app/ml/`,
  train on the same feature set, and have `predict.py` pick a model by
  a query param or always ensemble them.
- **React/TypeScript frontend**: the current dashboard is a single HTML
  file on purpose (zero build tooling = zero setup friction). Swapping in
  the React/Vite/Tailwind stack from the original spec is a frontend-only
  change — the API contract above doesn't need to change.
- **Postgres in production**: already wired up via `DATABASE_URL` — see
  `docker-compose.yml`.
- **Reports (PDF/CSV export)**: add a `/api/reports` route that queries
  `TrafficLog`/`Alert` over a date range and renders with a PDF library.

## Security notes before deploying anywhere real

- Change `JWT_SECRET_KEY` and the seeded admin password.
- Lock down `CORS_ORIGINS` to your actual frontend origin instead of `*`.
- Put this behind HTTPS (nginx + TLS, or a platform that terminates TLS for you).
