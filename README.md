# KY-SHIRO — iVAS SMS Platform

Platform SMS berbasis iVAS dengan dashboard real-time, WebSocket live SMS, dan OTP via WhatsApp.

**Developer:** KY-SHIRO OFFICIAL | **Telegram:** [@shiroky1](https://t.me/shiroky1)

---

## 🚀 Panduan Deploy

### ✅ Opsi 1: Railway (Recommended — Gratis, Auto Deploy)

1. Push project ke GitHub
2. Buka [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub Repo**
3. Pilih repo kamu — Railway otomatis detect `Dockerfile` di root + `railway.json`
4. Set Environment Variables di Railway dashboard:
   ```
   SECRET_KEY    = (random string panjang)
   WA_BOT_TOKEN  = kyshiro-wa-secret
   DB_PATH       = /data/kyshiro.db
   ```
5. Klik **Deploy** ✅

> WA Bot perlu service terpisah di Railway — tambahkan service baru dari folder `wa-bot/`.

---

### ✅ Opsi 2: VPS dengan Docker Compose (Full Stack)

Cocok untuk deploy Flask API + WA Bot sekaligus dalam satu server.

```bash
# Upload project ke VPS, lalu:
cd kyshiro

# Buat file .env
cp .env.example .env
nano .env   # isi SECRET_KEY dan WA_BOT_TOKEN

# Build dan jalankan
docker-compose up -d --build

# Cek logs
docker-compose logs -f api
```

**Akses:** Flask API di `http://your-vps-ip:5000`

---

### ✅ Opsi 3: Render.com

1. Push ke GitHub
2. Render → **New Web Service** → Connect repo
3. Settings:
   - **Environment:** Docker
   - **Dockerfile Path:** `./Dockerfile`
   - **Health Check:** `/health`
4. Set env vars: `SECRET_KEY`, `WA_BOT_TOKEN`, `DB_PATH=/tmp/kyshiro.db`
5. Deploy ✅

---

### ✅ Opsi 4: Heroku / Dokku / Coolify

Platform yang support `Procfile`:

```bash
heroku create nama-app
heroku config:set SECRET_KEY=ganti-ini WA_BOT_TOKEN=kyshiro-wa-secret DB_PATH=/tmp/kyshiro.db
git push heroku main
```

---

## 📁 Struktur Project

```
kyshiro/
├── Dockerfile          ← Root Dockerfile (Railway/Render)
├── railway.json        ← Config Railway
├── render.yaml         ← Config Render.com
├── Procfile            ← Heroku/Dokku/Coolify
├── docker-compose.yml  ← VPS full stack (API + WA Bot)
├── api/
│   ├── app.py
│   ├── requirements.txt
│   ├── Dockerfile      ← Dipakai docker-compose
│   ├── templates/
│   └── static/
└── wa-bot/
    ├── index.js
    ├── package.json
    └── Dockerfile
```

---

## ⚙️ Environment Variables

| Variable | Default | Keterangan |
|---|---|---|
| `SECRET_KEY` | `kyshiro-change-this` | Flask session secret (**wajib ganti!**) |
| `WA_BOT_URL` | `http://localhost:3001` | URL WA Bot |
| `WA_BOT_TOKEN` | `kyshiro-wa-secret` | Token auth WA Bot |
| `DB_PATH` | `/tmp/kyshiro.db` | Path database SQLite |
| `PORT` | `5000` | Port Flask (auto-set Railway/Render) |

---

## 🔐 Login Default Admin

```
Username : ADMINKIKI
Password : KIKI2008
```

> ⚠️ **Ganti password admin segera setelah deploy pertama!**

---

## 🤖 Setup WhatsApp Bot

1. Akses `/admin` di dashboard
2. Menu **WA Bot** → pilih metode pairing:
   - **QR Code:** Scan dengan WhatsApp
   - **Pairing Code:** Masukkan nomor HP

---

## 📡 API Endpoints

Semua endpoint butuh header `X-API-Key` atau login session.

| Method | Endpoint | Keterangan |
|---|---|---|
| GET | `/api/sms/live` | My SMS real-time |
| GET | `/api/sms/test` | Test SMS publik |
| GET | `/api/sms/received` | SMS dari range+number |
| GET | `/api/sms/otp` | Extract OTP dari SMS |
| GET | `/api/ranges` | Daftar range iVAS |
| GET | `/api/numbers/test-list` | Test numbers |
| GET | `/api/numbers/my-list` | My numbers |
| POST | `/api/numbers/add` | Add number |
| POST | `/api/numbers/delete` | Delete number |
| GET | `/health` | Health check |

Dokumentasi lengkap: `/dashboard/docs`
