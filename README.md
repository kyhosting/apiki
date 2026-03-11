# KY-SHIRO API Platform

**Developer**: KY-SHIRO OFFICIAL  
**Telegram**: [@shiroky1](https://t.me/shiroky1)  
**Email**: kikimodesad8@gmail.com  
**IG**: @kiki_fzl1

---

## Struktur Project

```
kyshiro/
├── api/              ← Flask Python backend
│   ├── app.py        ← Main app (semua route + proxy iVAS)
│   ├── templates/    ← HTML templates
│   ├── requirements.txt
│   ├── Dockerfile
│   └── vercel.json
├── wa-bot/           ← Node.js Baileys WhatsApp OTP
│   ├── index.js
│   ├── package.json
│   └── Dockerfile
└── docker-compose.yml
```

---

## Deploy VPS (Paling Direkomendasikan)

### 1. Install Docker
```bash
curl -fsSL https://get.docker.com | sh
apt install docker-compose -y
```

### 2. Clone & Setup
```bash
git clone <repo-kamu>
cd kyshiro
cp .env.example .env
nano .env   # isi SECRET_KEY dan WA_BOT_TOKEN
```

### 3. Jalankan
```bash
docker-compose up -d
```

### 4. Scan QR WhatsApp
```
Buka browser → http://IP-VPS:3001/qr
Scan dengan WhatsApp (Linked Devices)
```

### 5. Akses Platform
```
http://IP-VPS:5000
Login: admin / admin123  ← GANTI SEGERA!
```

---

## Deploy Railway / Render

### API (Flask)
1. Push folder `api/` ke GitHub
2. Import di Railway → New Service → GitHub
3. Set env vars:
   - `SECRET_KEY` = random string panjang
   - `WA_BOT_URL` = URL wa-bot service kamu
   - `WA_BOT_TOKEN` = token sama dengan wa-bot
   - `DB_PATH` = /tmp/kyshiro.db

### WA Bot (Node.js)
1. Push folder `wa-bot/` ke GitHub terpisah
2. Import di Railway → New Service → GitHub
3. Set env vars:
   - `WA_BOT_TOKEN` = token kamu
4. Setelah deploy, buka URL Railway + `/qr` untuk scan WA

---

## Deploy Vercel (API saja, tanpa WA bot & WebSocket)
> ⚠ Vercel tidak support WebSocket. SMS Live tidak bisa real-time.
> Gunakan Vercel hanya kalau mau endpoint received/ranges/numbers tanpa live WS.

```bash
cd api
vercel deploy
# Set env di Vercel dashboard
```

---

## Env Variables

| Variable | Deskripsi | Default |
|---|---|---|
| `SECRET_KEY` | Flask secret key | `kyshiro-change-this` |
| `WA_BOT_URL` | URL Baileys server | `http://localhost:3001` |
| `WA_BOT_TOKEN` | Token auth WA bot | `kyshiro-wa-secret` |
| `DB_PATH` | Path SQLite DB | `/tmp/kyshiro.db` |
| `PORT` | Port Flask | `5000` |

---

## Cara Pakai

### 1. Daftar akun
- Buka `/register`
- Isi data + nomor WhatsApp
- Verifikasi OTP yang dikirim ke WA

### 2. Login ke iVAS
- Masuk ke dashboard → **Login iVAS**
- Masukkan email + password akun iVAS **kamu sendiri**
- Sistem akan login ke iVAS dan konek WebSocket otomatis

### 3. Terima SMS
- Dashboard → **SMS Live** untuk SMS real-time
- Atau pakai API Key untuk integrasi external

---

## API Endpoints

Semua butuh header `X-API-Key: ky-xxx` atau `?api_key=ky-xxx`

| Method | Path | Deskripsi |
|--------|------|-----------|
| POST | /api/ivas/login | Login ke iVAS |
| GET | /api/ivas/status | Status koneksi iVAS + WS |
| GET | /api/sms/live | Ambil SMS live (cache WS) |
| GET | /api/sms/live/stream | SSE push stream real-time |
| POST | /api/sms/live/clear | Clear cache SMS live |
| GET | /api/sms/received | Histori SMS per range+nomor |
| GET | /api/ranges | Daftar range aktif |
| GET | /api/numbers | Nomor di range tertentu |
| GET | /api/numbers/my | My Numbers di akun iVAS |
| GET | /api/check-number | Cek ketersediaan nomor |
| POST | /api/numbers/add | Tambah nomor |
| POST | /api/numbers/delete | Hapus nomor |
| POST | /api/ws/reconnect | Reconnect WebSocket |

---

## Contoh Python

```python
import requests, json, sseclient

API_KEY = "ky-xxxxxxxxxxxx"
BASE    = "https://yourdomain.com"
HDRS    = {"X-API-Key": API_KEY}

# Login ke iVAS (sekali saja)
requests.post(f"{BASE}/api/ivas/login",
    data={"ivas_email": "email@kamu.com", "ivas_pass": "password"},
    headers={"Cookie": "session=..."})  # pakai session browser

# Ambil SMS live
r = requests.get(f"{BASE}/api/sms/live", headers=HDRS, params={"limit": 50})
for sms in r.json()["sms"]:
    print(sms["originator"], sms["message"])

# Stream real-time
r = requests.get(f"{BASE}/api/sms/live/stream", headers=HDRS, stream=True)
for ev in sseclient.SSEClient(r):
    if ev.data:
        sms = json.loads(ev.data)
        print("NEW SMS:", sms)

# Ambil ranges
r = requests.get(f"{BASE}/api/ranges", headers=HDRS, params={"from": "2024-01-01", "to": "2024-01-31"})
print(r.json()["ranges"])

# Tambah nomor per range
r = requests.post(f"{BASE}/api/numbers/add", headers=HDRS, json={"range_name": "INDONESIA"})
print(f"Ditambahkan: {r.json()['added']} nomor")
```

---

## Akun Default Admin
```
Username : admin
Password : admin123
```
**GANTI PASSWORD SEGERA setelah login pertama kali!**

---

© 2025 KY-SHIRO OFFICIAL
