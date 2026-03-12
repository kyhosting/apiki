# KY-SHIRO Telegram Bot Controller

Bot Telegram untuk admin KY-SHIRO — kontrol WA bot dan kirim OTP.

## Setup di Railway

1. **New Service** → GitHub Repo → sama dengan repo api
2. Settings → **Root Directory**: `tg-bot`
3. Set **Environment Variables**:

| Variable | Keterangan |
|---|---|
| `TG_TOKEN` | Token bot dari @BotFather (**WAJIB**) |
| `TG_ADMIN_IDS` | Chat ID admin, pisah koma. Gunakan `/myid` untuk cari |
| `WA_BOT_URL` | URL service wa-bot Railway |
| `WA_BOT_TOKEN` | Token wa-bot (default: `kyshiro-wa-secret`) |
| `API_URL` | URL service api Railway |
| `BOT_SECRET` | Secret webhook SMS (default: `kyshiro-tg-secret`) |

4. **Deploy** → tunggu Active
5. Set di service **api**: `TG_BOT_URL=https://tg-bot-xxx.up.railway.app`
6. Set di service **api**: `TG_BOT_SECRET=kyshiro-tg-secret`

## Commands Bot

| Command | Fungsi |
|---|---|
| `/start` | Welcome & daftar perintah |
| `/myid` | Lihat Chat ID kamu |
| `/status` | Status WA bot & server |
| `/kirim 6281234567890 123456` | Kirim OTP via WA |
| `/logs` | 10 API log terbaru |
| `/sms` | 5 SMS terbaru |
| `/waconnect 6281234567890` | Pairing WA via kode |
| `/warestart` | Restart WA bot |
| `/walogout` | Logout WA bot |

## Flow Kirim OTP

```
User request OTP di website
  → API Flask kirim ke WA bot (Baileys)
  → WA bot kirim pesan ke nomor user
  → API juga notify TG bot
  → Admin TG dapat notifikasi SMS masuk
```
