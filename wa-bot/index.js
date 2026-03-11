// ═══════════════════════════════════════════════════════
//  KY-SHIRO — Baileys WhatsApp OTP Server
//  Developer: KY-SHIRO OFFICIAL | @shiroky1
//  v2 — Support QR + Pairing Code + Admin Panel
// ═══════════════════════════════════════════════════════

const { default: makeWASocket, useMultiFileAuthState,
  DisconnectReason, fetchLatestBaileysVersion } = require("@whiskeysockets/baileys")
const { Boom }  = require("@hapi/boom")
const express   = require("express")
const pino      = require("pino")
const fs        = require("fs")
const qrcode    = require("qrcode")

const PORT       = process.env.PORT         || 3001
const TOKEN      = process.env.WA_BOT_TOKEN || "kyshiro-wa-secret"
const AUTH_DIR   = process.env.AUTH_DIR     || "./wa-auth"
const LOG_LEVEL  = process.env.LOG_LEVEL    || "silent"

const logger = pino({ level: LOG_LEVEL })

// ── State ─────────────────────────────────────────────
let sock            = null
let isReady         = false
let lastQR          = null
let qrDataUrl       = null
let connectAttempts = 0
let waUser          = null
let lastError       = ""
let connectionState = "disconnected"
let _startingWA     = false

const msgQueue = []

// ── Express ───────────────────────────────────────────
const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

function auth(req, res, next) {
  const t = req.headers["x-token"] || req.body?.token || req.query?.token
  if (t !== TOKEN) return res.status(401).json({ status: "error", message: "Token tidak valid" })
  next()
}

// ── Routes ────────────────────────────────────────────

app.get("/status", (req, res) => {
  res.json({
    status:      "ok",
    wa_ready:    isReady,
    has_qr:      !!lastQR,
    state:       connectionState,
    connects:    connectAttempts,
    queue_size:  msgQueue.length,
    wa_user:     waUser || null,
    last_error:  lastError || null,
  })
})

// QR sebagai JSON — untuk embed admin panel
app.get("/qr-json", (req, res) => {
  if (isReady) return res.json({ status: "connected", wa_user: waUser })
  if (!qrDataUrl) return res.json({ status: "waiting", message: "QR belum tersedia. Tunggu 5-10 detik." })
  res.json({ status: "qr", qr_data_url: qrDataUrl })
})

// QR HTML page
app.get("/qr", (req, res) => {
  if (isReady) return res.send(`<!DOCTYPE html><html><head><title>WA Connected</title>
<style>body{background:#080810;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;color:#e8e8ff;flex-direction:column}
.ok{color:#00e887;font-size:32px;margin-bottom:12px}.msg{color:#9090b8;font-size:14px}</style>
</head><body><div class="ok">✅ WhatsApp Connected</div>
<div class="msg">Bot sudah connected sebagai ${waUser?.id || "unknown"}</div></body></html>`)

  if (!qrDataUrl) return res.send(`<!DOCTYPE html><html><head><title>WA Bot - Waiting QR</title>
<meta http-equiv="refresh" content="5"/>
<style>body{background:#080810;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;color:#e8e8ff;flex-direction:column}
.spin{width:40px;height:40px;border:3px solid #1e1e3a;border-top:3px solid #7c6fff;border-radius:50%;animation:s 1s linear infinite;margin-bottom:16px}
@keyframes s{to{transform:rotate(360deg)}}</style>
</head><body><div class="spin"></div>
<div style="color:#7c6fff;font-size:16px">Menunggu QR...</div>
<div style="color:#4a4a7a;font-size:12px;margin-top:8px">Halaman refresh otomatis</div></body></html>`)

  res.send(`<!DOCTYPE html>
<html><head><title>KY-SHIRO WA Bot — Scan QR</title>
<style>
  body{background:#080810;display:flex;align-items:center;justify-content:center;min-height:100vh;flex-direction:column;font-family:sans-serif;color:#e8e8ff}
  h1{font-size:20px;margin-bottom:8px;color:#7c6fff}
  p{color:#9090b8;font-size:14px;margin-bottom:24px;text-align:center}
  img{border:3px solid #7c6fff;border-radius:14px;padding:12px;background:#fff;max-width:300px}
  .badge{margin-top:16px;padding:8px 20px;border-radius:20px;background:rgba(124,111,255,.1);border:1px solid rgba(124,111,255,.2);font-size:13px;color:#7c6fff}
</style></head><body>
  <h1>KY-SHIRO — WhatsApp Bot</h1>
  <p>Buka WhatsApp → Linked Devices → Link a Device<br/>Scan QR berikut:</p>
  <img src="${qrDataUrl}" alt="QR Code"/>
  <div class="badge">Auto refresh tiap 30 detik</div>
  <script>setTimeout(()=>location.reload(),30000)</script>
</body></html>`)
})

// Pairing Code — connect via nomor HP tanpa scan QR
app.post("/pairing", auth, async (req, res) => {
  const { phone } = req.body
  if (!phone) return res.status(400).json({ status: "error", message: "phone wajib" })

  const cleanPhone = String(phone).replace(/[^0-9]/g, "")
  if (!cleanPhone || cleanPhone.length < 10)
    return res.status(400).json({ status: "error", message: "Nomor HP tidak valid. Contoh: 6281234567890" })

  if (isReady)
    return res.json({ status: "ok", message: "WA sudah connected, tidak perlu pairing lagi.", already_connected: true })

  // Kalau belum ada koneksi, mulai dulu
  if (!sock || connectionState === "disconnected") {
    await startWA(true)
    // Tunggu socket siap
    await new Promise(r => setTimeout(r, 4000))
  }

  try {
    if (!sock) return res.status(503).json({ status: "error", message: "WA bot belum siap. Tunggu 5 detik lalu coba lagi." })
    console.log(`[PAIRING] Request pairing code untuk: +${cleanPhone}`)
    const code = await sock.requestPairingCode(cleanPhone)
    const formatted = code?.match(/.{1,4}/g)?.join("-") || code
    console.log(`[PAIRING] ✅ Code: ${formatted}`)
    connectionState = "pairing"
    res.json({
      status:  "ok",
      code:    formatted,
      message: `Kode pairing: ${formatted}`
    })
  } catch (e) {
    console.error(`[PAIRING] ❌ ${e.message}`)
    // Coba restart dan suggest QR
    res.status(500).json({
      status: "error",
      message: `Gagal generate pairing code: ${e.message}. Coba gunakan QR scan sebagai alternatif.`
    })
  }
})

// Send message
app.post("/send", auth, async (req, res) => {
  let { number, message } = req.body
  if (!number || !message) return res.status(400).json({ status: "error", message: "number dan message wajib" })

  number = String(number).replace(/[^0-9]/g, "")
  if (number.startsWith("0")) number = "62" + number.slice(1)
  const jid = number.includes("@") ? number : `${number}@s.whatsapp.net`

  if (!isReady || !sock) {
    msgQueue.push({ jid, message, ts: Date.now() })
    return res.status(202).json({ status: "queued", message: "WA belum ready, pesan masuk antrian", jid })
  }

  try {
    await sock.sendMessage(jid, { text: message })
    console.log(`[SEND] ✅ ${jid}`)
    res.json({ status: "ok", message: "Pesan terkirim", jid })
  } catch (e) {
    console.error(`[SEND] ❌ ${jid}: ${e.message}`)
    // Masukkan ke queue jika gagal
    msgQueue.push({ jid, message, ts: Date.now() })
    res.status(500).json({ status: "error", message: e.message, jid, queued: true })
  }
})

app.post("/flush-queue", auth, async (req, res) => {
  if (!isReady) return res.json({ status: "error", message: "WA belum ready" })
  const pending = [...msgQueue]; msgQueue.length = 0
  let sent = 0, failed = 0
  for (const item of pending) {
    try {
      await sock.sendMessage(item.jid, { text: item.message })
      sent++
      await new Promise(r => setTimeout(r, 500))
    } catch(e) { failed++; console.error(`[QUEUE] gagal ${item.jid}: ${e.message}`) }
  }
  res.json({ status: "ok", sent, failed })
})

app.post("/restart", auth, async (req, res) => {
  console.log("[WA] Manual restart...")
  try { sock?.end() } catch(e) {}
  isReady = false; connectionState = "disconnected"
  lastQR = null; qrDataUrl = null; _startingWA = false
  setTimeout(startWA, 1500)
  res.json({ status: "ok", message: "WA bot restart sedang diproses" })
})

app.post("/logout", auth, async (req, res) => {
  try {
    await sock?.logout()
  } catch(e) {}
  try { fs.rmSync(AUTH_DIR, { recursive: true, force: true }) } catch(e) {}
  isReady = false; sock = null; connectionState = "disconnected"
  lastQR = null; qrDataUrl = null; waUser = null; _startingWA = false
  res.json({ status: "ok", message: "Logout berhasil. Buka Admin Panel untuk connect ulang." })
  setTimeout(startWA, 1500)
})

// ── Baileys Connection ────────────────────────────────
async function startWA(pairingMode = false) {
  if (_startingWA) return
  _startingWA = true
  connectAttempts++
  connectionState = "connecting"
  console.log(`[WA] Connecting... attempt=${connectAttempts} pairingMode=${pairingMode}`)

  if (!fs.existsSync(AUTH_DIR)) fs.mkdirSync(AUTH_DIR, { recursive: true })

  let state, saveCreds, version
  try {
    const authResult = await useMultiFileAuthState(AUTH_DIR)
    state = authResult.state; saveCreds = authResult.saveCreds
    const verResult = await fetchLatestBaileysVersion()
    version = verResult.version
  } catch(e) {
    console.error(`[WA] Init error: ${e.message}`)
    lastError = e.message; _startingWA = false
    setTimeout(() => startWA(pairingMode), 5000)
    return
  }

  try {
    sock = makeWASocket({
      version,
      logger,
      printQRInTerminal: !pairingMode,
      auth: state,
      browser: ["KY-SHIRO Bot", "Chrome", "120.0.0"],
      connectTimeoutMs: 60000,
      defaultQueryTimeoutMs: 30000,
      keepAliveIntervalMs: 25000,
      retryRequestDelayMs: 2000,
      generateHighQualityLinkPreview: false,
      mobile: false,
    })
  } catch(e) {
    console.error(`[WA] makeWASocket error: ${e.message}`)
    lastError = e.message; _startingWA = false
    setTimeout(() => startWA(pairingMode), 5000)
    return
  }

  _startingWA = false

  sock.ev.on("creds.update", saveCreds)

  sock.ev.on("connection.update", async (update) => {
    const { connection, lastDisconnect, qr } = update

    if (qr && !pairingMode) {
      lastQR = qr
      connectionState = "qr"
      try {
        qrDataUrl = await qrcode.toDataURL(qr, { margin: 2, width: 300 })
      } catch(e) { qrDataUrl = null }
      console.log(`[WA] 📷 QR tersedia — buka http://localhost:${PORT}/qr`)
    }

    if (connection === "close") {
      isReady = false; waUser = null
      const reason = new Boom(lastDisconnect?.error)?.output?.statusCode
      const msg = lastDisconnect?.error?.message || "unknown"
      lastError = `${reason}: ${msg}`
      connectionState = "disconnected"
      console.log(`[WA] Closed: reason=${reason} msg=${msg}`)

      if (reason === DisconnectReason.loggedOut || reason === DisconnectReason.badSession) {
        console.log("[WA] Clear auth dan restart...")
        try { fs.rmSync(AUTH_DIR, { recursive: true, force: true }) } catch(e) {}
        lastQR = null; qrDataUrl = null
        setTimeout(startWA, 4000)
      } else if (reason === DisconnectReason.connectionReplaced) {
        setTimeout(startWA, 5000)
      } else {
        const delay = Math.min(5000 * Math.min(connectAttempts, 5), 30000)
        console.log(`[WA] Reconnect dalam ${delay/1000}s...`)
        setTimeout(startWA, delay)
      }
    }

    if (connection === "open") {
      isReady = true; connectAttempts = 0
      connectionState = "connected"; lastError = ""
      lastQR = null; qrDataUrl = null
      waUser = sock.user ? { id: sock.user.id, name: sock.user.name || "" } : null
      console.log(`[WA] ✅ Connected: ${sock.user?.id} (${sock.user?.name || ""})`)

      if (msgQueue.length > 0) {
        console.log(`[WA] Flushing ${msgQueue.length} pesan antrian...`)
        const pending = [...msgQueue]; msgQueue.length = 0
        for (const item of pending) {
          try {
            await sock.sendMessage(item.jid, { text: item.message })
            console.log(`[QUEUE] ✅ ${item.jid}`)
            await new Promise(r => setTimeout(r, 600))
          } catch(e) { console.error(`[QUEUE] ❌ ${item.jid}: ${e.message}`) }
        }
      }
    }
  })

  sock.ev.on("messages.upsert", () => {})
}

// ── Start ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════╗
║       KY-SHIRO WhatsApp OTP Server v2                ║
║  Port   : ${PORT}                                    ║
║  QR     : http://localhost:${PORT}/qr                ║
║  Status : http://localhost:${PORT}/status            ║
╚══════════════════════════════════════════════════════╝`)
  startWA()
})

process.on("SIGINT",  () => { try { sock?.end() } catch(e) {} process.exit() })
process.on("SIGTERM", () => { try { sock?.end() } catch(e) {} process.exit() })
