// ═══════════════════════════════════════════════════════
//  KY-SHIRO — Baileys WhatsApp OTP Server
//  Developer: KY-SHIRO OFFICIAL | @shiroky1
// ═══════════════════════════════════════════════════════

const { default: makeWASocket, useMultiFileAuthState,
  DisconnectReason, fetchLatestBaileysVersion,
  makeInMemoryStore } = require("@whiskeysockets/baileys")
const { Boom }  = require("@hapi/boom")
const express   = require("express")
const pino      = require("pino")
const fs        = require("fs")
const path      = require("path")
const qrcode    = require("qrcode")

const PORT       = process.env.PORT       || 3001
const TOKEN      = process.env.WA_BOT_TOKEN || "kyshiro-wa-secret"
const AUTH_DIR   = process.env.AUTH_DIR   || "./wa-auth"
const LOG_LEVEL  = process.env.LOG_LEVEL  || "silent"

const logger = pino({ level: LOG_LEVEL })

// ── State ─────────────────────────────────────────────
let sock       = null
let isReady    = false
let lastQR     = null
let qrDataUrl  = null
let connectAttempts = 0

// Queue pesan yg pending saat WA belum ready
const msgQueue = []

// ── Express ───────────────────────────────────────────
const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

// Auth middleware
function auth(req, res, next) {
  const t = req.headers["x-token"] || req.body?.token || req.query?.token
  if (t !== TOKEN) return res.status(401).json({ status: "error", message: "Token tidak valid" })
  next()
}

// ── Routes ────────────────────────────────────────────

// Status
app.get("/status", (req, res) => {
  res.json({
    status:     "ok",
    wa_ready:   isReady,
    has_qr:     !!lastQR,
    connects:   connectAttempts,
    queue_size: msgQueue.length,
  })
})

// QR Code untuk scan
app.get("/qr", (req, res) => {
  if (isReady) return res.json({ status: "ok", message: "Sudah connected, tidak perlu scan QR" })
  if (!qrDataUrl) return res.json({ status: "waiting", message: "QR belum tersedia. Tunggu 5-10 detik lalu refresh." })
  res.send(`<!DOCTYPE html>
<html><head><title>KY-SHIRO WA Bot — Scan QR</title>
<style>
  body{background:#080810;display:flex;align-items:center;justify-content:center;min-height:100vh;flex-direction:column;font-family:sans-serif;color:#e8e8ff}
  h1{font-size:20px;margin-bottom:8px;color:#7c6fff}
  p{color:#9090b8;font-size:14px;margin-bottom:24px;text-align:center}
  img{border:3px solid #7c6fff;border-radius:14px;padding:12px;background:#fff;max-width:280px}
  .badge{margin-top:16px;padding:8px 20px;border-radius:20px;background:rgba(124,111,255,.1);border:1px solid rgba(124,111,255,.2);font-size:13px;color:#7c6fff}
</style>
</head><body>
  <h1>KY-SHIRO — WhatsApp Bot</h1>
  <p>Buka WhatsApp → Linked Devices → Link a Device<br/>Scan QR berikut:</p>
  <img src="${qrDataUrl}" alt="QR Code"/>
  <div class="badge">QR refresh otomatis tiap 60 detik</div>
  <script>setTimeout(()=>location.reload(),30000)</script>
</body></html>`)
})

// Send message (dipakai Flask untuk kirim OTP)
app.post("/send", auth, async (req, res) => {
  let { number, message } = req.body
  if (!number || !message) return res.status(400).json({ status: "error", message: "number dan message wajib" })

  // Normalisasi nomor → format JID WhatsApp
  number = String(number).replace(/[^0-9]/g, "")
  if (number.startsWith("0")) number = "62" + number.slice(1)
  const jid = number.includes("@") ? number : `${number}@s.whatsapp.net`

  if (!isReady || !sock) {
    // Masukkan ke queue, coba lagi nanti
    msgQueue.push({ jid, message, ts: Date.now() })
    return res.status(202).json({ status: "queued", message: "WA belum ready, pesan masuk antrian", jid })
  }

  try {
    await sock.sendMessage(jid, { text: message })
    console.log(`[SEND] ✅ ${jid}`)
    res.json({ status: "ok", message: "Pesan terkirim", jid })
  } catch (e) {
    console.error(`[SEND] ❌ ${jid}: ${e.message}`)
    res.status(500).json({ status: "error", message: e.message, jid })
  }
})

// Flush message queue
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

// Restart koneksi
app.post("/restart", auth, async (req, res) => {
  console.log("[WA] Manual restart...")
  try { sock?.end() } catch(e) {}
  isReady = false
  setTimeout(startWA, 1000)
  res.json({ status: "ok", message: "Restart sedang diproses" })
})

// Logout (clear auth)
app.post("/logout", auth, async (req, res) => {
  try {
    await sock?.logout()
    fs.rmSync(AUTH_DIR, { recursive: true, force: true })
    isReady = false; sock = null
    res.json({ status: "ok", message: "Logout berhasil. Pergi ke /qr untuk scan ulang." })
    setTimeout(startWA, 1000)
  } catch(e) {
    res.json({ status: "error", message: e.message })
  }
})

// ── Baileys Connection ────────────────────────────────
async function startWA() {
  connectAttempts++
  console.log(`[WA] Connecting... (attempt ${connectAttempts})`)

  if (!fs.existsSync(AUTH_DIR)) fs.mkdirSync(AUTH_DIR, { recursive: true })

  const { state, saveCreds } = await useMultiFileAuthState(AUTH_DIR)
  const { version } = await fetchLatestBaileysVersion()

  sock = makeWASocket({
    version,
    logger,
    printQRInTerminal: true,
    auth: state,
    browser: ["KY-SHIRO Bot", "Chrome", "1.0.0"],
    connectTimeoutMs: 30000,
    defaultQueryTimeoutMs: 30000,
    keepAliveIntervalMs: 25000,
    retryRequestDelayMs: 2000,
    generateHighQualityLinkPreview: false,
  })

  sock.ev.on("creds.update", saveCreds)

  sock.ev.on("connection.update", async (update) => {
    const { connection, lastDisconnect, qr } = update

    if (qr) {
      lastQR = qr
      qrDataUrl = await qrcode.toDataURL(qr)
      console.log(`[WA] QR tersedia — buka http://localhost:${PORT}/qr untuk scan`)
    }

    if (connection === "close") {
      isReady = false
      const reason = new Boom(lastDisconnect?.error)?.output?.statusCode
      const msg = lastDisconnect?.error?.message || "unknown"
      console.log(`[WA] Closed: ${reason} — ${msg}`)

      if (reason === DisconnectReason.loggedOut) {
        console.log("[WA] Logged out. Hapus auth dan restart...")
        fs.rmSync(AUTH_DIR, { recursive: true, force: true })
        setTimeout(startWA, 3000)
      } else if (reason === DisconnectReason.badSession) {
        console.log("[WA] Bad session. Clear dan restart...")
        fs.rmSync(AUTH_DIR, { recursive: true, force: true })
        setTimeout(startWA, 3000)
      } else if (reason === DisconnectReason.connectionReplaced) {
        console.log("[WA] Sesi digantikan perangkat lain")
        setTimeout(startWA, 5000)
      } else if (reason === DisconnectReason.timedOut) {
        console.log("[WA] Timeout, reconnect...")
        setTimeout(startWA, 5000)
      } else {
        const delay = Math.min(5000 * connectAttempts, 60000)
        console.log(`[WA] Reconnect dalam ${delay/1000}s...`)
        setTimeout(startWA, delay)
      }
    }

    if (connection === "open") {
      isReady = true
      connectAttempts = 0
      qrDataUrl = null; lastQR = null
      console.log(`[WA] ✅ Connected sebagai: ${sock.user?.id || "unknown"}`)

      // Kirim pesan yang tertunda
      if (msgQueue.length > 0) {
        console.log(`[WA] Flushing ${msgQueue.length} pesan antrian...`)
        const pending = [...msgQueue]; msgQueue.length = 0
        for (const item of pending) {
          try {
            await sock.sendMessage(item.jid, { text: item.message })
            console.log(`[QUEUE] ✅ Terkirim: ${item.jid}`)
            await new Promise(r => setTimeout(r, 600))
          } catch(e) { console.error(`[QUEUE] ❌ ${item.jid}: ${e.message}`) }
        }
      }
    }
  })

  // Abaikan pesan masuk (ini bot kirim saja)
  sock.ev.on("messages.upsert", () => {})
}

// ── Start ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════╗
║       KY-SHIRO WhatsApp OTP Server           ║
║  Port : ${PORT}                               ║
║  QR   : http://localhost:${PORT}/qr           ║
╚══════════════════════════════════════════════╝`)
  startWA()
})

// Graceful shutdown
process.on("SIGINT",  () => { try { sock?.end() } catch(e) {} process.exit() })
process.on("SIGTERM", () => { try { sock?.end() } catch(e) {} process.exit() })
