// ═══════════════════════════════════════════════════════════════
//  KY-SHIRO — Telegram Bot Controller
//  Developer: KY-SHIRO OFFICIAL | @shiroky1
//  Fitur:
//    - Kirim OTP via WA (Baileys) dari command Telegram
//    - Admin: lihat status server, logs, SMS
//    - Admin: connect/disconnect/restart WA bot
//    - Webhook ke API utama untuk notifikasi SMS masuk
// ═══════════════════════════════════════════════════════════════

const TelegramBot = require("node-telegram-bot-api")
const express     = require("express")
const fetch       = require("node-fetch")

// ── Config dari ENV ───────────────────────────────────────────
const TG_TOKEN      = process.env.TG_TOKEN      || ""           // Token dari @BotFather
const TG_ADMIN_IDS  = (process.env.TG_ADMIN_IDS || "").split(",").map(x => x.trim()).filter(Boolean)
const API_URL       = process.env.API_URL        || "http://localhost:5000"
const API_KEY       = process.env.API_KEY        || ""          // Opsional: API key admin
const WA_BOT_URL    = process.env.WA_BOT_URL     || "http://localhost:3001"
const WA_BOT_TOKEN  = process.env.WA_BOT_TOKEN   || "kyshiro-wa-secret"
const PORT          = process.env.PORT           || 4000
const WEBHOOK_URL   = process.env.WEBHOOK_URL    || ""          // URL publik bot ini (untuk Telegram webhook)
const BOT_SECRET    = process.env.BOT_SECRET     || "kyshiro-tg-secret"

if (!TG_TOKEN) {
  console.error("❌ TG_TOKEN tidak di-set! Set environment variable TG_TOKEN")
  process.exit(1)
}

// ── Init Bot ──────────────────────────────────────────────────
// Pakai polling (lebih mudah di Railway tanpa setup domain khusus)
const bot = new TelegramBot(TG_TOKEN, { polling: true })

console.log(`
╔══════════════════════════════════════════════════════╗
║       KY-SHIRO Telegram Bot Controller               ║
║  Port     : ${PORT}                                  ║
║  Admin IDs: ${TG_ADMIN_IDS.join(", ") || "belum diset"}
║  API URL  : ${API_URL}                               ║
║  WA URL   : ${WA_BOT_URL}                            ║
╚══════════════════════════════════════════════════════╝`)

// ── Helper ────────────────────────────────────────────────────
function isAdmin(chatId) {
  if (TG_ADMIN_IDS.length === 0) return true // kalau belum set, semua bisa (dev mode)
  return TG_ADMIN_IDS.includes(String(chatId))
}

function adminOnly(msg, cb) {
  if (!isAdmin(msg.chat.id)) {
    bot.sendMessage(msg.chat.id, "⛔ Akses ditolak. Kamu bukan admin.")
    return
  }
  cb()
}

async function waFetch(path, method = "GET", body = null) {
  const opts = {
    method,
    headers: { "Content-Type": "application/json", "x-token": WA_BOT_TOKEN },
  }
  if (body) opts.body = JSON.stringify(body)
  const r = await fetch(`${WA_BOT_URL}${path}`, opts)
  return r.json()
}

async function apiFetch(path, method = "GET", body = null) {
  const opts = {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(API_KEY ? { "x-api-key": API_KEY } : {}),
    },
  }
  if (body) opts.body = JSON.stringify(body)
  const r = await fetch(`${API_URL}${path}`, opts)
  return r.json()
}

function escMd(text) {
  // Escape karakter khusus MarkdownV2
  return String(text || "").replace(/[_*[\]()~`>#+\-=|{}.!\\]/g, "\\$&")
}

function fmtTime(ts) {
  if (!ts) return "-"
  return new Date(ts * 1000).toLocaleString("id-ID", { timeZone: "Asia/Jakarta" })
}

// ── State ─────────────────────────────────────────────────────
const pendingOtp = new Map() // chatId → { step, nomor, otp, nama }

// ── COMMANDS ──────────────────────────────────────────────────

// /start — welcome
bot.onText(/\/start/, (msg) => {
  const nama = msg.from.first_name || "Admin"
  const isAdm = isAdmin(msg.chat.id)
  bot.sendMessage(msg.chat.id,
    `🤖 *KY\\-SHIRO Bot Controller*\n\n` +
    `Halo *${escMd(nama)}*\\!\n` +
    `Chat ID kamu: \`${msg.chat.id}\`\n\n` +
    (isAdm
      ? `✅ *Kamu adalah Admin*\n\nGunakan perintah berikut:\n\n` +
        `📊 /status — Status server & WA bot\n` +
        `📨 /kirim — Kirim OTP via WA\n` +
        `📋 /logs — Lihat API logs terbaru\n` +
        `📱 /sms — Lihat SMS terbaru\n` +
        `🔗 /waconnect — Connect WA via Pairing Code\n` +
        `🔄 /warestart — Restart WA bot\n` +
        `🚪 /walogout — Logout WA bot\n` +
        `❓ /help — Bantuan lengkap`
      : `⛔ Kamu belum terdaftar sebagai admin\\.\n` +
        `Hubungi admin untuk mendaftarkan Chat ID: \`${msg.chat.id}\``
    ),
    { parse_mode: "MarkdownV2" }
  )
})

// /help
bot.onText(/\/help/, (msg) => {
  if (!isAdmin(msg.chat.id)) return
  bot.sendMessage(msg.chat.id,
    `❓ *Daftar Perintah KY\\-SHIRO Bot*\n\n` +
    `*📊 Status & Monitoring*\n` +
    `/status — Status WA bot & server\n` +
    `/logs — 10 API log terbaru\n` +
    `/sms — 5 SMS terbaru yang masuk\n\n` +
    `*📨 Kirim OTP*\n` +
    `/kirim — Mulai kirim OTP interaktif\n` +
    `/kirim 6281234567890 1234 — Kirim OTP langsung\n\n` +
    `*🔗 Kontrol WA Bot*\n` +
    `/waconnect 6281234567890 — Pairing WA via kode\n` +
    `/warestart — Restart WA bot\n` +
    `/walogout — Logout & reset WA bot\n\n` +
    `*ℹ️ Info*\n` +
    `/myid — Lihat Chat ID kamu`,
    { parse_mode: "MarkdownV2" }
  )
})

// /myid
bot.onText(/\/myid/, (msg) => {
  bot.sendMessage(msg.chat.id,
    `🆔 Chat ID kamu: \`${msg.chat.id}\`\n\n` +
    `Berikan ID ini ke admin untuk mendapatkan akses bot\\.`,
    { parse_mode: "MarkdownV2" }
  )
})

// /status — cek WA bot + API server
bot.onText(/\/status/, (msg) => {
  adminOnly(msg, async () => {
    const loadMsg = await bot.sendMessage(msg.chat.id, "⏳ Mengecek status...")
    try {
      const [waStatus, apiStatus] = await Promise.allSettled([
        waFetch("/status"),
        apiFetch("/api/health").catch(() => apiFetch("/"))
      ])

      const wa = waStatus.status === "fulfilled" ? waStatus.value : { wa_ready: false, error: "Tidak bisa connect ke WA bot" }
      const api = apiStatus.status === "fulfilled" ? apiStatus.value : null

      const waIcon = wa.wa_ready ? "✅" : wa.state === "qr" ? "📷" : wa.state === "pairing" ? "🔐" : "❌"
      const waState = wa.wa_ready ? "Connected" : wa.state || "Offline"
      const waUser = wa.wa_user ? `\n👤 WA User: \`${escMd(wa.wa_user.id || "-")}\`` : ""
      const waErr = wa.last_error ? `\n⚠️ Error: ${escMd(wa.last_error)}` : ""
      const waQueue = wa.queue_size > 0 ? `\n📤 Antrian: ${wa.queue_size} pesan` : ""

      const apiIcon = api ? "✅" : "❌"

      bot.editMessageText(
        `📊 *Status KY\\-SHIRO*\n\n` +
        `*🤖 WA Bot*\n` +
        `${waIcon} Status: *${escMd(waState)}*` +
        waUser + waErr + waQueue + `\n\n` +
        `*🌐 API Server*\n` +
        `${apiIcon} Status: *${api ? "Online" : "Offline/Error"}*\n\n` +
        `🕐 _${escMd(new Date().toLocaleString("id-ID", { timeZone: "Asia/Jakarta" }))}_`,
        {
          chat_id: msg.chat.id,
          message_id: loadMsg.message_id,
          parse_mode: "MarkdownV2",
          reply_markup: {
            inline_keyboard: [[
              { text: "🔄 Refresh", callback_data: "refresh_status" },
              { text: "🔗 Connect WA", callback_data: "connect_wa" }
            ]]
          }
        }
      )
    } catch (e) {
      bot.editMessageText(`❌ Error: ${e.message}`, { chat_id: msg.chat.id, message_id: loadMsg.message_id })
    }
  })
})

// /logs — lihat API logs terbaru
bot.onText(/\/logs/, (msg) => {
  adminOnly(msg, async () => {
    const loadMsg = await bot.sendMessage(msg.chat.id, "⏳ Mengambil logs...")
    try {
      const d = await apiFetch("/api/admin/logs?limit=10")
      const logs = d.logs || d.data || []
      if (!logs.length) {
        bot.editMessageText("📋 Belum ada log.", { chat_id: msg.chat.id, message_id: loadMsg.message_id })
        return
      }
      const lines = logs.slice(0, 10).map(l => {
        const time = escMd(l.waktu || l.created_at || "-")
        const method = escMd(l.method || "GET")
        const endpoint = escMd(l.endpoint || l.path || "-")
        const status = l.status_code || l.status || "?"
        const icon = status >= 400 ? "🔴" : status >= 300 ? "🟡" : "🟢"
        return `${icon} \`${method}\` ${endpoint} \\[${status}\\]\n    🕐 ${time}`
      }).join("\n")
      bot.editMessageText(
        `📋 *10 API Log Terbaru*\n\n${lines}`,
        { chat_id: msg.chat.id, message_id: loadMsg.message_id, parse_mode: "MarkdownV2" }
      )
    } catch (e) {
      bot.editMessageText(`❌ Gagal ambil logs: ${escMd(e.message)}`,
        { chat_id: msg.chat.id, message_id: loadMsg.message_id, parse_mode: "MarkdownV2" })
    }
  })
})

// /sms — lihat SMS terbaru
bot.onText(/\/sms/, (msg) => {
  adminOnly(msg, async () => {
    const loadMsg = await bot.sendMessage(msg.chat.id, "⏳ Mengambil SMS terbaru...")
    try {
      const d = await apiFetch("/api/sms/live?limit=5")
      const smsList = d.sms || d.data || []
      if (!smsList.length) {
        bot.editMessageText("📱 Belum ada SMS masuk.", { chat_id: msg.chat.id, message_id: loadMsg.message_id })
        return
      }
      const lines = smsList.slice(0, 5).map((s, i) => {
        const num = escMd(s.number || s.nomor || "-")
        const msg2 = escMd((s.message || s.pesan || "-").slice(0, 80))
        const time = escMd(s.received_at || s.waktu || "-")
        return `*${i+1}\\.* 📞 \`${num}\`\n📝 ${msg2}\n🕐 ${time}`
      }).join("\n\n")
      bot.editMessageText(
        `📱 *5 SMS Terbaru*\n\n${lines}`,
        { chat_id: msg.chat.id, message_id: loadMsg.message_id, parse_mode: "MarkdownV2" }
      )
    } catch (e) {
      bot.editMessageText(`❌ Gagal ambil SMS: ${escMd(e.message)}`,
        { chat_id: msg.chat.id, message_id: loadMsg.message_id, parse_mode: "MarkdownV2" })
    }
  })
})

// /kirim — kirim OTP via WA
// Dua mode: /kirim (interaktif) atau /kirim 6281234567890 123456
bot.onText(/\/kirim(.*)/, (msg, match) => {
  adminOnly(msg, async () => {
    const args = match[1].trim().split(/\s+/).filter(Boolean)

    // Mode langsung: /kirim 6281234567890 123456
    if (args.length >= 2) {
      const nomor = args[0].replace(/[^0-9]/g, "")
      const otp = args[1]
      await doKirimOtp(msg.chat.id, nomor, otp)
      return
    }

    // Mode interaktif
    pendingOtp.set(msg.chat.id, { step: "nomor" })
    bot.sendMessage(msg.chat.id,
      `📨 *Kirim OTP via WhatsApp*\n\nMasukkan nomor WA tujuan:\n_Contoh: 6281234567890 atau 081234567890_`,
      { parse_mode: "MarkdownV2" }
    )
  })
})

// Handle text input untuk flow interaktif kirim OTP
bot.on("message", async (msg) => {
  if (!msg.text || msg.text.startsWith("/")) return
  if (!isAdmin(msg.chat.id)) return

  const state = pendingOtp.get(msg.chat.id)
  if (!state) return

  if (state.step === "nomor") {
    let nomor = msg.text.trim().replace(/[^0-9]/g, "")
    if (nomor.startsWith("0")) nomor = "62" + nomor.slice(1)
    if (nomor.length < 10) {
      bot.sendMessage(msg.chat.id, "❌ Nomor tidak valid. Coba lagi:")
      return
    }
    pendingOtp.set(msg.chat.id, { step: "otp", nomor })
    bot.sendMessage(msg.chat.id,
      `✅ Nomor: \`${nomor}\`\n\nSekarang masukkan kode OTP yang ingin dikirim:`,
      { parse_mode: "MarkdownV2" }
    )

  } else if (state.step === "otp") {
    const otp = msg.text.trim()
    pendingOtp.delete(msg.chat.id)
    await doKirimOtp(msg.chat.id, state.nomor, otp)
  }
})

async function doKirimOtp(chatId, nomor, otp) {
  let cleanNomor = String(nomor).replace(/[^0-9]/g, "")
  if (cleanNomor.startsWith("0")) cleanNomor = "62" + cleanNomor.slice(1)

  const loadMsg = await bot.sendMessage(chatId, `⏳ Mengirim OTP \`${otp}\` ke \`${cleanNomor}\`\\.\\.\\.`,
    { parse_mode: "MarkdownV2" })

  try {
    const pesan = `Halo!\n\nKode OTP kamu: *${otp}*\n\nBerlaku 5 menit. Jangan bagikan ke siapapun.\n\n— KY-SHIRO OFFICIAL`
    const d = await waFetch("/send", "POST", { number: cleanNomor, message: pesan })

    if (d.status === "ok") {
      bot.editMessageText(
        `✅ *OTP Berhasil Dikirim\\!*\n\n📞 Ke: \`${cleanNomor}\`\n🔑 OTP: \`${escMd(otp)}\`\n📤 Status: Terkirim`,
        { chat_id: chatId, message_id: loadMsg.message_id, parse_mode: "MarkdownV2" }
      )
    } else if (d.status === "queued") {
      bot.editMessageText(
        `⏳ *OTP Masuk Antrian*\n\n📞 Ke: \`${cleanNomor}\`\n🔑 OTP: \`${escMd(otp)}\`\n⚠️ WA bot belum ready, pesan akan terkirim saat WA connect`,
        { chat_id: chatId, message_id: loadMsg.message_id, parse_mode: "MarkdownV2" }
      )
    } else {
      bot.editMessageText(
        `❌ *Gagal Kirim OTP*\n\n📞 Ke: \`${cleanNomor}\`\n⚠️ ${escMd(d.message || "Error tidak diketahui")}\n\n_Pastikan WA bot sudah connected_`,
        { chat_id: chatId, message_id: loadMsg.message_id, parse_mode: "MarkdownV2" }
      )
    }
  } catch (e) {
    bot.editMessageText(
      `❌ *Error kirim OTP*\n\n${escMd(e.message)}\n\n_WA bot mungkin offline\\. Cek /status_`,
      { chat_id: chatId, message_id: loadMsg.message_id, parse_mode: "MarkdownV2" }
    )
  }
}

// /waconnect — connect WA via pairing code
bot.onText(/\/waconnect(.*)/, (msg, match) => {
  adminOnly(msg, async () => {
    const args = match[1].trim()
    let nomor = args.replace(/[^0-9]/g, "")

    if (!nomor) {
      bot.sendMessage(msg.chat.id,
        `🔗 *Connect WhatsApp Bot*\n\nGunakan:\n\`/waconnect 6281234567890\`\n\n_Masukkan nomor WA yang akan dijadikan bot OTP_`,
        { parse_mode: "MarkdownV2" }
      )
      return
    }

    if (nomor.startsWith("0")) nomor = "62" + nomor.slice(1)

    const loadMsg = await bot.sendMessage(msg.chat.id,
      `⏳ Meminta pairing code untuk \`${nomor}\`\\.\\.\\.`,
      { parse_mode: "MarkdownV2" }
    )

    try {
      const d = await waFetch("/pairing", "POST", { phone: nomor })

      if (d.status === "ok" && d.code) {
        bot.editMessageText(
          `✅ *Pairing Code Berhasil\\!*\n\n` +
          `📞 Nomor: \`${nomor}\`\n` +
          `🔑 Kode: \`${escMd(d.code)}\`\n\n` +
          `*Cara link WA:*\n` +
          `1\\. Buka WhatsApp di HP\n` +
          `2\\. Tap ⋮ → *Linked Devices*\n` +
          `3\\. Tap *Link with phone number instead*\n` +
          `4\\. Masukkan kode: \`${escMd(d.code)}\`\n\n` +
          `⏰ Kode berlaku \\~60 detik`,
          { chat_id: msg.chat.id, message_id: loadMsg.message_id, parse_mode: "MarkdownV2" }
        )
      } else if (d.already_connected) {
        bot.editMessageText(
          `✅ WA Bot sudah connected\\! Tidak perlu pairing ulang\\.`,
          { chat_id: msg.chat.id, message_id: loadMsg.message_id, parse_mode: "MarkdownV2" }
        )
      } else {
        bot.editMessageText(
          `❌ Gagal mendapatkan pairing code:\n${escMd(d.message || "Error tidak diketahui")}`,
          { chat_id: msg.chat.id, message_id: loadMsg.message_id, parse_mode: "MarkdownV2" }
        )
      }
    } catch (e) {
      bot.editMessageText(
        `❌ Error: ${escMd(e.message)}\n\n_WA bot mungkin offline_`,
        { chat_id: msg.chat.id, message_id: loadMsg.message_id, parse_mode: "MarkdownV2" }
      )
    }
  })
})

// /warestart — restart WA bot
bot.onText(/\/warestart/, (msg) => {
  adminOnly(msg, async () => {
    const loadMsg = await bot.sendMessage(msg.chat.id, "🔄 Merestart WA bot...")
    try {
      const d = await waFetch("/restart", "POST")
      bot.editMessageText(
        d.status === "ok"
          ? `✅ WA bot berhasil direstart\\!\n\n_Tunggu \\~10 detik lalu cek /status_`
          : `❌ Gagal restart: ${escMd(d.message || "-")}`,
        { chat_id: msg.chat.id, message_id: loadMsg.message_id, parse_mode: "MarkdownV2" }
      )
    } catch (e) {
      bot.editMessageText(`❌ Error: ${escMd(e.message)}`,
        { chat_id: msg.chat.id, message_id: loadMsg.message_id, parse_mode: "MarkdownV2" })
    }
  })
})

// /walogout — logout WA bot
bot.onText(/\/walogout/, (msg) => {
  adminOnly(msg, async () => {
    bot.sendMessage(msg.chat.id,
      `⚠️ *Konfirmasi Logout WA*\n\nIni akan disconnect WA bot dan hapus session\\.`,
      {
        parse_mode: "MarkdownV2",
        reply_markup: {
          inline_keyboard: [[
            { text: "✅ Ya, Logout", callback_data: "confirm_walogout" },
            { text: "❌ Batal", callback_data: "cancel_action" }
          ]]
        }
      }
    )
  })
})

// ── Callback Buttons ──────────────────────────────────────────
bot.on("callback_query", async (query) => {
  const chatId = query.message.chat.id
  const msgId = query.message.message_id

  if (!isAdmin(chatId)) {
    bot.answerCallbackQuery(query.id, { text: "⛔ Akses ditolak" })
    return
  }

  bot.answerCallbackQuery(query.id)

  switch (query.data) {

    case "refresh_status": {
      try {
        const wa = await waFetch("/status")
        const waIcon = wa.wa_ready ? "✅" : wa.state === "qr" ? "📷" : "❌"
        const waState = wa.wa_ready ? "Connected" : wa.state || "Offline"
        const waUser = wa.wa_user ? `\n👤 WA User: \`${escMd(wa.wa_user.id || "-")}\`` : ""
        bot.editMessageText(
          `📊 *Status KY\\-SHIRO*\n\n*🤖 WA Bot*\n${waIcon} Status: *${escMd(waState)}*${waUser}\n\n🕐 _${escMd(new Date().toLocaleString("id-ID", { timeZone: "Asia/Jakarta" }))}_`,
          {
            chat_id: chatId, message_id: msgId, parse_mode: "MarkdownV2",
            reply_markup: {
              inline_keyboard: [[
                { text: "🔄 Refresh", callback_data: "refresh_status" },
                { text: "🔗 Connect WA", callback_data: "connect_wa" }
              ]]
            }
          }
        )
      } catch (e) {
        bot.editMessageText(`❌ Error refresh: ${e.message}`, { chat_id: chatId, message_id: msgId })
      }
      break
    }

    case "connect_wa": {
      bot.sendMessage(chatId,
        `🔗 Untuk connect WA, gunakan:\n\n\`/waconnect 6281234567890\`\n\n_Ganti dengan nomor WA yang mau dijadikan bot_`,
        { parse_mode: "MarkdownV2" }
      )
      break
    }

    case "confirm_walogout": {
      try {
        const d = await waFetch("/logout", "POST")
        bot.editMessageText(
          d.status === "ok"
            ? `✅ WA bot berhasil logout\\!\n\nGunakan \`/waconnect\` untuk connect ulang\\.`
            : `❌ Gagal logout: ${escMd(d.message || "-")}`,
          { chat_id: chatId, message_id: msgId, parse_mode: "MarkdownV2" }
        )
      } catch (e) {
        bot.editMessageText(`❌ Error: ${escMd(e.message)}`, { chat_id: chatId, message_id: msgId })
      }
      break
    }

    case "cancel_action": {
      bot.editMessageText("✅ Dibatalkan\\.", { chat_id: chatId, message_id: msgId, parse_mode: "MarkdownV2" })
      break
    }
  }
})

// ── Express server — untuk terima notifikasi SMS dari API ──────
const app = express()
app.use(express.json())

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ok", service: "kyshiro-tg-bot", uptime: process.uptime() })
})

// Webhook: API utama kirim notifikasi SMS masuk ke sini
// API panggil POST /notify/sms saat ada SMS baru
app.post("/notify/sms", (req, res) => {
  const { secret, number, message, source, received_at } = req.body
  if (secret !== BOT_SECRET) return res.status(401).json({ error: "Unauthorized" })

  res.json({ ok: true })

  // Broadcast ke semua admin
  const text =
    `📱 *SMS Baru Masuk\\!*\n\n` +
    `📞 Dari: \`${escMd(number || "-")}\`\n` +
    `💬 Pesan:\n_${escMd((message || "").slice(0, 300))}_\n\n` +
    `🕐 ${escMd(received_at || new Date().toISOString())}`

  const admins = TG_ADMIN_IDS.length > 0 ? TG_ADMIN_IDS : []
  admins.forEach(adminId => {
    bot.sendMessage(adminId, text, { parse_mode: "MarkdownV2" }).catch(() => {})
  })
})

// Webhook: notifikasi WA connect/disconnect
app.post("/notify/wa", (req, res) => {
  const { secret, event, wa_user, error } = req.body
  if (secret !== BOT_SECRET) return res.status(401).json({ error: "Unauthorized" })

  res.json({ ok: true })

  let text = ""
  if (event === "connected") {
    text = `✅ *WA Bot Connected\\!*\n\n👤 User: \`${escMd(wa_user?.id || "-")}\``
  } else if (event === "disconnected") {
    text = `❌ *WA Bot Disconnected*\n\n⚠️ ${escMd(error || "Koneksi terputus")}`
  } else if (event === "qr") {
    text = `📷 *WA Bot menunggu scan QR*\n\nGunakan \`/waconnect\` untuk pairing via kode`
  }

  if (text) {
    const admins = TG_ADMIN_IDS.length > 0 ? TG_ADMIN_IDS : []
    admins.forEach(adminId => {
      bot.sendMessage(adminId, text, { parse_mode: "MarkdownV2" }).catch(() => {})
    })
  }
})

app.listen(PORT, () => {
  console.log(`✅ Express webhook server berjalan di port ${PORT}`)
})

// ── Error handling ─────────────────────────────────────────────
bot.on("polling_error", (err) => {
  console.error("[TG] Polling error:", err.message)
})

process.on("SIGINT",  () => { bot.stopPolling(); process.exit() })
process.on("SIGTERM", () => { bot.stopPolling(); process.exit() })
