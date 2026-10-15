import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import pg from "pg";
import crypto from "node:crypto";

const { Pool } = pg;
const app = express();
app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(express.json({ limit: "20kb" }));

const required = ["BOT_TOKEN", "ADMIN_CHAT_ID", "PUBLIC_BASE_URL", "SETUP_KEY", "DATABASE_URL", "FRONTEND_ORIGIN", "TELEGRAM_WEBHOOK_SECRET"];
for (const key of required) {
  if (!process.env[key]) console.warn(`Missing environment variable: ${key}`);
}
const env = (key, fallback = "") => process.env[key] || fallback;
const baseUrl = env("PUBLIC_BASE_URL").replace(/\/+$/, "");
const adminChatId = env("ADMIN_CHAT_ID");
const cooldownSeconds = Math.max(15, Number.parseInt(env("REQUEST_COOLDOWN_SECONDS", "15"), 10) || 15);
const turnstileRequired = env("TURNSTILE_REQUIRED", "true").toLowerCase() === "true";
const pool = new Pool({
  connectionString: env("DATABASE_URL"),
  ssl: /sslmode=require/i.test(env("DATABASE_URL")) ? { rejectUnauthorized: false } : undefined,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const allowedOrigins = env("FRONTEND_ORIGIN").split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin(origin, cb) {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error("Origin not allowed by CORS"));
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"],
  maxAge: 600
}));

const ipLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "অনেকবার চেষ্টা করা হয়েছে। কিছুক্ষণ পরে আবার চেষ্টা করুন।" }
});
app.use("/api/requests", ipLimiter);

let schemaReady = false;
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS otp_requests (
      id TEXT PRIMARY KEY,
      phone TEXT NOT NULL,
      phone_hash TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('processing','success','declined')),
      decline_reason TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS otp_requests_phone_created_idx ON otp_requests(phone_hash, created_at DESC);
    CREATE INDEX IF NOT EXISTS otp_requests_created_idx ON otp_requests(created_at DESC);
    CREATE TABLE IF NOT EXISTS admin_pending_reasons (
      admin_chat_id TEXT PRIMARY KEY,
      request_id TEXT NOT NULL REFERENCES otp_requests(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL
    );
  `);
  schemaReady = true;
}
const ready = initDb().catch(err => { console.error("Database initialization failed:", err.message); process.exitCode = 1; });

async function telegram(method, payload) {
  const token = env("BOT_TOKEN");
  if (!token) throw new Error("Telegram bot is not configured");
  const response = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.ok) throw new Error(data.description || `Telegram API error (${response.status})`);
  return data.result;
}
function safePhone(input) {
  if (typeof input !== "string") return null;
  const value = input.trim().replace(/[()\s.-]/g, "");
  if (!/^\+?[1-9]\d{7,14}$/.test(value)) return null;
  return value;
}
function phoneHash(phone) {
  return crypto.createHash("sha256").update(phone).digest("hex");
}
function escapeHtml(s = "") {
  return String(s).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}
async function verifyTurnstile(token, ip) {
  if (!turnstileRequired) return true;
  const secret = env("TURNSTILE_SECRET_KEY");
  if (!secret || !token) return false;
  const body = new URLSearchParams({ secret, response: token });
  if (ip) body.set("remoteip", ip);
  try {
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body });
    const result = await r.json();
    return result.success === true;
  } catch { return false; }
}
async function notifyAdmin(row) {
  const when = new Date(row.created_at).toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
  const text = `📨 <b>Authorized assistance request</b>\n\n🆔 <code>${escapeHtml(row.id)}</code>\n📱 Number: <code>${escapeHtml(row.phone)}</code>\n🕒 Time: ${escapeHtml(when)}\n\nOnly proceed if the requester is authorized. No OTP code is handled by this bot.`;
  await telegram("sendMessage", {
    chat_id: adminChatId, text, parse_mode: "HTML",
    reply_markup: { inline_keyboard: [[
      { text: "✅ DONE", callback_data: `done:${row.id}` },
      { text: "❌ DECLINE", callback_data: `decline:${row.id}` }
    ]] }
  });
}
function requestId() {
  return `REQ-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
}

app.get("/health", async (_req, res) => {
  try {
    await ready;
    await pool.query("SELECT 1");
    res.json({ ok: true, database: schemaReady ? "connected" : "initializing" });
  } catch {
    res.status(503).json({ ok: false, error: "Database unavailable" });
  }
});

app.post("/api/requests", async (req, res) => {
  await ready;
  const phone = safePhone(req.body?.phone);
  if (!phone) return res.status(400).json({ error: "সঠিক country code-সহ ফোন নম্বর লিখুন।" });
  if (req.body?.consent !== true) return res.status(400).json({ error: "অনুমতি/সম্মতির checkbox-এ সম্মতি দিন।" });
  if (!await verifyTurnstile(req.body?.turnstileToken, req.ip)) {
    return res.status(403).json({ error: "Anti-abuse verification ব্যর্থ হয়েছে। আবার চেষ্টা করুন।" });
  }

  const hash = phoneHash(phone);
  const client = await pool.connect();
  let row;
  try {
    await client.query("BEGIN");
    // Advisory lock serializes cooldown checks for this normalized phone.
    const lockKey = BigInt("0x" + hash.slice(0, 15)).toString();
    await client.query("SELECT pg_advisory_xact_lock($1::bigint)", [lockKey]);
    const recent = await client.query(
      "SELECT created_at FROM otp_requests WHERE phone_hash=$1 ORDER BY created_at DESC LIMIT 1",
      [hash]
    );
    if (recent.rowCount) {
      const elapsed = (Date.now() - new Date(recent.rows[0].created_at).getTime()) / 1000;
      if (elapsed < cooldownSeconds) {
        await client.query("ROLLBACK");
        return res.status(429).json({ error: `এই নম্বর থেকে আবার request দিতে ${Math.ceil(cooldownSeconds - elapsed)} সেকেন্ড অপেক্ষা করুন।` });
      }
    }
    const id = requestId();
    const inserted = await client.query(
      "INSERT INTO otp_requests (id, phone, phone_hash, status) VALUES ($1,$2,$3,'processing') RETURNING id, phone, status, created_at",
      [id, phone, hash]
    );
    row = inserted.rows[0];
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Create request failed:", err.message);
    return res.status(500).json({ error: "Request সংরক্ষণ করা যায়নি। কিছুক্ষণ পরে আবার চেষ্টা করুন।" });
  } finally {
    client.release();
  }

  try {
    await notifyAdmin(row);
    res.status(201).json({ id: row.id, status: row.status, createdAt: row.created_at });
  } catch (err) {
    // Keep the request persisted and report the notification failure clearly.
    console.error("Telegram notification failed:", err.message);
    res.status(502).json({ error: "Request database-এ সংরক্ষিত হয়েছে, কিন্তু Telegram notification পাঠানো যায়নি। Admin bot/configuration পরীক্ষা করুন।", id: row.id });
  }
});

app.get("/api/requests/:id", async (req, res) => {
  await ready;
  const id = String(req.params.id || "");
  if (!/^REQ-[A-Z0-9]+-[A-F0-9]{8}$/.test(id)) return res.status(400).json({ error: "Request ID সঠিক নয়।" });
  try {
    const result = await pool.query(
      "SELECT id, status, decline_reason, created_at FROM otp_requests WHERE id=$1",
      [id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "এই Request ID পাওয়া যায়নি।" });
    const row = result.rows[0];
    res.set("Cache-Control", "no-store");
    res.json({
      id: row.id, status: row.status, declineReason: row.decline_reason,
      createdAt: row.created_at
    });
  } catch {
    res.status(503).json({ error: "Status দেখা যাচ্ছে না। কিছুক্ষণ পরে আবার চেষ্টা করুন।" });
  }
});

app.post("/api/admin/setup-webhook", async (req, res) => {
  const supplied = typeof req.body?.setupKey === "string" ? req.body.setupKey : "";
  const expected = env("SETUP_KEY");
  if (!expected || supplied.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))) {
    return res.status(403).json({ error: "Unauthorized" });
  }
  try {
    const result = await telegram("setWebhook", {
      url: `${baseUrl}/api/telegram/webhook`,
      secret_token: env("TELEGRAM_WEBHOOK_SECRET"),
      allowed_updates: ["message", "callback_query"],
      drop_pending_updates: false
    });
    res.json({ ok: true, result });
  } catch (err) {
    res.status(502).json({ error: "Webhook setup failed", detail: err.message });
  }
});

app.post("/api/telegram/webhook", async (req, res) => {
  const incomingSecret = req.get("X-Telegram-Bot-Api-Secret-Token") || "";
  if (!incomingSecret || incomingSecret !== env("TELEGRAM_WEBHOOK_SECRET")) {
    return res.status(403).send("Forbidden");
  }
  // Acknowledge promptly; handlers are short, and errors are logged.
  res.sendStatus(200);
  try {
    await ready;
    const update = req.body || {};
    if (update.callback_query) {
      const q = update.callback_query;
      const chatId = String(q.message?.chat?.id ?? "");
      if (chatId !== String(adminChatId)) {
        await telegram("answerCallbackQuery", { callback_query_id: q.id, text: "Not authorized." });
        return;
      }
      const match = /^(done|decline):(REQ-[A-Z0-9]+-[A-F0-9]{8})$/.exec(q.data || "");
      if (!match) return;
      const [, action, id] = match;
      const found = await pool.query("SELECT id,status FROM otp_requests WHERE id=$1", [id]);
      if (!found.rowCount) {
        await telegram("answerCallbackQuery", { callback_query_id: q.id, text: "Request পাওয়া যায়নি।", show_alert: true });
        return;
      }
      const current = found.rows[0];
      if (current.status !== "processing") {
        await telegram("answerCallbackQuery", { callback_query_id: q.id, text: "এই request ইতিমধ্যে process করা হয়েছে।", show_alert: true });
        return;
      }
      if (action === "done") {
        const updated = await pool.query(
          "UPDATE otp_requests SET status='success', updated_at=NOW() WHERE id=$1 AND status='processing' RETURNING id",
          [id]
        );
        if (updated.rowCount) {
          await telegram("editMessageReplyMarkup", { chat_id: chatId, message_id: q.message.message_id, reply_markup: { inline_keyboard: [] } });
          await telegram("answerCallbackQuery", { callback_query_id: q.id, text: "Marked DONE." });
          await telegram("sendMessage", { chat_id: adminChatId, text: `✅ ${id} marked as Success.` });
        }
      } else {
        await pool.query(
          `INSERT INTO admin_pending_reasons(admin_chat_id,request_id,expires_at)
           VALUES($1,$2,NOW()+INTERVAL '30 minutes')
           ON CONFLICT(admin_chat_id) DO UPDATE SET request_id=EXCLUDED.request_id, expires_at=EXCLUDED.expires_at`,
          [chatId, id]
        );
        await telegram("answerCallbackQuery", { callback_query_id: q.id, text: "Send the decline reason in this chat." });
        await telegram("sendMessage", { chat_id: adminChatId, text: `❌ ${id} decline করতে কারণটি এই chat-এ reply হিসেবে পাঠান। (৩০ মিনিটের মধ্যে)` });
      }
    } else if (update.message && String(update.message.chat?.id ?? "") === String(adminChatId)) {
      const message = update.message;
      const text = (message.text || "").trim();
      if (text.startsWith("/start")) {
        await telegram("sendMessage", { chat_id: adminChatId, text: "OTP Request Manager admin bot ready. New requests appear here with DONE / DECLINE buttons." });
        return;
      }
      if (!text || text.startsWith("/")) return;
      const pending = await pool.query(
        "SELECT request_id FROM admin_pending_reasons WHERE admin_chat_id=$1 AND expires_at>NOW()",
        [String(adminChatId)]
      );
      if (!pending.rowCount) return;
      const id = pending.rows[0].request_id;
      const reason = text.slice(0, 500);
      const updated = await pool.query(
        `UPDATE otp_requests SET status='declined', decline_reason=$2, updated_at=NOW()
         WHERE id=$1 AND status='processing' RETURNING id`,
        [id, reason]
      );
      await pool.query("DELETE FROM admin_pending_reasons WHERE admin_chat_id=$1", [String(adminChatId)]);
      if (!updated.rowCount) {
        await telegram("sendMessage", { chat_id: adminChatId, text: `এই request আর pending নেই: ${id}` });
        return;
      }
      await telegram("sendMessage", { chat_id: adminChatId, text: `❌ ${id} declined. Reason saved.` });
    }
  } catch (err) {
    console.error("Telegram webhook handler failed:", err.message);
  }
});

app.use((err, _req, res, _next) => {
  if (err.message === "Origin not allowed by CORS") return res.status(403).json({ error: "এই website origin অনুমোদিত নয়।" });
  console.error("Unhandled error:", err.message);
  res.status(500).json({ error: "Server error হয়েছে। পরে আবার চেষ্টা করুন।" });
});

const port = Number.parseInt(env("PORT", "3000"), 10);
await ready;
app.listen(port, () => console.log(`OTP Request Manager listening on ${port}`));
