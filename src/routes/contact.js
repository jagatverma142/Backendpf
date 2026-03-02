const path = require("path");
const crypto = require("crypto");
const { readJson, writeJsonAtomic } = require("../lib/jsonStore");
const express = require("express");
const rateLimit = require("express-rate-limit");
const { sanitizeText, isValidEmail } = require("../lib/sanitize");
const { sendContactEmail } = require("../lib/mailer");

const router = express.Router();

// 🔹 messages.json path
const messagesPath = path.join(__dirname, "..", "..", "data", "messages.json");

// 🔹 Optional: anonymize IP
function anonymizeIp(ip) {
  const salt = process.env.LOG_SALT || process.env.JWT_SECRET || "default_salt";
  return crypto.createHash("sha256").update(String(ip) + salt).digest("hex");
}

const contactLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { ok: false, error: { code: "RATE_LIMIT", message: "Too many requests, try later" } }
});

router.post("/", contactLimiter, async (req, res, next) => {
  try {
    const name = sanitizeText(req.body?.name);
    const email = sanitizeText(req.body?.email);
    const phone = sanitizeText(req.body?.phone);
    const subject = sanitizeText(req.body?.subject);
    const message = sanitizeText(req.body?.message);

    if (!name) return res.status(400).json({ ok: false, error: { code: "VALIDATION", message: "Name is required" } });
    if (!email || !isValidEmail(email)) return res.status(400).json({ ok: false, error: { code: "VALIDATION", message: "Valid email is required" } });
    if (!message || message.length < 10 || message.length > 2000) {
      return res.status(400).json({ ok: false, error: { code: "VALIDATION", message: "Message length must be 10-2000 characters" } });
    }

    // 🔹 Send email
    await sendContactEmail({ name, email, phone, subject, message });

    // 🔹 Log message
    const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip || "";
    const entry = {
      id: "msg_" + crypto.randomBytes(8).toString("hex"),
      timestamp: new Date().toISOString(),
      name,
      email,
      phone: phone || "",
      subject: subject || "",
      message,
      ipHash: anonymizeIp(ip)
    };

    const messages = await readJson(messagesPath, []);
    messages.push(entry);
    await writeJsonAtomic(messagesPath, messages);

    res.json({ ok: true, message: "Message sent successfully" });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
