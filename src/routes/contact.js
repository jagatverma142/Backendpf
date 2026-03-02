const path = require("path");
const crypto = require("crypto");
const express = require("express");
const rateLimit = require("express-rate-limit");

const { readJson, writeJsonAtomic } = require("../lib/jsonStore");
const { sanitizeText, isValidEmail } = require("../lib/sanitize");
const { sendContactEmail } = require("../lib/mailer");

const router = express.Router();

// ✅ messages.json path
const messagesPath = path.join(__dirname, "..", "..", "data", "messages.json");

// ✅ Optional: anonymize IP
function anonymizeIp(ip) {
  const salt = process.env.LOG_SALT || process.env.JWT_SECRET || "default_salt";
  return crypto.createHash("sha256").update(String(ip) + salt).digest("hex");
}

// ✅ Per-route rate limit (Contact form)
const contactLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7", // valid drafts include 6/7/8
  legacyHeaders: false,
  message: {
    ok: false,
    error: { code: "RATE_LIMIT", message: "Too many requests, try later" }
  }
});

// ✅ GET health for browser test (also rate-limited)
router.get("/", contactLimiter, (req, res) => {
  res.json({ ok: true, message: "Contact API is running. Use POST /api/contact" });
});

router.post("/", contactLimiter, async (req, res, next) => {
  try {
    // ✅ Basic body guard (avoid non-JSON or empty body issues)
    const body = req.body && typeof req.body === "object" ? req.body : {};

    const name = sanitizeText(body.name);
    const email = sanitizeText(body.email);
    const phone = sanitizeText(body.phone);
    const subject = sanitizeText(body.subject);
    const message = sanitizeText(body.message);
    const service = sanitizeText(body.service);
    const budget = sanitizeText(body.budget);
    const timeline = sanitizeText(body.timeline);
    const consent = body.consent;

    // ✅ Validations
    if (!name) {
      return res.status(400).json({
        ok: false,
        error: { code: "VALIDATION", message: "Name is required" }
      });
    }

    if (!email || !isValidEmail(email)) {
      return res.status(400).json({
        ok: false,
        error: { code: "VALIDATION", message: "Valid email is required" }
      });
    }

    if (!message || message.length < 10 || message.length > 2000) {
      return res.status(400).json({
        ok: false,
        error: {
          code: "VALIDATION",
          message: "Message length must be 10-2000 characters"
        }
      });
    }

    if (consent !== true) {
      return res.status(400).json({
        ok: false,
        error: { code: "VALIDATION", message: "Consent is required" }
      });
    }

    // ✅ Client IP (trust proxy enabled in index.js, so req.ip is ok behind Render)
    const ip =
      req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip || "";

    // ✅ Save entry first (so even if email fails, message is not lost)
    const entry = {
      id: "msg_" + crypto.randomBytes(8).toString("hex"),
      timestamp: new Date().toISOString(),
      name,
      email,
      phone: phone || "",
      subject: subject || "",
      message,
      service: service || "",
      budget: budget || "",
      timeline: timeline || "",
      consent: true,
      ipHash: anonymizeIp(ip)
    };

    const messages = await readJson(messagesPath, []);
    messages.push(entry);
    await writeJsonAtomic(messagesPath, messages);

    // ✅ Try sending email (do not fail the whole request if email is down)
    try {
      await sendContactEmail({
        name,
        email,
        phone,
        subject,
        message,
        service,
        budget,
        timeline
      });
    } catch (mailErr) {
      // If you want: log mailErr in server logs
      return res.status(202).json({
        ok: true,
        message: "Saved, but email sending failed",
        saved: { id: entry.id, timestamp: entry.timestamp }
      });
    }

    // ✅ Do not return full entry (PII / ipHash)
    return res.json({
      ok: true,
      message: "Message sent successfully",
      saved: { id: entry.id, timestamp: entry.timestamp }
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
