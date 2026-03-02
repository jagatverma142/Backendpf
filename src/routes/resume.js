const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { readJson, writeJsonAtomic } = require("../lib/jsonStore");

const router = express.Router();
const eventsPath = path.join(__dirname, "..", "..", "data", "events.json");

function anonymizeIp(ip) {
  const salt = process.env.LOG_SALT || process.env.JWT_SECRET || "default_salt";
  return crypto.createHash("sha256").update(String(ip) + salt).digest("hex");
}

router.get("/", async (req, res, next) => {
  try {
    const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip || "";
    const entry = { type: "resume_download", timestamp: new Date().toISOString(), ipHash: anonymizeIp(ip) };

    const events = await readJson(eventsPath, []);
    events.push(entry);
    await writeJsonAtomic(eventsPath, events);

    const filePath = path.join(__dirname, "..", "..", "public", "resume.pdf");
    return res.download(filePath, "resume.pdf");
  } catch (e) { next(e); }
});

module.exports = router;
