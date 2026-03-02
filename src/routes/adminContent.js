const express = require("express");
const path = require("path");
const { requireJwt } = require("../middleware/auth");
const { readJson, writeJsonAtomic } = require("../lib/jsonStore");

const router = express.Router();
const contentPath = path.join(__dirname, "..", "..", "data", "content.json");

// ✅ GET content.json (JWT protected)
router.get("/content", requireJwt, async (req, res, next) => {
  try {
    const content = await readJson(contentPath, null);
    if (!content) {
      return res.status(500).json({
        ok: false,
        error: { code: "CONTENT_MISSING", message: "content.json missing" }
      });
    }
    res.json({ ok: true, content });
  } catch (e) {
    next(e);
  }
});

// ✅ PUT content.json (JWT protected, with validation)
router.put("/content", requireJwt, async (req, res, next) => {
  try {
    const body = req.body && typeof req.body === "object" ? req.body : null;
    if (!body) {
      return res.status(400).json({
        ok: false,
        error: { code: "VALIDATION", message: "Invalid JSON body" }
      });
    }

    // Minimal validation (can be extended later)
    if (!body.home || !body.about || !body.services || !body.settings) {
      return res.status(400).json({
        ok: false,
        error: {
          code: "VALIDATION",
          message: "Missing sections (home/about/services/settings)"
        }
      });
    }

    // Auto-update meta timestamp
    body.meta = body.meta || {};
    body.meta.updatedAt = new Date().toISOString();

    await writeJsonAtomic(contentPath, body);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

module.exports = router;
