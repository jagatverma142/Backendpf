const express = require("express");
const path = require("path");
const { readJson } = require("../lib/jsonStore");

const router = express.Router();
const contentPath = path.join(__dirname, "..", "..", "data", "content.json");

// ✅ GET full content.json
router.get("/", async (req, res, next) => {
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

// ✅ Example: GET only "home" section
router.get("/home", async (req, res, next) => {
  try {
    const content = await readJson(contentPath, null);
    if (!content?.home) {
      return res.status(404).json({
        ok: false,
        error: { code: "SECTION_MISSING", message: "home section missing" }
      });
    }
    res.json({ ok: true, home: content.home });
  } catch (e) {
    next(e);
  }
});

// ✅ Example: GET only "about" section
router.get("/about", async (req, res, next) => {
  try {
    const content = await readJson(contentPath, null);
    if (!content?.about) {
      return res.status(404).json({
        ok: false,
        error: { code: "SECTION_MISSING", message: "about section missing" }
      });
    }
    res.json({ ok: true, about: content.about });
  } catch (e) {
    next(e);
  }
});

module.exports = router;
