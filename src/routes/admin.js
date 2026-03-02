const express = require("express");
const path = require("path");
const { requireJwt } = require("../middleware/auth");
const { readJson, writeJsonAtomic } = require("../lib/jsonStore");

const router = express.Router();

const messagesPath = path.join(__dirname, "..", "..", "data", "messages.json");
const eventsPath = path.join(__dirname, "..", "..", "data", "events.json");

// GET /api/admin/messages  (JWT protected)
router.get("/messages", requireJwt, async (req, res, next) => {
  try {
    const messages = await readJson(messagesPath, []);
    res.json({ ok: true, messages });
  } catch (e) {
    next(e);
  }
});

// DELETE /api/admin/messages/:id (JWT protected)
router.delete("/messages/:id", requireJwt, async (req, res, next) => {
  try {
    const id = String(req.params.id);
    const messages = await readJson(messagesPath, []);
    const nextMessages = messages.filter((m) => String(m.id) !== id);

    if (nextMessages.length === messages.length) {
      return res.status(404).json({
        ok: false,
        error: { code: "NOT_FOUND", message: "Message not found" }
      });
    }

    await writeJsonAtomic(messagesPath, nextMessages);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

// GET /api/admin/events (JWT protected)
router.get("/events", requireJwt, async (req, res, next) => {
  try {
    const events = await readJson(eventsPath, []);
    res.json({ ok: true, events });
  } catch (e) {
    next(e);
  }
});

module.exports = router;
