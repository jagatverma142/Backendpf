const express = require("express");
const { requireJwt } = require("../middleware/auth");
const { sanitizeText } = require("../lib/sanitize");
const {
  listProjects, getProject, createProject, updateProject, deleteProject
} = require("../lib/projectsStore");

const router = express.Router();

router.get("/", async (req, res, next) => {
  try {
    const projects = await listProjects();
    res.json({ ok: true, projects });
  } catch (e) { next(e); }
});

router.get("/:id", async (req, res, next) => {
  try {
    const project = await getProject(req.params.id);
    if (!project) return res.status(404).json({ ok: false, error: { code: "NOT_FOUND", message: "Project not found" } });
    res.json({ ok: true, project });
  } catch (e) { next(e); }
});

// Admin protected CRUD
router.post("/", requireJwt, async (req, res, next) => {
  try {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const cleaned = {};
    for (const [k, v] of Object.entries(body)) cleaned[k] = typeof v === "string" ? sanitizeText(v) : v;

    const created = await createProject(cleaned);
    res.status(201).json({ ok: true, project: created });
  } catch (e) { next(e); }
});

router.put("/:id", requireJwt, async (req, res, next) => {
  try {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const cleaned = {};
    for (const [k, v] of Object.entries(body)) cleaned[k] = typeof v === "string" ? sanitizeText(v) : v;

    const updated = await updateProject(req.params.id, cleaned);
    if (!updated) return res.status(404).json({ ok: false, error: { code: "NOT_FOUND", message: "Project not found" } });
    res.json({ ok: true, project: updated });
  } catch (e) { next(e); }
});

router.delete("/:id", requireJwt, async (req, res, next) => {
  try {
    const ok = await deleteProject(req.params.id);
    if (!ok) return res.status(404).json({ ok: false, error: { code: "NOT_FOUND", message: "Project not found" } });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

module.exports = router;
