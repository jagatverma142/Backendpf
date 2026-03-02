const express = require("express");
const jwt = require("jsonwebtoken");

const router = express.Router();

router.post("/login", async (req, res) => {
  const password = String(req.body?.password || "");

  if (!password) {
    return res.status(400).json({
      ok: false,
      error: { message: "Password required" }
    });
  }

  // ✅ Set your admin password in .env as ADMIN_PASSWORD
  const adminPass = process.env.ADMIN_PASSWORD || "admin123";

  if (password !== adminPass) {
    return res.status(401).json({
      ok: false,
      error: { message: "Invalid password" }
    });
  }

  // ✅ JWT secret in .env as JWT_SECRET
  const secret = process.env.JWT_SECRET || "dev_secret_change_me";

  const token = jwt.sign(
    { role: "admin" },
    secret,
    { expiresIn: "7d" }
  );

  return res.json({ ok: true, token });
});

module.exports = router;
