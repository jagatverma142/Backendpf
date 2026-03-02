const jwt = require("jsonwebtoken");

function requireJwt(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ ok: false, error: { code: "UNAUTHORIZED", message: "Missing token" } });

    const secret = process.env.JWT_SECRET;
    if (!secret) return res.status(500).json({ ok: false, error: { code: "JWT_NOT_CONFIGURED", message: "JWT_SECRET missing" } });

    req.user = jwt.verify(token, secret);
    next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: { code: "UNAUTHORIZED", message: "Invalid token" } });
  }
}

module.exports = { requireJwt };
