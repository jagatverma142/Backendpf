const path = require("path");
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

const { notFound } = require("./middleware/notFound");
const { errorHandler } = require("./middleware/errorHandler");

// ✅ Routes imports
const healthRoutes = require("./routes/health");
const contactRoutes = require("./routes/contact");
const projectsRoutes = require("./routes/projects");
const adminRoutes = require("./routes/admin"); // /login (if used)
const adminDataRoutes = require("./routes/adminData"); // /messages, /events
const resumeRoutes = require("./routes/resume");
const contentRoutes = require("./routes/content");
const adminContentRoutes = require("./routes/adminContent");
const adminAuthRoutes = require("./routes/adminAuth"); // /login (if used)

const app = express();
app.set("trust proxy", 1);

// ✅ Security + JSON parser
app.use(helmet());
app.use(express.json({ limit: "200kb" }));

// ✅ CORS setup (localhost + GitHub Pages allow)
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://127.0.0.1:5173",
      "https://jagatverma14.github.io"
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

// ✅ Rate limiting
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: "draft-7",
    legacyHeaders: false
  })
);

// ✅ Routes mount section
app.use("/api/health", healthRoutes);
app.use("/api/contact", contactRoutes);
app.use("/api/projects", projectsRoutes);
app.use("/api/resume", resumeRoutes);
app.use("/api/content", contentRoutes);

// ✅ Admin routes (IMPORTANT: avoid duplicate /login routes)
// Use ONE login route: prefer adminAuthRoutes for /api/admin/login
app.use("/api/admin", adminDataRoutes);
app.use("/api/admin", adminContentRoutes);
app.use("/api/admin", adminAuthRoutes);

// ❗ If you still use old adminRoutes (also provides /login), keep it OFF to avoid confusion
// app.use("/api/admin", adminRoutes);

// ✅ Production: serve frontend build (optional; Render usually backend-only)
if (process.env.NODE_ENV === "production") {
  const clientDist = path.join(__dirname, "..", "..", "Frontend", "dist");
  app.use(express.static(clientDist));
  app.get("*", (req, res) => res.sendFile(path.join(clientDist, "index.html")));
}

// ✅ Error handlers
app.use(notFound);
app.use(errorHandler);

const port = process.env.PORT || 5000;
app.listen(port, () => console.log(`Backend running: http://localhost:${port}`));
