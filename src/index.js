const path = require("path");
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });


const { notFound } = require("./middleware/notFound");
const { errorHandler } = require("./middleware/errorHandler");

const healthRoutes = require("./routes/health");
const contactRoutes = require("./routes/contact");
const projectsRoutes = require("./routes/projects");
const adminRoutes = require("./routes/admin");          // /login
const adminDataRoutes = require("./routes/adminData"); // /messages, /events
const resumeRoutes = require("./routes/resume");
const contentRoutes = require("./routes/content");
const adminContentRoutes = require("./routes/adminContent");
const adminAuthRoutes = require("./routes/adminAuth");


const app = express();
app.set("trust proxy", 1);

app.use(helmet());
app.use(express.json({ limit: "200kb" }));

// Dev me aapka Frontend Vite usually :5173 pe hota hai
const allowedOrigins = new Set([
  "http://localhost:5173",
  "http://127.0.0.1:5173"
]);

app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true); // same-origin/curl
      if (process.env.NODE_ENV === "development" && allowedOrigins.has(origin)) return cb(null, true);
      if (process.env.NODE_ENV === "production") return cb(null, true);
      return cb(new Error("Not allowed by CORS"));
    }
  })
);

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
app.use("/api/admin", adminRoutes);       // /login
app.use("/api/admin", adminDataRoutes);   // /messages, /events
app.use("/api/resume", resumeRoutes);
app.use("/api/content", contentRoutes);
app.use("/api/admin", adminContentRoutes); // /content
app.use("/api/admin", adminAuthRoutes);    // /login


// Production: built Frontend serve karo (same-origin)
if (process.env.NODE_ENV === "production") {
  const clientDist = path.join(__dirname, "..", "..", "Frontent", "dist");
  app.use(express.static(clientDist));
  app.get("*", (req, res) => res.sendFile(path.join(clientDist, "index.html")));
}

app.use(notFound);
app.use(errorHandler);

const port = process.env.PORT || 5000;
app.listen(port, () => console.log(`Backend running: http://localhost:${port}`));
