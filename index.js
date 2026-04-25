require("dotenv").config();
const express = require("express");
const cors = require("cors");

const authRouter = require("./src/routes/auth");
const conversationsRouter = require("./src/routes/conversations");
const adminRouter = require("./src/routes/admin");

const app = express();
const PORT = parseInt(process.env.PORT || "4000", 10);

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
app.use(
  cors({
    origin: [
      "http://localhost:3000","https://chatgptbackend-oh5n.onrender.com",
      process.env.FRONTEND_URL,
    ].filter(Boolean),
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

app.use(express.json({ limit: "10kb" }));

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
app.use("/api/auth", authRouter);
app.use("/api/conversations", conversationsRouter);
app.use("/api/admin", adminRouter);

// Health check
app.get("/health", (_req, res) => res.json({ status: "ok" }));

// 404 handler
app.use((_req, res) => res.status(404).json({ error: "Not found" }));

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`🚀  Backend running on http://localhost:${PORT}`);
});
