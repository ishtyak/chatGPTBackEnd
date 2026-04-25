const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("../db");

const router = express.Router();
const SALT_ROUNDS = 12;

// ---------------------------------------------------------------------------
// POST /api/auth/register
// Body: { name, email, password }
// ---------------------------------------------------------------------------
router.post("/register", async (req, res) => {
  const { name, email, password } = req.body || {};

  // --- Input validation ---
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Invalid email address." });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters." });
  }

  try {
    // --- Check for duplicate email ---
    const [existing] = await pool.query(
      "SELECT id FROM users WHERE email = ? LIMIT 1",
      [email.toLowerCase().trim()]
    );
    if (existing.length > 0) {
      return res.status(409).json({ error: "An account with this email already exists." });
    }

    // --- Hash password and insert ---
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const [result] = await pool.query(
      "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
      [name ? name.trim() : null, email.toLowerCase().trim(), passwordHash]
    );

    const userId = result.insertId;

    // --- Issue JWT ---
    const token = jwt.sign(
      { id: userId, email: email.toLowerCase().trim(), name: name || null },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.status(201).json({
      message: "Account created successfully.",
      token,
      user: { id: userId, name: name || null, email: email.toLowerCase().trim() },
    });
  } catch (err) {
    console.error("[register]", err);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/login
// Body: { email, password }
// ---------------------------------------------------------------------------
router.post("/login", async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  try {
    const [rows] = await pool.query(
      "SELECT id, name, email, password_hash FROM users WHERE email = ? LIMIT 1",
      [email.toLowerCase().trim()]
    );

    if (rows.length === 0) {
      // Use the same message for both "not found" and "wrong password" to
      // prevent email enumeration attacks.
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const user = rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.status(200).json({
      message: "Login successful.",
      token,
      user: { id: user.id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error("[login]", err);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/verify
// Header: Authorization: Bearer <token>
// Returns the decoded user payload if the token is valid.
// ---------------------------------------------------------------------------
router.post("/verify", (req, res) => {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "No token provided." });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    return res.status(200).json({ valid: true, user: payload });
  } catch {
    return res.status(401).json({ valid: false, error: "Invalid or expired token." });
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/google-upsert
// Body: { email, name }
// Used by NextAuth signIn callback to create/retrieve a DB user for OAuth logins
// and get a backend JWT.
// ---------------------------------------------------------------------------
router.post("/google-upsert", async (req, res) => {
  const { email, name } = req.body || {};
  if (!email) return res.status(400).json({ error: "Email required." });

  try {
    const [existing] = await pool.query(
      "SELECT id, name, email FROM users WHERE email = ? LIMIT 1",
      [email.toLowerCase().trim()]
    );

    let userId, userName;
    if (existing.length > 0) {
      userId = existing[0].id;
      userName = existing[0].name;
    } else {
      const [result] = await pool.query(
        "INSERT INTO users (name, email, password_hash) VALUES (?, ?, NULL)",
        [name || null, email.toLowerCase().trim()]
      );
      userId = result.insertId;
      userName = name || null;
    }

    const token = jwt.sign(
      { id: userId, email: email.toLowerCase().trim(), name: userName },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.status(200).json({
      token,
      user: { id: userId, name: userName, email: email.toLowerCase().trim() },
    });
  } catch (err) {
    console.error("[google-upsert]", err);
    return res.status(500).json({ error: "Internal server error." });
  }
});

module.exports = router;
