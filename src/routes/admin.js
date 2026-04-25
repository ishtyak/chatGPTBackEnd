const router = require("express").Router();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const pool = require("../db");
const adminAuth = require("../middleware/adminAuth");

/* ── helpers ──────────────────────────────────────────────── */

/** Mask an API key: show last 8 characters only. */
function maskKey(value) {
  if (!value || value.length <= 8) return "••••••••";
  return "••••••••" + value.slice(-8);
}

/* ── POST /api/admin/login ───────────────────────────────── */
router.post("/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  try {
    const [rows] = await pool.query(
      "SELECT id, name, email, password_hash, is_admin FROM users WHERE email = ? LIMIT 1",
      [email]
    );
    const user = rows[0];
    if (!user || !user.is_admin) {
      return res.status(401).json({ error: "Invalid admin credentials." });
    }
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: "Invalid admin credentials." });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name, isAdmin: true },
      process.env.ADMIN_JWT_SECRET,
      { expiresIn: "8h" }
    );
    res.json({ token, name: user.name, email: user.email });
  } catch (err) {
    console.error("Admin login error:", err);
    res.status(500).json({ error: "Server error." });
  }
});

/* ── GET /api/admin/api-keys ─────────────────────────────── */
router.get("/api-keys", adminAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, provider, label, is_active, created_at, updated_at, key_value FROM api_keys ORDER BY provider, created_at"
    );
    const masked = rows.map((r) => ({
      id: r.id,
      provider: r.provider,
      label: r.label,
      is_active: !!r.is_active,
      created_at: r.created_at,
      updated_at: r.updated_at,
      masked_key: maskKey(r.key_value),
    }));
    res.json(masked);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error." });
  }
});

/* ── POST /api/admin/api-keys ────────────────────────────── */
router.post("/api-keys", adminAuth, async (req, res) => {
  const { provider, label, key_value, is_active = true } = req.body || {};
  if (!provider || !key_value) {
    return res.status(400).json({ error: "provider and key_value are required." });
  }

  const VALID_PROVIDERS = [
    "openai", "anthropic", "google", "meta",
    "mistral", "xai", "deepseek", "perplexity", "replicate"
  ];
  if (!VALID_PROVIDERS.includes(provider.toLowerCase())) {
    return res.status(400).json({ error: `Invalid provider. Must be one of: ${VALID_PROVIDERS.join(", ")}` });
  }

  try {
    // If new key is set active, deactivate all existing keys for that provider first
    if (is_active) {
      await pool.query(
        "UPDATE api_keys SET is_active = 0 WHERE provider = ?",
        [provider.toLowerCase()]
      );
    }

    const [result] = await pool.query(
      "INSERT INTO api_keys (provider, label, key_value, is_active) VALUES (?, ?, ?, ?)",
      [provider.toLowerCase(), label || "", key_value, is_active ? 1 : 0]
    );

    res.status(201).json({
      id: result.insertId,
      provider: provider.toLowerCase(),
      label: label || "",
      is_active: !!is_active,
      masked_key: maskKey(key_value),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error." });
  }
});

/* ── PUT /api/admin/api-keys/:id ─────────────────────────── */
router.put("/api-keys/:id", adminAuth, async (req, res) => {
  const { id } = req.params;
  const { label, key_value } = req.body || {};

  try {
    const [rows] = await pool.query(
      "SELECT id FROM api_keys WHERE id = ? LIMIT 1",
      [id]
    );
    if (!rows.length) return res.status(404).json({ error: "Key not found." });

    const updates = [];
    const params = [];
    if (label !== undefined) { updates.push("label = ?"); params.push(label); }
    if (key_value)           { updates.push("key_value = ?"); params.push(key_value); }

    if (!updates.length) {
      return res.status(400).json({ error: "Nothing to update." });
    }
    params.push(id);
    await pool.query(`UPDATE api_keys SET ${updates.join(", ")} WHERE id = ?`, params);

    const [updated] = await pool.query(
      "SELECT id, provider, label, is_active, key_value FROM api_keys WHERE id = ? LIMIT 1",
      [id]
    );
    const r = updated[0];
    res.json({
      id: r.id,
      provider: r.provider,
      label: r.label,
      is_active: !!r.is_active,
      masked_key: maskKey(r.key_value),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error." });
  }
});

/* ── DELETE /api/admin/api-keys/:id ─────────────────────── */
router.delete("/api-keys/:id", adminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query("DELETE FROM api_keys WHERE id = ?", [id]);
    if (!result.affectedRows) return res.status(404).json({ error: "Key not found." });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error." });
  }
});

/* ── PATCH /api/admin/api-keys/:id/activate ─────────────── */
router.patch("/api-keys/:id/activate", adminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query(
      "SELECT id, provider FROM api_keys WHERE id = ? LIMIT 1",
      [id]
    );
    if (!rows.length) return res.status(404).json({ error: "Key not found." });

    const { provider } = rows[0];
    // Deactivate all keys for this provider, then activate the chosen one
    await pool.query("UPDATE api_keys SET is_active = 0 WHERE provider = ?", [provider]);
    await pool.query("UPDATE api_keys SET is_active = 1 WHERE id = ?", [id]);

    res.json({ success: true, provider, activated_id: Number(id) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error." });
  }
});

/* ── GET /api/admin/api-key/:provider (internal) ────────── */
/* Used by the Next.js chat route server-side only.           */
/* No admin auth needed since it's server-to-server.          */
router.get("/api-key/:provider", async (req, res) => {
  const { provider } = req.params;
  try {
    const [rows] = await pool.query(
      "SELECT key_value FROM api_keys WHERE provider = ? AND is_active = 1 LIMIT 1",
      [provider.toLowerCase()]
    );
    if (!rows.length) return res.status(404).json({ error: "No active key found." });
    res.json({ key: rows[0].key_value });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error." });
  }
});

module.exports = router;
