const express = require("express");
const pool = require("../db");
const authenticate = require("../middleware/authenticate");

const router = express.Router();

// All conversation routes require auth
router.use(authenticate);

// ── POST /api/conversations ─────────────────────────────────────────────────
// Creates a new conversation for the logged-in user.
// Body: { title }
router.post("/", async (req, res) => {
  const { title } = req.body || {};
  const userId = req.user.id;
  try {
    const [result] = await pool.query(
      "INSERT INTO conversations (user_id, title) VALUES (?, ?)",
      [userId, title ? String(title).slice(0, 200) : "New Chat"]
    );
    return res.status(201).json({ id: result.insertId });
  } catch (err) {
    console.error("[conversations POST]", err);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// ── GET /api/conversations ──────────────────────────────────────────────────
// Returns the 50 most-recent conversations for the logged-in user.
router.get("/", async (req, res) => {
  const userId = req.user.id;
  try {
    const [rows] = await pool.query(
      "SELECT id, title, updated_at FROM conversations WHERE user_id = ? ORDER BY updated_at DESC LIMIT 50",
      [userId]
    );
    return res.json(rows);
  } catch (err) {
    console.error("[conversations GET]", err);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// ── GET /api/conversations/:id/messages ────────────────────────────────────
// Returns all messages for a conversation (ownership-checked).
router.get("/:id/messages", async (req, res) => {
  const userId = req.user.id;
  const convId = parseInt(req.params.id, 10);
  if (isNaN(convId)) return res.status(400).json({ error: "Invalid id." });

  try {
    const [convRows] = await pool.query(
      "SELECT id FROM conversations WHERE id = ? AND user_id = ?",
      [convId, userId]
    );
    if (convRows.length === 0) return res.status(404).json({ error: "Not found." });

    const [messages] = await pool.query(
      "SELECT id, role, content FROM messages WHERE conversation_id = ? ORDER BY created_at ASC",
      [convId]
    );
    return res.json(messages);
  } catch (err) {
    console.error("[messages GET]", err);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// ── POST /api/conversations/:id/messages ───────────────────────────────────
// Saves an array of messages to a conversation (ownership-checked).
// Body: { messages: [{ role, content }] }
router.post("/:id/messages", async (req, res) => {
  const userId = req.user.id;
  const convId = parseInt(req.params.id, 10);
  if (isNaN(convId)) return res.status(400).json({ error: "Invalid id." });

  const { messages } = req.body || {};
  if (!Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: "messages array required." });
  }

  // Validate each message
  for (const m of messages) {
    if (!["user", "assistant"].includes(m.role) || typeof m.content !== "string") {
      return res.status(400).json({ error: "Invalid message format." });
    }
  }

  try {
    const [convRows] = await pool.query(
      "SELECT id FROM conversations WHERE id = ? AND user_id = ?",
      [convId, userId]
    );
    if (convRows.length === 0) return res.status(404).json({ error: "Not found." });

    const values = messages.map((m) => [convId, m.role, m.content]);
    await pool.query("INSERT INTO messages (conversation_id, role, content) VALUES ?", [values]);
    await pool.query("UPDATE conversations SET updated_at = NOW() WHERE id = ?", [convId]);

    return res.status(201).json({ saved: messages.length });
  } catch (err) {
    console.error("[messages POST]", err);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// ── DELETE /api/conversations/:id ──────────────────────────────────────────
// Deletes a conversation and all its messages (ownership-checked).
router.delete("/:id", async (req, res) => {
  const userId = req.user.id;
  const convId = parseInt(req.params.id, 10);
  if (isNaN(convId)) return res.status(400).json({ error: "Invalid id." });

  try {
    const [convRows] = await pool.query(
      "SELECT id FROM conversations WHERE id = ? AND user_id = ?",
      [convId, userId]
    );
    if (convRows.length === 0) return res.status(404).json({ error: "Not found." });

    await pool.query("DELETE FROM conversations WHERE id = ?", [convId]);
    return res.json({ success: true });
  } catch (err) {
    console.error("[conversations DELETE]", err);
    return res.status(500).json({ error: "Internal server error." });
  }
});

module.exports = router;
