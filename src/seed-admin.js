/**
 * Seeds the admin user.
 * Usage: node src/seed-admin.js
 */
require("dotenv").config();
const bcrypt = require("bcryptjs");
const pool = require("./db");

async function seed() {
  const email = process.env.ADMIN_EMAIL || "admin@softkey.ai";
  const password = process.env.ADMIN_PASSWORD || "Admin@123456";

  if (password.length < 8) {
    console.error("❌  ADMIN_PASSWORD must be at least 8 characters.");
    process.exit(1);
  }

  const hash = await bcrypt.hash(password, 12);
  const conn = await pool.getConnection();
  try {
    const [existing] = await conn.query(
      "SELECT id FROM users WHERE email = ? LIMIT 1",
      [email]
    );
    if (existing.length > 0) {
      await conn.query(
        "UPDATE users SET password_hash = ?, is_admin = 1 WHERE email = ?",
        [hash, email]
      );
      console.log(`✅  Admin user updated: ${email}`);
    } else {
      await conn.query(
        "INSERT INTO users (name, email, password_hash, is_admin) VALUES (?, ?, ?, 1)",
        ["Super Admin", email, hash]
      );
      console.log(`✅  Admin user created: ${email}`);
    }
    console.log(`   Password: ${password}`);
    console.log("   ⚠️  Change the password before going to production!");
  } finally {
    conn.release();
    await pool.end();
  }
}

seed().catch((err) => { console.error(err); process.exit(1); });
