/**
 * Creates / migrates all required tables.
 * Usage: node src/migrate.js
 */
const pool = require("./db");

async function migrate() {
  const conn = await pool.getConnection();
  try {
    // Users table (allow null password_hash for OAuth users)
    await conn.query(`
      CREATE TABLE IF NOT EXISTS users (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        name          VARCHAR(255),
        email         VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NULL,
        created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);
    // Allow null for existing installs that created the column as NOT NULL
    await conn.query(
      `ALTER TABLE users MODIFY COLUMN password_hash VARCHAR(255) NULL`
    ).catch(() => {});

    // Conversations table
    await conn.query(`
      CREATE TABLE IF NOT EXISTS conversations (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        user_id    INT NOT NULL,
        title      VARCHAR(255) NOT NULL DEFAULT 'New Chat',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_user_id (user_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // Messages table
    await conn.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id              INT AUTO_INCREMENT PRIMARY KEY,
        conversation_id INT NOT NULL,
        role            ENUM('user','assistant') NOT NULL,
        content         MEDIUMTEXT NOT NULL,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_conv_id (conversation_id),
        FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // is_admin flag on users (ignore if already exists)
    await conn.query(
      `ALTER TABLE users ADD COLUMN is_admin TINYINT(1) NOT NULL DEFAULT 0`
    ).catch(() => {});

    // API keys table (one active key per provider)
    await conn.query(`
      CREATE TABLE IF NOT EXISTS api_keys (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        provider   VARCHAR(50) NOT NULL,
        label      VARCHAR(100) NOT NULL DEFAULT '',
        key_value  TEXT NOT NULL,
        is_active  TINYINT(1) NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_provider (provider)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    console.log("✅  All tables are ready.");
  } catch (err) {
    console.error("❌  Migration failed:", err.message);
    process.exit(1);
  } finally {
    conn.release();
    await pool.end();
  }
}

migrate();
