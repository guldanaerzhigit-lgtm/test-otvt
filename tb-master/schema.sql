PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'Все темы',
  mode TEXT NOT NULL CHECK (mode IN ('study', 'exam')),
  total INTEGER NOT NULL CHECK (total >= 0),
  correct INTEGER NOT NULL CHECK (correct >= 0 AND correct <= total),
  percent INTEGER NOT NULL CHECK (percent >= 0 AND percent <= 100),
  elapsed INTEGER NOT NULL DEFAULT 0 CHECK (elapsed >= 0),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_attempts_user_date ON attempts(user_id, created_at DESC);