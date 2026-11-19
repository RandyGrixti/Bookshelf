-- Bookshelf schema record
-- Applied via d1_bookshelf.py apply-0001 on Nov 18, 2026.
-- dropbox_id and enriched arrive with migration 0003
-- This file is a copy of ~/workspace/bookshelf-build/migrations/0001_init.sql,
-- kept here as the record of the live schema.

-- Bookshelf initial schema
-- Applied via d1_bookshelf.py apply-0001
-- Note for the splitter in that helper: comments in this file must
-- never contain a semicolon

CREATE TABLE IF NOT EXISTS books (
  id INTEGER PRIMARY KEY,
  title TEXT NOT NULL,
  title_key TEXT NOT NULL,
  author TEXT NOT NULL DEFAULT '',
  author_key TEXT NOT NULL DEFAULT '',
  year INTEGER,
  reader TEXT NOT NULL DEFAULT 'Randy' CHECK (reader IN ('Randy', 'Lisa', 'All')),
  is_read INTEGER NOT NULL DEFAULT 0,
  read_on TEXT NOT NULL DEFAULT '',
  rating REAL,
  genres TEXT NOT NULL DEFAULT '',
  cover_url TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  page_count INTEGER,
  publisher TEXT NOT NULL DEFAULT '',
  published_date TEXT NOT NULL DEFAULT '',
  google_rating REAL,
  ratings_count INTEGER,
  isbn TEXT NOT NULL DEFAULT '',
  language TEXT NOT NULL DEFAULT '',
  info_link TEXT NOT NULL DEFAULT '',
  dropbox_path TEXT NOT NULL DEFAULT '',
  filename TEXT NOT NULL DEFAULT '',
  dropbox_id TEXT NOT NULL DEFAULT '',
  enriched TEXT NOT NULL DEFAULT '',
  format TEXT NOT NULL DEFAULT '',
  formats TEXT NOT NULL DEFAULT '',
  added_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT '',
  UNIQUE (title_key, author_key)
);

CREATE INDEX IF NOT EXISTS idx_books_reader ON books(reader);
CREATE INDEX IF NOT EXISTS idx_books_is_read ON books(is_read);

CREATE TABLE IF NOT EXISTS lists (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS list_items (
  list_id INTEGER NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
  book_id INTEGER NOT NULL REFERENCES books(id) ON DELETE CASCADE,
  position INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (list_id, book_id)
);

CREATE INDEX IF NOT EXISTS idx_list_items_list ON list_items(list_id, position);

CREATE TABLE IF NOT EXISTS device_tokens (
  token_hash TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS unlock_attempts (
  id INTEGER PRIMARY KEY,
  ip_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_unlock_attempts_ip ON unlock_attempts(ip_hash, created_at);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS d1_migrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pending_renames (
  id INTEGER PRIMARY KEY,
  book_id INTEGER NOT NULL,
  old_path TEXT NOT NULL,
  new_filename TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_pending_renames_book ON pending_renames(book_id);
