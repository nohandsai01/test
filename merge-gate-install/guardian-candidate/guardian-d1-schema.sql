-- Guardian-only isolated D1 schema candidate. Never auto-applied by source.
-- Operator must independently identify the database and approve migration.
-- No automatic cleanup: deleting replay receipts can re-accept old deliveries.

CREATE TABLE IF NOT EXISTS guardian_install_intents (
  state_hash TEXT PRIMARY KEY NOT NULL
    CHECK (length(state_hash) = 64),
  owner_session_hash TEXT NOT NULL
    CHECK (length(owner_session_hash) = 64),
  expires_at TEXT NOT NULL,
  consumed_at TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS guardian_installation_bindings (
  installation_id INTEGER PRIMARY KEY NOT NULL CHECK (installation_id > 0),
  app_id INTEGER NOT NULL CHECK (app_id > 0),
  owner_account_id INTEGER NOT NULL CHECK (owner_account_id > 0),
  repository_id INTEGER NOT NULL CHECK (repository_id > 0),
  verified_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS guardian_delivery_receipts (
  delivery_hash TEXT PRIMARY KEY NOT NULL
    CHECK (length(delivery_hash) = 64),
  installation_id INTEGER NOT NULL CHECK (installation_id > 0),
  pull_number INTEGER NOT NULL CHECK (pull_number > 0),
  head_sha TEXT NOT NULL CHECK (length(head_sha) = 40),
  created_at TEXT NOT NULL DEFAULT (
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  )
) STRICT;
