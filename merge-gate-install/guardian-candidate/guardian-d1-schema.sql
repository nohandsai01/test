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

-- G7 OAuth PKCE exchange bridge. Stores only an ephemeral verifier, never
-- a GitHub user access/refresh token or OAuth client secret. OAuth state
-- remains a tombstone after consumption, including if GitHub rejects code.
CREATE TABLE IF NOT EXISTS guardian_owner_oauth_states (
  state_hash TEXT PRIMARY KEY NOT NULL CHECK (length(state_hash) = 64),
  browser_session_hash TEXT NOT NULL CHECK (length(browser_session_hash) = 64),
  installation_state_hash TEXT NOT NULL CHECK (length(installation_state_hash) = 64),
  installation_id INTEGER NOT NULL CHECK (installation_id > 0),
  setup_action TEXT NOT NULL CHECK (setup_action IN ('install', 'update')),
  code_verifier TEXT NOT NULL CHECK (length(code_verifier) = 43),
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

-- Optional full-mode gate: exactly one authoritative conclusion attempt per
-- repository/PR/head. A failed or uncertain POST leaves a permanent tombstone
-- for operator reconciliation; never silently retry with a conflicting check.
CREATE TABLE IF NOT EXISTS guardian_conclusion_reservations (
  repository_id INTEGER NOT NULL CHECK (repository_id > 0),
  pull_number INTEGER NOT NULL CHECK (pull_number > 0),
  head_sha TEXT NOT NULL CHECK (length(head_sha) = 40),
  delivery_hash TEXT NOT NULL UNIQUE CHECK (length(delivery_hash) = 64),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  PRIMARY KEY (repository_id, pull_number, head_sha)
) STRICT;
