// SPDX-License-Identifier: GPL-3.0-or-later
//! Versioned schema migrations, tracked in SQLite's `user_version`.
//!
//! Migrations only ever get appended. Each runs in its own transaction together with the
//! version bump, so a crash leaves the database at the previous version, never in between.

use rusqlite::Connection;

use crate::error::StoreError;

/// Schema migrations; entry `n` takes the database from version `n` to `n + 1`.
const MIGRATIONS: &[&str] = &[V1, V2, V3];

/// The schema version this build writes.
pub const SCHEMA_VERSION: u32 = 3;

const V1: &str = r"
CREATE TABLE rules (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scope             TEXT    NOT NULL CHECK (scope IN ('global', 'sandbox')),
    sandbox_id        TEXT,
    pattern_kind      TEXT    NOT NULL CHECK (pattern_kind IN ('exact', 'suffix')),
    pattern           TEXT    NOT NULL,
    effect            TEXT    NOT NULL CHECK (effect IN ('allow', 'deny')),
    expires_at        INTEGER,
    created_at        INTEGER NOT NULL,
    created_by        TEXT    NOT NULL CHECK (created_by IN ('cli', 'ui', 'api')),
    source_pending_id INTEGER,
    CHECK ((scope = 'global') = (sandbox_id IS NULL))
) STRICT;
CREATE INDEX rules_sandbox ON rules (sandbox_id);
CREATE INDEX rules_expiry ON rules (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE pending (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    sandbox_id TEXT    NOT NULL,
    host       TEXT    NOT NULL,
    port       INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 1,
    state      TEXT    NOT NULL DEFAULT 'requested'
               CHECK (state IN ('requested', 'allowed', 'denied', 'expired')),
    decided_at INTEGER,
    decided_by TEXT CHECK (decided_by IN ('cli', 'ui', 'api', 'system')),
    rule_id    INTEGER
) STRICT;
-- R-11: at most one open row per (sandbox, host, port).
CREATE UNIQUE INDEX pending_open_key ON pending (sandbox_id, host, port)
    WHERE state = 'requested';
CREATE INDEX pending_state_seen ON pending (state, last_seen);
-- R-12: a row's identity never changes, and the end states are final.
CREATE TRIGGER pending_identity_immutable
BEFORE UPDATE OF id, sandbox_id, host, port, first_seen ON pending
WHEN NEW.id IS NOT OLD.id OR NEW.sandbox_id IS NOT OLD.sandbox_id OR NEW.host IS NOT OLD.host
  OR NEW.port IS NOT OLD.port OR NEW.first_seen IS NOT OLD.first_seen
BEGIN
    SELECT RAISE(ABORT, 'pending row identity is immutable');
END;
CREATE TRIGGER pending_end_state_final
BEFORE UPDATE OF state ON pending
WHEN OLD.state <> 'requested' AND NEW.state IS NOT OLD.state
BEGIN
    SELECT RAISE(ABORT, 'pending row end state is final');
END;
CREATE TRIGGER pending_no_delete
BEFORE DELETE ON pending
BEGIN
    SELECT RAISE(ABORT, 'pending rows are never deleted');
END;

CREATE TABLE audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    type       TEXT    NOT NULL,
    sandbox_id TEXT,
    line       TEXT    NOT NULL CHECK (length(CAST(line AS BLOB)) <= 4096)
) STRICT;
CREATE INDEX audit_sandbox ON audit (sandbox_id, id);
-- Running total of line bytes, so the cap check (R-26) doesn't scan the table.
CREATE TABLE audit_size (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    bytes INTEGER NOT NULL
) STRICT;
INSERT INTO audit_size (id, bytes) VALUES (1, 0);
CREATE TRIGGER audit_size_insert AFTER INSERT ON audit
BEGIN
    UPDATE audit_size SET bytes = bytes + length(CAST(NEW.line AS BLOB)) WHERE id = 1;
END;
CREATE TRIGGER audit_size_delete AFTER DELETE ON audit
BEGIN
    UPDATE audit_size SET bytes = bytes - length(CAST(OLD.line AS BLOB)) WHERE id = 1;
END;
";

/// The audit filters: `host` and `outcome` become columns so the API's filters never
/// parse JSON, and the filtered scans are indexed. Existing rows are backfilled from their
/// lines; `AuditRecord::host` and `AuditRecord::outcome` must give the same values (tested).
const V2: &str = r"
ALTER TABLE audit ADD COLUMN host TEXT;
ALTER TABLE audit ADD COLUMN outcome TEXT;
UPDATE audit SET
    host = lower(CASE type
        WHEN 'connection' THEN json_extract(line, '$.host')
        WHEN 'pending_created' THEN json_extract(line, '$.pending.host')
        WHEN 'pending_decided' THEN json_extract(line, '$.pending.host')
        WHEN 'pending_expired' THEN json_extract(line, '$.pending.host')
        WHEN 'rule_created' THEN json_extract(line, '$.rule.pattern')
        WHEN 'rule_updated' THEN json_extract(line, '$.rule.pattern')
        WHEN 'rule_deleted' THEN json_extract(line, '$.rule.pattern')
        WHEN 'rule_expired' THEN json_extract(line, '$.rule.pattern')
    END),
    outcome = CASE type
        WHEN 'connection' THEN json_extract(line, '$.decision')
        WHEN 'pending_created' THEN 'pending'
        WHEN 'pending_decided' THEN CASE json_extract(line, '$.pending.state')
            WHEN 'allowed' THEN 'allow'
            WHEN 'denied' THEN 'deny'
        END
        WHEN 'pending_expired' THEN 'expired'
    END;
CREATE INDEX audit_type ON audit (type, id);
CREATE INDEX audit_outcome ON audit (outcome, id) WHERE outcome IS NOT NULL;
CREATE INDEX audit_ts ON audit (ts);
";

/// Rule sets (`docs/spec/rules.md` §7). `rules` is rebuilt because SQLite can't change a
/// `CHECK`: a rule's scope may now be `set`, with the set in `set_id`. The `AUTOINCREMENT`
/// high-water mark is carried over, so a deleted rule's id is still never reused.
const V3: &str = r"
CREATE TABLE rule_sets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    description TEXT    NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    created_at  INTEGER NOT NULL,
    created_by  TEXT    NOT NULL CHECK (created_by IN ('cli', 'ui', 'api'))
) STRICT;
CREATE UNIQUE INDEX rule_sets_name ON rule_sets (name COLLATE NOCASE);

CREATE TABLE rules_v3 (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scope             TEXT    NOT NULL CHECK (scope IN ('global', 'sandbox', 'set')),
    sandbox_id        TEXT,
    set_id            INTEGER REFERENCES rule_sets (id),
    pattern_kind      TEXT    NOT NULL CHECK (pattern_kind IN ('exact', 'suffix')),
    pattern           TEXT    NOT NULL,
    effect            TEXT    NOT NULL CHECK (effect IN ('allow', 'deny')),
    expires_at        INTEGER,
    created_at        INTEGER NOT NULL,
    created_by        TEXT    NOT NULL CHECK (created_by IN ('cli', 'ui', 'api')),
    source_pending_id INTEGER,
    CHECK ((scope = 'sandbox') = (sandbox_id IS NOT NULL)),
    CHECK ((scope = 'set') = (set_id IS NOT NULL))
) STRICT;
INSERT INTO rules_v3 (id, scope, sandbox_id, set_id, pattern_kind, pattern, effect, expires_at,
                      created_at, created_by, source_pending_id)
    SELECT id, scope, sandbox_id, NULL, pattern_kind, pattern, effect, expires_at,
           created_at, created_by, source_pending_id
    FROM rules;
DELETE FROM sqlite_sequence WHERE name = 'rules_v3';
INSERT INTO sqlite_sequence (name, seq) SELECT 'rules_v3', seq FROM sqlite_sequence WHERE name = 'rules';
DROP TABLE rules;
ALTER TABLE rules_v3 RENAME TO rules;
CREATE INDEX rules_sandbox ON rules (sandbox_id);
CREATE INDEX rules_expiry ON rules (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX rules_set ON rules (set_id) WHERE set_id IS NOT NULL;

-- The set whose entry decided a row, when one did (`builtin:<slug>`, `user:<id>`, `system`).
ALTER TABLE pending ADD COLUMN rule_set TEXT;

-- On/off per set: one row for every sandbox (sandbox_id NULL) and one per sandbox override.
-- No row means the next level decides: the sandbox's, then every sandbox's, then the set's default.
CREATE TABLE rule_set_switches (
    rule_set   TEXT    NOT NULL,
    sandbox_id TEXT,
    enabled    INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    changed_at INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX rule_set_switches_key ON rule_set_switches (rule_set, ifnull(sandbox_id, ''));

-- Why puddle allows its System managed hosts, as last derived from the user's setup, so a
-- restart with the same setup changes (and records) nothing.
CREATE TABLE system_reasons (
    sandbox_id TEXT,
    reason     TEXT NOT NULL
) STRICT;
CREATE UNIQUE INDEX system_reasons_key ON system_reasons (ifnull(sandbox_id, ''), reason);

-- The built-in sets' entries as this database last saw them, to record what an update changed.
CREATE TABLE builtin_sets_seen (
    slug       TEXT PRIMARY KEY,
    entries    TEXT    NOT NULL,
    changed_at INTEGER
) STRICT;
";

/// Brings `conn` to [`SCHEMA_VERSION`] and returns the version it started at.
///
/// # Errors
/// [`StoreError::SchemaTooNew`] for a database written by a newer puddle (never downgraded),
/// or the SQLite error of a failed migration (which is rolled back).
pub(crate) fn migrate(conn: &mut Connection) -> Result<u32, StoreError> {
    migrate_with(conn, MIGRATIONS)
}

/// Migrates only up to `version`, to build the database an older puddle left behind.
#[cfg(test)]
pub(crate) fn migrate_up_to(conn: &mut Connection, version: usize) -> Result<u32, StoreError> {
    migrate_with(conn, &MIGRATIONS[..version])
}

fn migrate_with(conn: &mut Connection, migrations: &[&str]) -> Result<u32, StoreError> {
    let start: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let supported = u32::try_from(migrations.len()).unwrap_or(u32::MAX);
    if start > supported {
        return Err(StoreError::SchemaTooNew {
            found: start,
            supported,
        });
    }
    for (version, sql) in (start..).zip(migrations.iter().skip(start as usize)) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", version + 1)?;
        tx.commit()?;
    }
    Ok(start)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(conn: &Connection) -> u32 {
        conn.pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn fresh_database_migrates_to_latest() {
        let mut conn = Connection::open_in_memory().unwrap();
        assert_eq!(migrate(&mut conn).unwrap(), 0);
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert_eq!(MIGRATIONS.len(), SCHEMA_VERSION as usize);
    }

    #[test]
    fn v3_keeps_every_rule_and_never_reuses_a_deleted_id() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate_up_to(&mut conn, 2).unwrap();
        conn.execute_batch(
            "INSERT INTO rules (scope, sandbox_id, pattern_kind, pattern, effect, created_at, created_by)
                VALUES ('global', NULL, 'exact', 'a.example', 'allow', 1, 'cli'),
                       ('sandbox', 'box', 'suffix', '.example.com', 'deny', 2, 'ui'),
                       ('global', NULL, 'exact', 'gone.example', 'allow', 3, 'api');
             DELETE FROM rules WHERE pattern = 'gone.example';
             INSERT INTO pending (sandbox_id, host, port, first_seen, last_seen)
                VALUES ('box', 'x.example', 443, 1, 1);",
        )
        .unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        migrate(&mut conn).unwrap();
        let kept: Vec<(i64, String, Option<String>, Option<i64>)> = conn
            .prepare("SELECT id, scope, sandbox_id, set_id FROM rules ORDER BY id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            kept,
            vec![
                (1, "global".into(), None, None),
                (2, "sandbox".into(), Some("box".into()), None)
            ]
        );
        conn.execute(
            "INSERT INTO rules (scope, pattern_kind, pattern, effect, created_at, created_by)
             VALUES ('global', 'exact', 'new.example', 'allow', 4, 'cli')",
            [],
        )
        .unwrap();
        assert_eq!(
            conn.last_insert_rowid(),
            4,
            "id 3 was deleted before and stays unused"
        );
        // A set entry needs its set, and a set scope needs a set id.
        assert!(
            conn.execute(
                "INSERT INTO rules (scope, set_id, pattern_kind, pattern, effect, created_at, created_by)
                 VALUES ('set', 9, 'exact', 'a.example', 'allow', 4, 'cli')",
                [],
            )
            .is_err()
        );
        assert!(
            conn.execute(
                "INSERT INTO rules (scope, pattern_kind, pattern, effect, created_at, created_by)
                 VALUES ('set', 'exact', 'a.example', 'allow', 4, 'cli')",
                [],
            )
            .is_err()
        );
        let rule_set: Option<String> = conn
            .query_row("SELECT rule_set FROM pending", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rule_set, None);
    }

    #[test]
    fn migrating_twice_is_a_no_op() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(migrate(&mut conn).unwrap(), SCHEMA_VERSION);
        assert_eq!(version(&conn), SCHEMA_VERSION);
    }

    #[test]
    fn newer_schema_is_refused() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        assert!(matches!(
            migrate(&mut conn),
            Err(StoreError::SchemaTooNew { found, supported })
                if found == SCHEMA_VERSION + 1 && supported == SCHEMA_VERSION
        ));
    }

    #[test]
    fn later_migrations_apply_in_order_and_failures_roll_back() {
        let mut conn = Connection::open_in_memory().unwrap();
        let steps = [
            "CREATE TABLE a (x INTEGER);",
            "ALTER TABLE a ADD COLUMN y INTEGER;",
        ];
        migrate_with(&mut conn, &steps[..1]).unwrap();
        assert_eq!(version(&conn), 1);
        migrate_with(&mut conn, &steps).unwrap();
        assert_eq!(version(&conn), 2);
        let broken = [steps[0], steps[1], "CREATE TABLE b (x INTEGER); NOT SQL;"];
        assert!(migrate_with(&mut conn, &broken).is_err());
        assert_eq!(version(&conn), 2);
        let b_exists: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name = 'b'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(b_exists, 0);
    }
}
