// SPDX-License-Identifier: GPL-3.0-or-later
//! Versioned schema migrations, tracked in SQLite's `user_version`.
//!
//! Migrations only ever get appended. Each runs in its own transaction together with the
//! version bump, so a crash leaves the database at the previous version, never in between.

use rusqlite::Connection;

use crate::error::StoreError;

/// Schema migrations; entry `n` takes the database from version `n` to `n + 1`.
const MIGRATIONS: &[&str] = &[V1];

/// The schema version this build writes.
pub const SCHEMA_VERSION: u32 = 1;

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

/// Brings `conn` to [`SCHEMA_VERSION`] and returns the version it started at.
///
/// # Errors
/// [`StoreError::SchemaTooNew`] for a database written by a newer puddle (never downgraded),
/// or the SQLite error of a failed migration (which is rolled back).
pub(crate) fn migrate(conn: &mut Connection) -> Result<u32, StoreError> {
    migrate_with(conn, MIGRATIONS)
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
