-- 0001: foundation tables shared by every component.

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Append-only record of every action Snare takes. Rows are never updated or
-- deleted; an undo is a new row that references the action it reverses.
CREATE TABLE action_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    actor       TEXT    NOT NULL CHECK (actor IN ('policy', 'human')),
    kind        TEXT    NOT NULL,             -- e.g. rule.promote, key.deactivate
    subject     TEXT    NOT NULL,             -- what the action applied to
    evidence    TEXT    NOT NULL DEFAULT '{}',-- JSON
    undo        TEXT,                         -- JSON undo handle, NULL if irreversible
    reverses_id INTEGER REFERENCES action_log(id)
);
CREATE INDEX action_log_subject ON action_log(subject);

CREATE TRIGGER action_log_no_update BEFORE UPDATE ON action_log
BEGIN SELECT RAISE(ABORT, 'action_log is append-only'); END;
CREATE TRIGGER action_log_no_delete BEFORE DELETE ON action_log
BEGIN SELECT RAISE(ABORT, 'action_log is append-only'); END;

-- Queue for irreversible or risky actions that need a person to decide.
CREATE TABLE approvals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    kind        TEXT NOT NULL,
    subject     TEXT NOT NULL,
    proposal    TEXT NOT NULL,                -- JSON: what would be done and why
    state       TEXT NOT NULL DEFAULT 'pending'
                CHECK (state IN ('pending', 'approved', 'rejected', 'expired')),
    decided_at  TEXT,
    decided_by  TEXT,
    action_id   INTEGER REFERENCES action_log(id)
);
CREATE INDEX approvals_state ON approvals(state);
