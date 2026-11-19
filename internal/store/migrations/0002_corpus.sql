-- 0002: benign corpus recorded by the gateway or imported.
--
-- The full exchange (redacted headers and bodies) is sealed with AES-256-GCM
-- in `sealed`. The plaintext columns hold only what coverage queries need,
-- and they are derived from already-redacted data.

CREATE TABLE corpus_exchanges (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT    NOT NULL,
    route         TEXT    NOT NULL,
    source        TEXT    NOT NULL CHECK (source IN ('live', 'har')),
    method        TEXT    NOT NULL,
    path_template TEXT    NOT NULL,             -- redacted path, ids replaced by {n}/{id}
    status        INTEGER NOT NULL,
    duration_ms   REAL    NOT NULL DEFAULT 0,
    req_bytes     INTEGER NOT NULL DEFAULT 0,
    resp_bytes    INTEGER NOT NULL DEFAULT 0,
    params        TEXT    NOT NULL DEFAULT '[]', -- JSON list of "query:q", "form:x", "json:a.b"
    sealed        BLOB    NOT NULL
);
CREATE INDEX corpus_route_template ON corpus_exchanges(route, method, path_template);

-- When each route started recording, for the learning period.
CREATE TABLE route_learning (
    route      TEXT PRIMARY KEY,
    started_at TEXT NOT NULL
);
