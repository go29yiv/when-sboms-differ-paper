BEGIN EXCLUSIVE;

CREATE TABLE repositories_new
(
    id INTEGER PRIMARY KEY,

    name TEXT NOT NULL CHECK (name = LOWER(name)),
    owner TEXT NOT NULL CHECK (owner = LOWER(owner)),
    url TEXT UNIQUE NOT NULL CHECK (url = LOWER(url)),

    stars INTEGER, -- as estimated by the github api
    size INTEGER, -- as estimated by the github api (I need these estimates in order to get a rough idea on how costly materialization of this repo would be)

    created_at TEXT DEFAULT CURRENT_TIMESTAMP
) STRICT;

INSERT INTO repositories_new (id, name, owner, url, stars, size, created_at)
SELECT id, LOWER(name), LOWER(owner), LOWER(url), stars, size, created_at FROM repositories;

PRAGMA foreign_keys = OFF;

DROP TABLE repositories;
ALTER TABLE repositories_new RENAME TO repositories;

COMMIT;
