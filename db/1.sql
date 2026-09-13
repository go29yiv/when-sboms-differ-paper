CREATE TABLE IF NOT EXISTS creators
(
    id INTEGER PRIMARY KEY,

    type TEXT CHECK (type IN ('person', 'organization', 'tool')) NOT NULL,

    name TEXT NOT NULL,
    email TEXT, -- only relevant if this represents a person
    version TEXT, -- only relevant if this represents a tool

    UNIQUE(name, email, version)
) STRICT;

CREATE TABLE IF NOT EXISTS sbom_creators
(
    sbom_id INTEGER NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
    creator_id INTEGER NOT NULL REFERENCES creators(id) ON DELETE CASCADE,

    PRIMARY KEY (sbom_id, creator_id)
) STRICT;

CREATE TABLE IF NOT EXISTS sboms
(
    id INTEGER PRIMARY KEY,

    repository_state_id INTEGER NOT NULL REFERENCES repository_states(id) ON DELETE CASCADE,

    type TEXT CHECK (type IN ('SPDX', 'CycloneDX')) NOT NULL,
    version TEXT NOT NULL,
    raw TEXT NOT NULL,

    -- sbom origin information --
    origin_type TEXT CHECK (origin_type IN ('downloaded', 'generated')) NOT NULL,
    origin_url TEXT, -- only for downloaded origin

    created_at TEXT DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE IF NOT EXISTS repository_states
(
    id INTEGER PRIMARY KEY,
    repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,

    commit_hash TEXT NOT NULL,

    created_at TEXT DEFAULT CURRENT_TIMESTAMP,

    -- I find it somewhat likely to have 2 different repositories to have commits with identical hashes, so we enforce uniqueness on the repo AND commit
    -- however, two commits with the same hash in one repo, while not impossible (but still unlikely), seem to cause havoc anyway. So I don't care (https://stackoverflow.com/questions/10434326/hash-collision-in-git)
    UNIQUE(repository_id, commit_hash)
) STRICT;

CREATE TABLE IF NOT EXISTS repositories
(
    id INTEGER PRIMARY KEY,

    name TEXT NOT NULL,
    owner TEXT NOT NULL,
    url TEXT UNIQUE NOT NULL,

    stars INTEGER, -- as estimated by the github api
    size INTEGER, -- as estimated by the github api (I need these estimates in order to get a rough idea on how costly materialization of this repo would be)

    created_at TEXT DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE IF NOT EXISTS repository_languages
(
    repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    language_id INTEGER NOT NULL REFERENCES languages(id) ON DELETE RESTRICT,

    percentage REAL CHECK (percentage >= 0.0 AND percentage <= 100.0) NOT NULL,

    created_at TEXT DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE IF NOT EXISTS languages
(
    id INTEGER PRIMARY KEY,
    name TEXT
) STRICT;
