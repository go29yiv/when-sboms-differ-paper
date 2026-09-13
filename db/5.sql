BEGIN EXCLUSIVE;

CREATE TABLE sbomqs (
    id INTEGER PRIMARY KEY,
    sbom_id INTEGER NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,

    version TEXT NOT NULL,

    score REAL NOT NULL,
    grade TEXT CHECK (grade IN ('A', 'B', 'C', 'D', 'E', 'F')) NOT NULL,

    num_components INTEGER NOT NULL,

    created_at TEXT DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE sbomqs_profile (
    sbomqs_id INTEGER NOT NULL REFERENCES sbomqs(id) ON DELETE CASCADE,
    profile_def_id INTEGER NOT NULL REFERENCES sbomqs_profile_def(id),

    score REAL NOT NULL,
    grade TEXT CHECK (grade IN ('A', 'B', 'C', 'D', 'E', 'F')) NOT NULL,

    PRIMARY KEY (sbomqs_id, profile_def_id)
) STRICT;

CREATE TABLE sbomqs_profile_def (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE -- e.g. "Interlynk", "NTIA Minimum Elements (2021)", "BSI TR-03183-2 v1.1"
) STRICT;

CREATE TABLE sbomqs_raw (
    sbomqs_id INTEGER PRIMARY KEY REFERENCES sbomqs(id) ON DELETE CASCADE,
    raw TEXT NOT NULL
) STRICT;

CREATE INDEX idx_sbomqs_sbom_id ON sbomqs(sbom_id);
CREATE INDEX idx_sbomqs_grade ON sbomqs(grade);
CREATE INDEX idx_sbomqs_profile_def_grade ON sbomqs_profile(profile_def_id, grade);

COMMIT;
