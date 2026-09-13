import sys

from typing import Dict

if __name__ == "__main__":
    sys.exit("this is not a script")

# sbom names as they are used in the db
SPDX = "SPDX"
CYCLONEDX = "CycloneDX"

def get_first_id_from_by_kv(cur, table, key, value):
    cur.execute(f"SELECT id FROM {table} WHERE {key} = ?", (value,))
    row = cur.fetchone()

    if row:
        return row[0]
    else:
        return None

# languages is the dictionary as returned by the github api
def update_or_add_repo(cur, repo: str, owner: str, url: str, stars: int, size: int, languages: Dict[str, int]) -> int:
    if (repo_id := get_first_id_from_by_kv(cur, "repositories", "url", url)) is None:
        cur.execute("""
            INSERT INTO repositories (name, owner, url, stars, size)
            VALUES (?, ?, ?, ?, ?)
        """, (repo, owner, url, stars, size,))
        repo_id = cur.lastrowid

    # remove all existing stats for the repository before proceeding
    cur.execute("""
        DELETE FROM repository_languages
        WHERE repository_id IN (
            SELECT id
            FROM repositories
            WHERE id = ?
        )
    """, (repo_id,))

    # add language distribution for repository
    languages_total_amount = sum(languages.values())
    for lang, amount in languages.items():
        percentage = max(0.0, min((amount / languages_total_amount) * 100.0, 100.0))

        if (lang_id := get_first_id_from_by_kv(cur, "languages", "name", lang)) is None:
            cur.execute("""
                INSERT INTO languages (name)
                VALUES (?)
            """, (lang,))
            lang_id = cur.lastrowid

        cur.execute("""
            INSERT INTO repository_languages (repository_id, language_id, percentage)
            VALUES (?, ?, ?)
        """, (repo_id, lang_id, percentage))

    return repo_id

def add_creator_org(cur, name: str) -> int:
    cur.execute("""
        SELECT id FROM creators
        WHERE name = ? AND type = 'organization'
    """, (name,))
    if (row := cur.fetchone()) is None:
        cur.execute("""
            INSERT INTO creators (type, name, email, version)
            VALUES ('organization', ?, NULL, NULL)
        """, (name,))
        return cur.lastrowid
    return row[0]

def add_creator_tool(cur, name: str, version: str) -> int:
    cur.execute("""
        SELECT id FROM creators
        WHERE name = ? AND type = 'tool' AND version = ?
    """, (name, version,))
    if (row := cur.fetchone()) is None:
        cur.execute("""
            INSERT INTO creators (type, name, email, version)
            VALUES ('tool', ?, NULL, ?)
        """, (name, version,))
        return cur.lastrowid
    return row[0]
