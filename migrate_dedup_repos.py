#!/usr/bin/env python3
"""
One-off migration: resolve GitHub redirects and merge duplicate repository entries.

For each repository in the DB, calls the GitHub API to get the canonical URL via
repo_data["html_url"]. When multiple DB entries resolve to the same canonical URL,
they are merged:
  - repository_states not in the winner are re-parented to the winner (if the
    commit_hash is unique) or deleted (if the winner already has that commit_hash,
    which cascades through sboms, sbom_raw, sbom_creators, sbomqs, etc.)
  - The duplicate repositories rows are then deleted (CASCADE handles
    repository_languages and any remaining repository_states children).
  - The winner's name/owner/url are updated to the canonical values from GitHub.

Usage:
  python migrate_dedup_repos.py --dry-run   # preview only
  python migrate_dedup_repos.py             # apply changes
"""

import os
import sys
import time
import logging
import argparse
from collections import defaultdict

import requests
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(__file__))
from utilities.utils import get_db, normalize_github_url, make_session, exponential_backoff

GH_TOKEN = os.getenv("GH_TOKEN")
if not GH_TOKEN:
    sys.exit("Provide GH_TOKEN env variable.")

GH_HEADERS = {
    "Authorization": f"Bearer {GH_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def get_canonical(session, owner, repo):
    """Returns (canonical_owner, canonical_repo, canonical_url) or None on failure/404."""
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    backoff = exponential_backoff(base=60)

    for _ in range(5):
        try:
            r = session.get(api_url, headers=GH_HEADERS)
        except requests.RequestException as e:
            logging.warning(f"Request error for {owner}/{repo}: {e}")
            return None

        remaining = int(r.headers.get("x-ratelimit-remaining", 1))
        reset = int(r.headers.get("x-ratelimit-reset", 0))

        if r.status_code == 200:
            data = r.json()
            canonical_url = normalize_github_url(data["html_url"])
            return data["owner"]["login"].lower(), data["name"].lower(), canonical_url

        if r.status_code in (403, 429):
            if remaining == 0:
                delay = max(reset - time.time(), 0) + 2
                logging.info(f"Primary rate limit hit. Sleeping {delay:.0f}s")
            elif "retry-after" in r.headers:
                delay = int(r.headers["retry-after"]) + 2
                logging.info(f"Secondary rate limit (retry-after). Sleeping {delay:.0f}s")
            else:
                delay = next(backoff)
                logging.info(f"Secondary rate limit (backoff). Sleeping {delay:.0f}s")
            time.sleep(delay)
            continue

        if r.status_code == 404:
            logging.warning(f"Repo not found (deleted/private?): {owner}/{repo}")
            return None

        logging.warning(f"HTTP {r.status_code} for {owner}/{repo}")
        return None

    logging.error(f"Failed after 5 attempts: {owner}/{repo}")
    return None


def merge_into_winner(con, winner_id, duplicate_id, dry_run):
    cur = con.cursor()

    cur.execute(
        "SELECT id, commit_hash FROM repository_states WHERE repository_id = ?",
        (duplicate_id,),
    )
    dup_states = [(row["id"], row["commit_hash"]) for row in cur.fetchall()]

    cur.execute(
        "SELECT commit_hash FROM repository_states WHERE repository_id = ?",
        (winner_id,),
    )
    winner_hashes = {row["commit_hash"] for row in cur.fetchall()}

    to_delete = [(sid,) for sid, ch in dup_states if ch in winner_hashes]
    to_move   = [(winner_id, sid) for sid, ch in dup_states if ch not in winner_hashes]

    logging.info(
        f"  repo id={duplicate_id}: {len(to_delete)} conflicting states → delete, "
        f"{len(to_move)} unique states → re-parent to winner id={winner_id}"
    )

    if not dry_run:
        if to_delete:
            cur.executemany("DELETE FROM repository_states WHERE id = ?", to_delete)
        if to_move:
            cur.executemany(
                "UPDATE repository_states SET repository_id = ? WHERE id = ?", to_move
            )
        # CASCADE handles repository_languages and any leftover repository_states children
        cur.execute("DELETE FROM repositories WHERE id = ?", (duplicate_id,))

    cur.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without modifying the DB.")
    parser.add_argument("--log-file", default="migrate_dedup.log", help="Log file path.")
    args = parser.parse_args()

    logging.basicConfig(
        filename=args.log_file,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if args.dry_run:
        print("[DRY RUN] No changes will be written.")

    con = get_db()
    con.execute("PRAGMA foreign_keys = ON")

    cur = con.cursor()
    cur.execute("SELECT id, name, owner, url FROM repositories")
    repos = [dict(r) for r in cur.fetchall()]
    cur.close()

    print(f"Loaded {len(repos)} repositories from DB.")

    session = make_session()

    # Step 1: resolve canonical URL for every repo in the DB
    canonical_map = {}  # db_id → (canonical_owner, canonical_name, canonical_url)
    skipped = []
    for r in tqdm(repos, desc="Resolving canonical URLs via GitHub API"):
        result = get_canonical(session, r["owner"], r["name"])
        if result is not None:
            canonical_map[r["id"]] = result
        else:
            skipped.append(r)
            logging.warning(f"Skipping unresolvable repo: id={r['id']} url={r['url']}")

    if skipped:
        print(f"Could not resolve {len(skipped)} repos (deleted/private/rate-limited) — skipped. See {args.log_file}.")

    # Step 2: group DB entries by canonical URL
    groups = defaultdict(list)  # canonical_url → [db_id, ...]
    for db_id, (_, _, c_url) in canonical_map.items():
        groups[c_url].append(db_id)

    duplicates = {url: ids for url, ids in groups.items() if len(ids) > 1}
    print(f"Found {len(duplicates)} canonical URL(s) with multiple DB entries.")

    if not duplicates:
        print("No duplicates. Nothing to do.")
        con.close()
        return

    id_to_repo = {r["id"]: r for r in repos}

    # Step 3: for each duplicate group, pick a winner and merge
    for canonical_url, db_ids in duplicates.items():
        cur = con.cursor()
        placeholders = ",".join("?" * len(db_ids))
        cur.execute(
            f"SELECT repository_id, COUNT(*) as cnt FROM repository_states "
            f"WHERE repository_id IN ({placeholders}) GROUP BY repository_id",
            db_ids,
        )
        state_counts = {row["repository_id"]: row["cnt"] for row in cur.fetchall()}
        cur.close()

        # Winner preference: URL already matches canonical > most states > lowest id
        def winner_key(db_id):
            return (
                id_to_repo[db_id]["url"] == canonical_url,
                state_counts.get(db_id, 0),
                -db_id,
            )

        sorted_ids = sorted(db_ids, key=winner_key, reverse=True)
        winner_id = sorted_ids[0]
        dup_ids = sorted_ids[1:]

        c_owner, c_name, _ = canonical_map[winner_id]

        print(f"\nCanonical URL: {canonical_url}")
        print(f"  Winner  : id={winner_id}  stored='{id_to_repo[winner_id]['url']}'")
        for d in dup_ids:
            print(f"  Merging : id={d}  stored='{id_to_repo[d]['url']}'")

        for dup_id in dup_ids:
            merge_into_winner(con, winner_id, dup_id, args.dry_run)

        # Update winner's name/owner/url to canonical values if they differ
        w = id_to_repo[winner_id]
        if w["url"] != canonical_url or w["owner"] != c_owner or w["name"] != c_name:
            print(f"  Updating winner: url={canonical_url}, owner={c_owner}, name={c_name}")
            if not args.dry_run:
                cur = con.cursor()
                cur.execute(
                    "UPDATE repositories SET url = ?, owner = ?, name = ? WHERE id = ?",
                    (canonical_url, c_owner, c_name, winner_id),
                )
                cur.close()

        if not args.dry_run:
            con.commit()

    if args.dry_run:
        print("\n[DRY RUN] No changes were made to the DB.")
    else:
        print("\nMigration complete.")

    con.close()


if __name__ == "__main__":
    main()
