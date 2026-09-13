import json
import logging

from tqdm import tqdm
from pathlib import Path

from scraper.ecosystem_support import rust, python

from utilities.utils import *
from utilities.queries import *

if __name__ == "__main__":
    print("this is not a script")
    sys.exit(0)

def add_github_sboms(repos):
    from scraper.github_utils import fetch_repo_data, parse_owner_repo

    con = get_db()
    cur = con.cursor()

    for url in tqdm(repos, desc="Updating Database"):
        # this is not the api link, this is the link which is stored in the database that references the donwload location for the sbom
        origin_url = add_to_url_path(url, "network", "dependencies")

        if (tmp := parse_owner_repo(url)) is None:
            continue

        owner, repo = tmp

        if (data := fetch_repo_data(owner, repo)) is None:
            continue

        repo_meta_data = data["repo_data"]

        # prepare data
        stars = repo_meta_data["stargazers_count"]
        size = repo_meta_data["size"]

        canonical_url = normalize_github_url(repo_meta_data["html_url"]) or url
        canonical_owner = repo_meta_data["owner"]["login"]                                                                                                                                             
        canonical_repo  = repo_meta_data["name"]
        origin_url = add_to_url_path(canonical_url, "network", "dependencies")

        commit_hash = data["commit_hash"]
        sbom = data["sbom"]
        languages = data["languages"]

        # parse data from sbom
        spdx_version = sbom["spdxVersion"].split("-")[1]
        [tool, version] = sbom["creationInfo"]["creators"][0][6:].split("-")[:2]

        # store data in database
        repo_id = update_or_add_repo(cur, canonical_repo, canonical_owner, canonical_url, stars, size, languages)  

        cur.execute("""
            SELECT id FROM repository_states
            WHERE repository_id = ? AND commit_hash = ?
        """, (repo_id, commit_hash,))
        if (state_id := cur.fetchone()) is not None:
            # check if we already have a github provided SBOM for this commit
            cur.execute("""
                SELECT s.id FROM sboms s
                JOIN sbom_creators sc ON sc.sbom_id = s.id
                JOIN creators c ON c.id = sc.creator_id
                WHERE s.repository_state_id = ?
                AND c.type = 'tool' AND c.name = ? AND c.version = ?
            """, (state_id, tool, version,))

            if cur.fetchone():
                continue # we already have a GitHub provided SBOM for this commit
        else:
            # since this commit is new, we cannot have an SBOM for this state yet
            cur.execute("""
                INSERT INTO repository_states (repository_id, commit_hash)
                VALUES (?, ?)
            """, (repo_id, commit_hash))
            state_id = cur.lastrowid

        # add the sbom meta data
        cur.execute("""
            INSERT INTO sboms (repository_state_id, type, version, origin_type, origin_url)
            VALUES (?, 'SPDX', ?, 'downloaded', ?)
        """, (state_id, spdx_version, origin_url))
        sbom_id = cur.lastrowid

        # add the actual sbom to a blob table
        cur.execute("""
            INSERT INTO sbom_raw (sbom_id, raw)
            VALUES(?, ?)
        """, (sbom_id, json.dumps(sbom, indent=4)))

        # add GitHub organization as creator
        org_id = add_creator_org(cur, "GitHub")
        tool_id = add_creator_tool(cur, tool, version)

        rows = [(sbom_id, org_id), (sbom_id, tool_id)]

        cur.executemany("""
            INSERT INTO sbom_creators (sbom_id, creator_id)
            VALUES (?, ?)
        """, rows)

        con.commit()

    cur.close()
    con.commit()
    con.close()

def arguments(parser):
    parser.description = "SBOM-Dataset collection"

    parser.add_argument("--cache-dir", type=str, required=False, help="Cache directory for all downloads. If you need fresh data, either ensure that the cashes are non existent or omit this argument.")
    parser.add_argument("--log-file", type=str, required=False, help="Log file.", default = "./scraper.log")

    parser.add_argument("--limit", type=int, required=False, help="Limits the amount of repositories to be scraped.")

    data_source_group = parser.add_mutually_exclusive_group(required=True)
    data_source_group.add_argument("--source-ecosystem", choices=["Rust", "Python"])
    data_source_group.add_argument("--source-file", type=str, help="Repository Links for SBOM analysis (JSON array).")

    parser.add_argument("--to-source-file", type=str, required=False, help="All repositories collected from the datasource will be saved to the specified file")

    parser.add_argument("--allow-updates", action="store_true", help="Allows updating/adding data to already existing Database entries.")

def main(args):
    logging.basicConfig(filename=args.log_file, level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    if (cache_dir := args.cache_dir):
        path = Path(cache_dir)
        if path.exists() and not path.is_dir():
            sys.exit(f"{cache_dir} exists but is not a directory!")

        path.mkdir(parents=True, exist_ok=True)

    # Collect base data from data source (usually just repository links for scraping)
    source = None
    match args.source_ecosystem:
        case "Rust":
            source = rust.project_repo_list(cache_dir=args.cache_dir)
        case "Python":
            source = python.project_repo_list(cache_dir=args.cache_dir)
        case _:
            if not args.source_file:
                sys.exit("Unknown source for sbom scraping.")

            with open(args.source_file, "r") as f:
                source = json.load(f)

            # check if the file has at least the correct types (this does not check if we actually got any urls)
            if not (isinstance(source, list) and all(isinstance(item, str) for item in source)):
                sys.exit(f"Provided data source {args.source_file} is not a list of strings!")

    assert source is not None

    source_gh = {url for url in (normalize_github_url(url) for url in source) if url is not None} # set is intentional for deduplication
    print(f"Found {len(source_gh)} Github projects from datasource {args.source_ecosystem}.")

    # Check if the data should be collected to a file or continue with scraping
    if (source_file := args.to_source_file):
        print(f"Saving collected repository links to {source_file}.")
        with open(source_file, 'w') as f:
            json.dump(list(source_gh), f, indent=4)

    # Now actually scrape the repositories and save the data to DB
    if not args.allow_updates:
        con = get_db()
        con.row_factory = sqlite3.Row

        cur = con.execute("SELECT url FROM repositories")
        urls_in_db = {row["url"] for row in cur.fetchall()}
        print(f"Updates are disallowed. Removing {len(urls_in_db)} already existing entries from datasource.")
        filtered_gh = list((source_gh - urls_in_db))

        con.close()
    else:
        sys.exit("Updates are currently not implemented")
        filtered_gh = list(source_gh)

    assert isinstance(filtered_gh, list)

    if (limit := args.limit):
        assert limit >= 0
        filtered_gh = filtered_gh[:limit]

    add_github_sboms(filtered_gh)
