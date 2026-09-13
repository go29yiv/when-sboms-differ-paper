import os
import logging
import subprocess
import json

from concurrent.futures import ProcessPoolExecutor, as_completed

from utilities.utils import *
from utilities.queries import *

TOOLS = {
    # tool, version, sha256
    "sbomqs": ("2.0.5", "0b2cdfe679610f1af10e84c722280aa179387ad4ead0620633bb49837bdfcf07"),
}
INSTALL_DIR = "./analysis/tools/"

BATCH_SIZE = 500
NUM_WORKERS = 16
WRITE_BATCH = 300

def install_tools(tool_dir):
    print("installing analysis tools")
    os.makedirs(tool_dir, exist_ok=True)

    for tool, (version, hash) in TOOLS.items():
        out = os.path.join(tool_dir, tool)

        if os.path.isfile(out):
            continue

        match tool:
            case "sbomqs":
                url = f"https://github.com/interlynk-io/sbomqs/releases/download/v{version}/sbomqs_{version}_Linux_x86_64.tar.gz"
                download_tar_extract(url, 'r:gz', tool, out)
            case _:
                sys.exit(f"Missing tool installer for {tool}!")

        if hash != comp_sha256(out):
            os.remove(out)
            sys.exit(f"[ABORTING] Installation of {tool} failed due to mismatched hash!")

        os.chmod(out, 0o555)

    print("> all tools installed")

def fetch_unscored_sbom_batch():
    con = get_db()
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    while True:
        cur.execute("""
            SELECT
                sr.sbom_id, sr.raw
            FROM sbom_raw sr
                JOIN sboms s ON s.id = sr.sbom_id
                LEFT JOIN sbomqs sqs ON sqs.sbom_id = s.id WHERE sqs.id IS NULL
            ORDER BY sr.sbom_id LIMIT ?
        """, (BATCH_SIZE,))
        rows = cur.fetchall()

        if not rows:
            logging.info("no more unscored sboms")
            break

        yield [(int(r["sbom_id"]), r["raw"]) for r in rows]

    cur.close()
    con.close()

def score_sbom(sbom_id: int, raw: str):
    with tempfile.NamedTemporaryFile(delete=True, prefix="sbom_dataset_", suffix=".json") as f:
        f.write(raw.encode("utf-8"))
        f.flush()

        try:
            process = subprocess.run([f"{INSTALL_DIR}/sbomqs", "score", "--json", f.name], stdout=subprocess.PIPE)
            if process.returncode == 0:
                res = json.loads(process.stdout)
                return res

            logging.error(f"[sbom: {sbom_id}] sbomqs returned nonzero exit: {process.returncode}")
            return None
        except Exception as e:
            logging.error(f"[sbom: {sbom_id}] scoring failed with: {e}")
            return None


def pipeline():
    _profile_def_cache: dict[str, int] = {}
    def add_sbomqs_profile_def(cur, name: str) -> int:
        if name in _profile_def_cache:
            return _profile_def_cache[name]

        cur.execute("""
            SELECT id FROM sbomqs_profile_def
            WHERE name = ?
        """, (name,))
        if (row := cur.fetchone()) is None:
            cur.execute("""
                INSERT INTO sbomqs_profile_def (name)
                VALUES (?)
            """, (name,))
            profile_id = cur.lastrowid
        else:
            profile_id = row[0]

        _profile_def_cache[name] = profile_id
        return profile_id

    with ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
        for idx, batch in enumerate(fetch_unscored_sbom_batch()):
            logging.info(f"processing batch {idx}")
            futures = {}
            results = {}

            for (sbom_id, raw) in batch:
                future = executor.submit(score_sbom, sbom_id, raw)
                futures[future] = sbom_id

            for future in tqdm(as_completed(futures), total=len(futures), desc=f"batch {idx}"):
                sbom_id = futures[future]
                try:
                    res = future.result()
                    if res is None:
                        continue

                    assert len(res["files"]) == 1
                    results[sbom_id] = res

                except Exception as e:
                    logging.error(f"scoring for sbom {sbom_id} failed with: {e}")

            logging.info(f"adding results from batch {idx}")

            with get_db() as con:
                cur = con.cursor()
                for sbom_id, res in results.items():
                    file = res["files"][0]

                    cur.execute("""
                        INSERT INTO sbomqs (sbom_id, version, score, grade, num_components)
                        VALUES (?, ?, ?, ?, ?)
                    """, (sbom_id, res["creation_info"]["version"], float(file["sbom_quality_score"]), file["grade"], int(file["num_components"])))
                    sbomqs_id = cur.lastrowid

                    cur.execute("""
                        INSERT INTO sbomqs_raw (sbomqs_id, raw)
                        VALUES (?, ?)
                    """, (sbomqs_id, json.dumps(res, indent=4)))

                    profile_rows = [
                        (sbomqs_id, add_sbomqs_profile_def(cur, p["profile"]), float(p["score"]), p["grade"])
                        for p in file["profiles"]
                    ]

                    cur.executemany("""
                        INSERT INTO sbomqs_profile (sbomqs_id, profile_def_id, score, grade)
                        VALUES (?, ?, ?, ?)
                    """, profile_rows)

                con.commit()
                cur.close()

def arguments(parser):
    parser.description = "SBOM-Dataset scoring"

    parser.add_argument("--log-file", type=str, required=False, help="Log file", default = "./score.log")

    parser.add_argument("--batch-size", type=int, required=False, help=f"SBOM batch size for scoring (default: {BATCH_SIZE})", default=BATCH_SIZE)
    parser.add_argument("--num-workers", type=int, required=False, default=NUM_WORKERS, help=f"Number of parallel workers (default: {NUM_WORKERS})")

def main(args):
    global BATCH_SIZE, NUM_WORKERS

    if not os.path.exists("sboms.db"):
        sys.exit("Did not find Database! Use the scraper to aquire some data first!")

    install_tools(INSTALL_DIR)

    if (batch_size := args.batch_size):
        BATCH_SIZE = batch_size

    if (num_workers := args.num_workers):
        NUM_WORKERS = num_workers

    logging.basicConfig(filename=args.log_file, level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    pipeline()
