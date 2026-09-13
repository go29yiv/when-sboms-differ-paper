import os
import sys
import tarfile
import tempfile
import requests

from pathlib import Path
from tqdm import tqdm

import pandas as pd

from typing import List
from typing import Optional

if __name__ == "__main__":
    print("this is not a script")
    sys.exit(0)

ARCHIVE = f"db-dump.tar.gz"
# crates.io provides a complete datase dump, which is updated every 24 hours
# see https://crates.io/data-access#database-dumps
CRATES_IO_DB_DUMP_URL = f"https://static.crates.io/{ARCHIVE}"

def _download_crates_io_db(dir):
    tar_path = os.path.join(dir, ARCHIVE)

    # assume cached db if the tarfile exists
    if Path(tar_path).exists():
        print("Detected cached crates.io dump! Skipping download.")
        return

    response = requests.get(CRATES_IO_DB_DUMP_URL, stream=True)
    response.raise_for_status()

    with open(tar_path, 'wb') as f:
        for chunk in tqdm(response.iter_content(chunk_size=65636), desc="Downloading crates.io"):
            f.write(chunk)

    with tarfile.open(tar_path, 'r:gz') as tar:
        tar.extractall(path=dir)

# this function just steps through one folder level iff there is only one folder present in the given directory
def _traverse_inner_directory(path):
    entries = os.listdir(path)
    dirs = [e for e in entries if os.path.isdir(os.path.join(path, e))]

    if len(dirs) < 1:
        raise OSError("No inner directory found.")
    elif len(dirs) > 1:
        raise OSError("Too many inner directories found.")

    return os.path.join(path, dirs[0])

def _read_csv_column(csv_path, key):
    df = pd.read_csv(csv_path, usecols=[key])
    return df[key].tolist()

def project_repo_list(cache_dir: Optional[str]=None) -> List[str]:
    print("Scraping Rust projects from crates.io")
    with tempfile.TemporaryDirectory() as tmpdir:
        # tmpdir is created regardless, but cache_dir is mostly for quick testing anyways. So this inefficiency doesn't matter...
        dir = tmpdir if cache_dir is None else cache_dir

        _download_crates_io_db(dir)

        # the downloaded db contains a timestamped folder. We just want to skip past it to get to the actual data
        db_base_path = _traverse_inner_directory(dir)

        crates_csv = os.path.join(os.path.join(db_base_path, "data"), "crates.csv")

        # These are all the available keys
        # created_at,description,documentation,homepage,id,max_features,max_upload_size,name,readme,repository,updated_at
        projects = _read_csv_column(crates_csv, "repository")

    # some crates just exist without providing anything creating a NaN repository entry (oftentimes reserving a crate-name for future use)
    return list(set([p for p in projects if type(p) is str]))
