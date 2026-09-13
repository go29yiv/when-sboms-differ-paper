import sys
import os
import re
import sqlite3
import tempfile
import shutil
import hashlib
import tarfile

from tqdm import tqdm
from posixpath import join as urljoin
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from typing import Optional

CHUNK_SZ = 65636

if __name__ == "__main__":
    sys.exit("this is not a script")

def get_db():
    con = sqlite3.connect("sboms.db", timeout=120)

    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")

    con.row_factory = sqlite3.Row
    return con

def init_db():
    db = get_db()
    cur = db.execute("PRAGMA user_version")
    row = cur.fetchone()
    version = row[0] if row else 0
    cur.close()

    to_run = {}
    for file in os.listdir("db"):
        match = re.match(r"(\d+)\.sql", file)
        if not match:
            continue
        target_version = int(match.group(1))
        if version >= target_version:
            continue
        with open(f"db/{file}") as f:
            to_run[target_version] = f.read()

    if not to_run:
        # Nothing to do
        print(f"Nothing to do, database (version {version}) is up to date")
        return

    new_version = max(to_run)
    if version > 0:
        print(f"Upgrading database from version {version} to version {new_version}")
    else:
        print(f"Creating database (version {new_version})")
    # Check we have _all_ intermediate versions
    expected_keys = list(range(version + 1, new_version + 1))
    for key in expected_keys:
        if key not in to_run:
            raise FileNotFoundError(f"Missing DB upgrade script for version {key}")
        print(f"Executing db script {key}")
        db.executescript(to_run[key])

    # Can't prepare the PRAGMA, unfortunately.
    assert isinstance(new_version, int)
    db.execute(f"PRAGMA user_version = {new_version}")

    db.commit()
    if version > 0:
        print("Database upgraded")
    else:
        print("Database created")

    db.close()

# expectation is to only handle links of the form `https://github.com/<owner>/<repo>`
# common "failures" (as seen in github links from crates.io):
# - https://github.com/<owner>/<repo>.git
# - https://github.com//<owner>//<repo>
# - https://github.com/<owner>/<repo>/tree/main/<some-sub-path>
def normalize_github_url(url: str) -> Optional[str]:
    parsed = urlparse(url)
    if parsed.netloc != "github.com":
        return None

    normalized_path = re.sub(r'/+', '/', parsed.path).strip("/")
    parts = normalized_path.split('/')

    if len(parts) < 2:
        return None

    owner, repo = parts[0], parts[1]

    if repo.endswith(".git"):
        repo = repo[:-4]

    # is this actually sane with .lower()?
    return f"https://github.com/{owner}/{repo}".lower()

def add_to_url_path(url: str, *parts: str) -> str:
    parsed = urlparse(url)

    new_path = urljoin(parsed.path, *parts)

    if not new_path.startswith('/'):
        new_path = '/' + new_path

    return urlunparse(parsed._replace(path=new_path))

def exponential_backoff(base=60):
    iteration = 0
    while True:
        yield base * (2 ** iteration)
        iteration += 1

def make_session():
    session = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=4,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "HEAD", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def comp_sha256(file):
    sha256 = hashlib.sha256()
    with open(file, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SZ), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def download_blob(url, file, download_text):
    response = requests.get(url, stream=True)
    response.raise_for_status()

    with open(file, "wb") as f:
        for chunk in tqdm(response.iter_content(chunk_size=CHUNK_SZ), desc=download_text):
            f.write(chunk)

def download_tar_extract(url, mode, tool, out):
    with tempfile.TemporaryDirectory() as tmpdir:
        tar_path = os.path.join(tmpdir, "archive")

        download_blob(url, tar_path, tool)

        with tarfile.open(tar_path, mode) as tar:
            tar.extractall(tmpdir, filter="fully_trusted")

        dl = os.path.join(tmpdir, tool)
        shutil.copyfile(dl, out)
