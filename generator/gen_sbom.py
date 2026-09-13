import os
import logging
import json
import uuid
import subprocess

from tqdm import tqdm
from podman import PodmanClient
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from dataclasses import dataclass
from typing import List, Dict, Set

from utilities.utils import *
from utilities.queries import *

PODMAN_BASE_URL = f"unix:///run/user/{os.getuid()}/podman/podman.sock"
TMP_DIR = "/tmp"

CONTAINER_REPO_DIR = "/repo"
CONTAINER_RESULT_DIR = "/result"

@dataclass
class ToolJob:
    name: str
    cmd: List[str]
    env: Dict[str, str]

@dataclass
class ToolConfig:
    version: str
    repository: str
    build_jobs: List[ToolJob]

    @property
    def image(self) -> str:
        return self.repository.format(version=self.version)

    @property
    def produces(self) -> Set[str]:
        return {job.name for job in self.build_jobs}

TOOLS = {
    "syft": ToolConfig(
        version = "1.42.1",
        repository = "docker.io/anchore/syft:v{version}",
        build_jobs = [
            ToolJob(
                name = SPDX,
                cmd = ["scan", f"dir:{CONTAINER_REPO_DIR}", "-o", f"spdx-json={CONTAINER_RESULT_DIR}/syft_spdx.json"],
                env = {"SYFT_CHECK_FOR_APP_UPDATE": "false"},
            ),
            ToolJob(
                name = CYCLONEDX,
                cmd = ["scan", f"dir:{CONTAINER_REPO_DIR}", "-o", f"cyclonedx-json={CONTAINER_RESULT_DIR}/syft_cyclonedx.json"],
                env = {"SYFT_CHECK_FOR_APP_UPDATE": "false"},
            ),
        ]
    ),
    "trivy": ToolConfig(
        version = "0.69.1",
        repository = "docker.io/aquasec/trivy:{version}",
        build_jobs = [
            ToolJob(
                name = SPDX,
                cmd = ["fs", "--format", "spdx-json", "--include-dev-deps", "--output", f"{CONTAINER_RESULT_DIR}/trivy_spdx.json", CONTAINER_REPO_DIR],
                env = {},
            ),
            ToolJob(
                name = CYCLONEDX,
                cmd = ["fs", "--format", "cyclonedx", "--include-dev-deps", "--output", f"{CONTAINER_RESULT_DIR}/trivy_cyclonedx.json", CONTAINER_REPO_DIR],
                env = {},
            ),
        ]
    ),
    "cdxgen": ToolConfig(
        version = "12.0.0",
        repository = "ghcr.io/cyclonedx/cdxgen:v{version}",
        build_jobs = [
            ToolJob(
                name = CYCLONEDX,
                cmd = ["-r", CONTAINER_REPO_DIR, "--fail-on-error", "-o", f"{CONTAINER_RESULT_DIR}/cdxgen_cyclonedx.json"],
                env = {"CDXGEN_IN_CONTAINER": "true"},
            )
        ]
    )
}

def pull_images():
    with PodmanClient(base_url=PODMAN_BASE_URL) as client:
        for tool_name, tool_cfg in TOOLS.items():
            if not client.images.exists(tool_cfg.image):
                print(tool_cfg.image)
                print(f"> Pulling Podman image for {tool_name}:{tool_cfg.version}... (this may take some time)")
                client.images.pull(tool_cfg.image)
            else:
                print(f"> Podman image for {tool_name}:{tool_cfg.version} already exists")

def git(args, cwd):
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    cmd = ["git"] + args
    subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

def get_sboms_from_tool(owner: str, repo: str, tool_name: str, repo_url: str, commit_hash: str, repository_state_id: int, creator_id: int, remove_failed_containers: bool):
    # uses repository_state_id and creator_id
    def add_sbom(sbom_type, sbom_version, sbom):
        con = get_db()
        cur = con.cursor()

        cur.execute("""
            INSERT INTO sboms (repository_state_id, type, version, origin_type)
            VALUES (?, ?, ?, 'generated')
        """, (repository_state_id, sbom_type, sbom_version))
        sbom_id = cur.lastrowid

        cur.execute("""
            INSERT INTO sbom_raw (sbom_id, raw)
            VALUES(?, ?)
        """, (sbom_id, json.dumps(sbom, indent=4)))

        cur.execute("""
            INSERT INTO sbom_creators (sbom_id, creator_id)
            VALUES (?, ?)
        """, (sbom_id, creator_id))

        con.commit()
        cur.close()
        con.close()

    project_name = f"{owner}/{repo}"
    job_name = f"{owner}-{repo}-{uuid.uuid4().hex}"
    LOGGING_PREFIX = f"[{job_name}] "

    with tempfile.TemporaryDirectory(dir=TMP_DIR) as result_dir, tempfile.TemporaryDirectory(dir=TMP_DIR) as repo_dir:
        result_path = Path(result_dir)
        repo_path = Path(repo_dir)

        os.chmod(result_dir, 0o777)
        os.chmod(repo_dir, 0o777)

        try:
            git(["init", "-q"], repo_path)
            git(["remote", "add", "origin", repo_url], repo_path)
            git(["fetch", "--depth", "1", "origin", commit_hash], repo_path)
            git(["checkout", "--detach", commit_hash], repo_path)
        except subprocess.CalledProcessError as e:
            logging.error(f"git failed on {repo_url} with: {e}")
            return None

        mounts = [
            {
                "type": "bind",
                "source": str(repo_path),
                "target": CONTAINER_REPO_DIR,
                "read_only": False,
            },
            {
                "type": "bind",
                "source": str(result_path),
                "target": CONTAINER_RESULT_DIR,
                "read_only": False,
            },
        ]

        tool_cfg = TOOLS[tool_name]

        with PodmanClient(base_url=PODMAN_BASE_URL) as client:
            for job in tool_cfg.build_jobs:
                CONTAINER_PREFIX = LOGGING_PREFIX + f"[Container {job.name}] "

                container = client.containers.create(
                    name = job_name,
                    image = tool_cfg.image,
                    command = job.cmd,
                    mounts = mounts,
                    environment = job.env or None,
                )

                container.start()
                logging.info(CONTAINER_PREFIX + "started")
                exit_code = container.wait(condition=["stopped", "exited"])

                if exit_code != 0:
                    logging.error(CONTAINER_PREFIX + f"exited with {exit_code}. Inspection: {container.inspect()}")
                    if remove_failed_containers:
                        container.remove(force=True)
                    return None

                logging.info(CONTAINER_PREFIX + f"exited normally")
                container.remove(force=True)


        for json_file in result_path.glob("*.json"):
            try:
                with json_file.open("r", encoding="utf-8") as f:
                    sbom = json.load(f)
            except Exception as e:
                logging.error(f"failed to load json {json_file.name}")
                continue

            if (spdx_ver := sbom.get("spdxVersion")) is not None:
                sbom["name"] = project_name

                add_sbom(SPDX, spdx_ver.split("-")[1], sbom)
                logging.info(f"[{job_name}][{tool_name}]: Added {SPDX} sbom")
            elif (format := sbom.get("bomFormat")) is not None and format == "CycloneDX":
                sbom["metadata"]["component"]["name"] = project_name

                add_sbom(CYCLONEDX, sbom["specVersion"], sbom)
                logging.info(f"[{job_name}][{tool_name}]: Added {CYCLONEDX} sbom")
            else:
                logging.error(LOGGING_PREFIX + f"found unknown result `{json_file.name}`")
                continue
        return

def generate_sboms(tool_name: str, num_workers: int, min_stars: int, replace_existing: bool, remove_failed_containers: bool):
    tool_cfg = TOOLS[tool_name]

    con = get_db()
    cur = con.cursor()

    tool_version = tool_cfg.version

    creator_id = add_creator_tool(cur, tool_name, tool_version)
    con.commit()

    # we need to get all the repositories that have at least min_stars many stars
    # with no sbom generated by the specified tool
    # there may be one sbom type missing
    cur.execute("""
        SELECT
            r.url AS url,
            rs.commit_hash AS hash,
            rs.id AS id,
            r.owner AS owner,
            r.name as repo,
            CASE WHEN s.type = 'SPDX' AND s.origin_type = 'generated' AND c.name = ? AND c.version = ? THEN 1 ELSE 0 END AS has_spdx,
            CASE WHEN s.type = 'CycloneDX' AND s.origin_type = 'generated' AND c.name = ? AND c.version = ? THEN 1 ELSE 0 END AS has_cyclonedx
        FROM repositories r
            JOIN repository_states rs ON rs.repository_id = r.id
            LEFT JOIN sboms s ON s.repository_state_id = rs.id
            LEFT JOIN sbom_creators sc ON sc.sbom_id = s.id
            LEFT JOIN creators c ON c.id = sc.creator_id
        WHERE
            r.stars >= ?
        GROUP BY
            r.url, rs.commit_hash
    """, (tool_name, tool_version, tool_name, tool_version, min_stars))
    rows = cur.fetchall()
    cur.close()
    con.close()

    # not all sbom generators produce all formats
    rows = [
        row for row in rows
        if (
            (SPDX in tool_cfg.produces and not bool(row["has_spdx"]))
            or
            (CYCLONEDX in tool_cfg.produces and not bool(row["has_cyclonedx"]))
        )
    ]

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = {}

        for row in rows:
            if not (replace_existing or not (bool(row["has_spdx"]) and bool(row["has_cyclonedx"]))):
                continue

            job_name = f"{row["owner"]}-{row["repo"]}-{uuid.uuid4().hex}"
            args = (row["owner"], row["repo"], tool_name, row["url"], row["hash"], row["id"], creator_id, remove_failed_containers)

            future = executor.submit(get_sboms_from_tool, *args)
            futures[future] = job_name

        logging.info(f"Submitted {len(futures)} jobs")
        print(f"Submitted {len(futures)} jobs")

        for future in tqdm(as_completed(futures), total=len(futures)):
            try:
                future.result()
            except Exception as e:
                task = futures[future]
                logging.error(f"{task} failed with: {e}")

def arguments(parser):
    parser.add_argument("--log-file", type=str, required=False, help="Log file.", default = "./gen.log")

    parser.add_argument("--podman-socket", type=str, required=False, help=f"Override podman socket location (default for your user: `{PODMAN_BASE_URL}`).")
    parser.add_argument("--remove-failed-containers", action="store_true", required=False, help="Removes containes that exited with nonzero exit-code. Failed containers are usually kept for inspection.")
    parser.add_argument("--tmp-dir", type=str, required=False, help=f"Temporary Directory used to transfer files between container and host (default: `{TMP_DIR}`)")

    # since TOOLS stores not only the name, we reduce it down to just the names for the CLI interface
    parser.add_argument("--sbom-generator", choices=list(TOOLS.keys()), required=True)
    parser.add_argument("--num-workers", type=int, required=False, default=16, help="Number of parallel workers.")

    parser.add_argument("--replace-existing", action="store_true", help="Replaces already existing sboms from the specified tool with a freshly generated one.")
    parser.add_argument("--min-stars", type=int, required=False, default=0, help="Minimum number of stars a repository needs in order for an sbom to be generated.")

def main(args):
    global PODMAN_BASE_URL, TMP_DIR

    logging.basicConfig(filename=args.log_file, level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    if not os.path.exists("sboms.db"):
        sys.exit("Did not find Database! Use the scraper to aquire some data first!")

    if (tmp := args.tmp_dir) is not None:
        TMP_DIR = tmp

    if (url := args.podman_socket) is not None:
        PODMAN_BASE_URL = url

    if args.sbom_generator not in TOOLS.keys():
        sys.exit("Unknown tool!")

    pull_images()
    generate_sboms(args.sbom_generator, args.num_workers, args.min_stars, args.replace_existing, args.remove_failed_containers)
