import os
import sys
import time

import logging

import requests
from http.client import RemoteDisconnected

from concurrent.futures import ThreadPoolExecutor, as_completed

from utilities.utils import *

if __name__ == "__main__":
    print("this is not a script")
    sys.exit(0)

GH_TOKEN = os.getenv("GH_TOKEN")
if not GH_TOKEN:
    print("Provide GH_TOKEN env variable. Required permissions: [read]")
    sys.exit(0)

GH_HEADERS = {
    "Authorization": f"Bearer {GH_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
}

ADDITIONAL_DELAY = 2

def _rate_limit_remaining_used_reset(response):
    limit = int(response.headers.get("x-ratelimit-limit", 0))
    remaining = int(response.headers.get("x-ratelimit-remaining", 0))
    used = int(response.headers.get("x-ratelimit-used", 0))
    reset = int(response.headers.get("x-ratelimit-reset", 0))

    return limit, remaining, used, reset

def _retrieve_data(api_url, query_fun, max_retries=5):
    # resources for handling api endpoint appropriately:
    # 1) best practices: https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api?apiVersion=2022-11-28
    # 2) rate limits: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28
    # 3) SBOM endpoint: https://docs.github.com/en/rest/dependency-graph/sboms?apiVersion=2022-11-28

    exp_backoff_seconds = exponential_backoff(base=60)

    # handles its own retries and exponential backoff for any kind of network failures
    session = make_session()

    for _ in range(max_retries):
        try:
            response = session.get(api_url, headers=GH_HEADERS)
        except RemoteDisconnected:
            logging.error(f"Connection dropped for {api_url}")
            break
        except requests.RequestException as e:
            logging.error(f"Request error for {api_url}")
            break
        except Exception as e:
            logging.error(f"Unexpected error occured for {api_url}: {e}")
            break

        _, rate_remaining, _, rate_reset = _rate_limit_remaining_used_reset(response)

        match response.status_code:
            case 200:
                return query_fun(response)
            case 403 | 429:
                delay = ADDITIONAL_DELAY

                if rate_remaining == 0:
                    # primary rate limit
                    delay += max(rate_reset - time.time(), 0)
                    logging.info(f"Hitting primary rate limit. Sleeping {delay}s")
                else:
                    # secondary rate limit
                    if "retry-after" in response.headers.keys():
                        delay += int(response.headers["retry-after"])
                    else:
                        delay += next(exp_backoff_seconds)
                    logging.info(f"Hitting secondary rate limit. Sleeping {delay}s")

                time.sleep(delay)
                # we have waited an appropriate time -> retry
                continue
            case _:
                # maybe 404, or internal server error (5XX), or something else entirely
                # --> log the failure and skip for now
                logging.error(f"HTTP status {response.status_code} for {api_url}")
                break
    else:
        logging.error(f"Unable to retrieve data after {max_retries} attempts for {api_url}")

    return None

def parse_owner_repo(repo_url):
    split = repo_url.split("github.com/")[1].split("/")

    if len(split) < 2:
        return None

    [owner, repo] = split[:2]

    return owner, repo

def _api_base_link(owner, repo, endpoint):
    if endpoint is not None:
        return f"https://api.github.com/repos/{owner}/{repo}/{endpoint}"
    else:
        return f"https://api.github.com/repos/{owner}/{repo}"

def get_custom(api_link, query_fun):
    return _retrieve_data(api_link, query_fun)

def get_last_commit_hash(owner, repo):
    # this may also be a paginated endpoint, however we are only interested in the most recent commit -> no need for pagination here
    return _retrieve_data(_api_base_link(owner, repo, "commits"), lambda r : r.json()[0]["sha"])

def get_sbom(owner, repo):
    return _retrieve_data(_api_base_link(owner, repo, "dependency-graph/sbom"), lambda r : r.json()["sbom"])

def get_languages(owner, repo):
    return _retrieve_data(_api_base_link(owner, repo, "languages"), lambda r : r.json())

def get_repo_data(owner, repo):
    return _retrieve_data(_api_base_link(owner, repo, None), lambda r : r.json())

# wrapper that performs all the required actions for the database to add a new repository + SBOM
# performs requests concurrently for a slight speedup (full asyncio might be better here, but this is certainly faster to implement for now as I can keep the remaining architecture in place)
def fetch_repo_data(owner, repo):
    query_results = {}

    # we fetch sbom and commit in squence as they should always be consecutive. Also the sbom retrieval is the most likely call to fail due to privacy settings
    if (sbom := get_sbom(owner, repo)) is None:
        return None

    if (commit := get_last_commit_hash(owner, repo)) is None:
        return None

    query_results["sbom"] = sbom
    query_results["commit_hash"] = commit

    queries = {
        "repo_data": lambda: get_repo_data(owner, repo),
        "languages": lambda: get_languages(owner, repo),
    }

    with ThreadPoolExecutor(max_workers=len(queries)) as executor:
        future_to_key = {executor.submit(fn): key for key, fn in queries.items()}

        for future in as_completed(future_to_key):
            key = future_to_key[future]
            try:
                if (res := future.result()) is None:
                    return None

                query_results[key] = res
            except Exception as e:
                logging.error(f"Error retrieving {key} from ThreadPool for {owner}/{repo}: {e}")
                return None

    return query_results
