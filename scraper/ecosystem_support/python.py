import requests

from tqdm import tqdm
from bs4 import BeautifulSoup

from typing import List
from typing import Optional

from utilities.utils import normalize_github_url

import logging

SIMPLE_INDEX = "https://pypi.org/simple"

# identification as per: https://docs.pypi.org/api/
HEADERS = {
    "User-Agent": "XXX-Anonymous-XXX" # anonymous for submission
}

def _get_all_projects():
    response = requests.get(SIMPLE_INDEX, timeout=60)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")
    projects = [a.text.strip() for a in soup.find_all("a")]
    return projects

def _get_project_source_url(project):
    query_url = f"https://pypi.org/pypi/{project}/json"

    try:
        response = requests.get(query_url, timeout=60)
        response.raise_for_status()

        data = response.json()

        # usually the repository link would be stored in info->project_urls->Source
        # however, some people put the repository link as the homepage link which occurs multiple times
        # --> we look in all the relevant locations for a github link, collect them all and then redundancy reduce
        potential_links = set()

        project_info = data["info"]

        if (u := normalize_github_url(project_info.get("home_page", ""))) is not None:
            potential_links.add(u)

        if (project_urls := project_info.get("project_urls", None)) is not None:
            # there may be 3 cases:
            # 1) project_urls exists and has data -> no problem
            # 2) project_urls is already None
            # 3) project_urls does not exist (unsure if this is possible)
            for url in project_urls.values():
                if (u := normalize_github_url(url)) is not None:
                    potential_links.add(u)

        # should not be necessary
        potential_links.discard(None)

        if len(potential_links) < 1:
            logging.error(f"{query_url} has no links")
            return None

        if len(potential_links) > 1:
            # let's remove the offenders that have too many links. Because they added some (sorry to say this) borderline arbitrary bullshit to their package info
            # or just leaving the default "tempalte" links to the sample python project for packaging (https://github.com/pypa/sampleproject)
            # we can filter through the logs afterwards to assess the real "damage"
            logging.critical(f"{query_url} has too many links ({len(potential_links)})! {[potential_links]}")
            return None

        return potential_links.pop()
    except Exception as e:
        logging.error(f"Failed to retrieve {query_url} due to: {e}")
        return None

def project_repo_list(cache_dir: Optional[str]=None) -> List[str]:
    projects = _get_all_projects()

    repos = []
    for project in tqdm(projects, desc="Fetching Metadata for PyPi Projects"):
        # requests are performed in serial as requested by the documentation: https://docs.pypi.org/api/
        if (url := _get_project_source_url(project)) is not None:
            repos.append(url)

    return repos
