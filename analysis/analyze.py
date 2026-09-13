import os
import matplotlib.pyplot as plt
import csv
import logging
import json
from itertools import combinations
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm.auto import tqdm
from tabulate import tabulate
from typing import List
import numpy as np
import math

from utilities.utils import *

DPI = 800
OUT_DIR = os.getcwd()

EXPECTED_SBOMS = {'trivy_cdx', 'trivy_spdx', 'gh_spdx', 'syft_cdx', 'syft_spdx'}

TOOL_DISPLAY_NAMES = {
    "syft_spdx": "Syft (SPDX)",
    "syft_cdx": "Syft (CDX)",
    "trivy_spdx": "Trivy (SPDX)",
    "trivy_cdx": "Trivy (CDX)",
    "gh_spdx": "GH (SPDX)",
}

PLOT_STYLE = {
    "bar_color": "#4C78A8",
    "edge_color": "#1F2A44",
    "grid_color": "#D0D0D0",
    "font_size": 14,
    "title_size": 16,
}

plt.rcParams.update({
    "font.family": "sans-serif",
    "axes.titlesize": 12,
    "axes.labelsize": 10,
})

def sbomqs(creator_keys: List[str]):
    con = get_db()
    cur = con.cursor()

    for creator in creator_keys:
        print() # some spacing between results

        cur.execute("SELECT * FROM creators WHERE name = ?", (creator,))
        if len(cur.fetchall()) == 0:
            print(f"=!!= No creator '{creator}' found =!!=")
            continue

        cur.execute("""
        SELECT
            s.type AS sbom_type,
            spd.name AS profile_name,
            AVG(sp.score) AS avg_score
        FROM sbomqs_profile sp
        JOIN sbomqs sq ON sp.sbomqs_id = sq.id
        JOIN sboms s ON sq.sbom_id = s.id
        JOIN sbomqs_profile_def spd ON sp.profile_def_id = spd.id
        WHERE s.id IN (
            SELECT DISTINCT s.id
            FROM sboms s
            JOIN sbom_creators sc ON s.id = sc.sbom_id
            JOIN creators c ON sc.creator_id = c.id
            WHERE c.name = ?
        )
        GROUP BY s.type, spd.id, spd.name
        ORDER BY s.type, spd.name
        """, (creator,))
        rows = cur.fetchall()

        print(f"==== SBOMQS Results for SBOMs created by: {creator} ====")
        print(tabulate(
            rows,
            headers=["Type", "Profile", "Avg Score"],
            floatfmt=".2f"
        ))


def str_or_int(value):
    try:
        return int(value)
    except ValueError:
        return value
    
def jaccard_similarity(a: set, b: set):
    union = a.union(b)

    if  union:
        return len(a.intersection(b)) / len(union)
    
    return None

def normalize_format(t: str):
    if not t:
        logging.warning("Missing SBOM type")
        return "missing"
    
    if t.lower() == "cyclonedx":
        return "cdx"
    elif t.lower() == "spdx":
        return "spdx"
    
    logging.warning(f"Unknown SBOM type: {t}")
    return "unknown"

def normalize_tool_label(row: dict):
    sbom_format = normalize_format(row["type"])

    tool = row["tool_name"]
    origin = (row["origin_type"] or "").lower()

    # CASE 1: GitHub SBOM
    # protobom OR missing tool + downloaded origin → GitHub
    if tool == "protobom" or (tool is None and "download" in origin):
        return f"gh_{sbom_format}"

    # CASE 2: Normal
    if tool:
        tool = tool.lower()
        return f"{tool}_{sbom_format}"

    # CASE 3: unknown
    logging.warning(f"Unknown tool: {tool}, origin: {origin}, sbom_id: {row['sbom_id']}")
    return None

def get_components(sbom: dict, sbom_format: str, filter_repo_comps: bool = False, names_only: bool = False):
    if not sbom:
        return set()

    all_components = []
    if sbom_format == "cdx":
        comps = sbom.get("components")
        if not comps:
            return set()

        for comp in comps:
            name = comp.get("name").lower() # Standardize names
            # Handle no version or version: "" or None
            version = comp.get("version") or "NA"
            all_components.append((name, version))

    elif sbom_format == "spdx":
        packages = sbom.get("packages")
        if not packages:
            return set()

        for package in packages:
            name = package["name"].lower()
            version = package.get("versionInfo") or "NA"
            all_components.append((name, version))

    components = set()

    for name, version in all_components:
        if not (filter_repo_comps and name.startswith("/repo")): # in SPDX SBOMs, /repo represents the repository itself (the folder which Trivy and Syft were executed in), and /repo/.github/workflows/... in Syft CDX SBOMs
            components.add(name if names_only else f"{name}@{version}")

    return components

def count_duplicate_component_stats(sbom: dict, sbom_format: str):
    if not sbom:
        return 0, 0

    versions_by_name = {}

    if sbom_format == "cdx":
        for comp in sbom.get("components") or []:
            name = (comp.get("name") or "").lower()
            if not name:
                continue
            versions_by_name.setdefault(name, set()).add(comp.get("version") or "NA")
    elif sbom_format == "spdx":
        for package in sbom.get("packages") or []:
            name = (package.get("name") or "").lower()
            if not name:
                continue
            versions_by_name.setdefault(name, set()).add(package.get("versionInfo") or "NA")

    duplicate_name_count = sum(1 for versions in versions_by_name.values() if len(versions) > 1) # count how many names have more than 1 version
    duplicate_total_count = sum(max(0, len(versions) - 1) for versions in versions_by_name.values()) # count how many duplicates there are in total

    return duplicate_name_count, duplicate_total_count

def extract_components_from_raw(raw: str, sbom_format: str, filter_repo_comps: bool = False, names_only: bool = False):
    try:
        sbom = json.loads(raw)
        return get_components(sbom, sbom_format, filter_repo_comps=filter_repo_comps, names_only=names_only)
    except json.JSONDecodeError as e:
        logging.exception(f"Failed to decode JSON: {e}")
        return set()

def process_sbom(sbom_rows: list, buffer: dict, filter_repo_comps: bool = False, names_only: bool = False):
    row = sbom_rows[0] # returned rows for the same sbom (sbom_id) (e.g., github protobom + download origin) -> just take first

    tool_label = normalize_tool_label(row)

    if tool_label is None:
        return # unknown tool, skip

    if tool_label in buffer:
        return # already processed tool sbom for this repo state, skip (gh)

    fmt = normalize_format(row["type"])

    components = extract_components_from_raw(row["raw"], fmt, filter_repo_comps=filter_repo_comps, names_only=names_only)

    buffer[tool_label] = components # store components for this tool in the buffer for the current repo state

def process_buffer(repo_id: str, state_id: int, buffer: dict):
    rows = []

    tools = sorted(buffer.keys()) # sorted to always have the same order in combinations

    all_tools_present = int(set(tools) == EXPECTED_SBOMS)
    if not all_tools_present:
        logging.warning(f"Not all expected SBOMs present for {repo_id} (state {state_id}). Only found: {tools}")

    for tool_a, tool_b in combinations(tools, 2):
        comps_a = buffer[tool_a]
        comps_b = buffer[tool_b]

        jaccard = jaccard_similarity(comps_a, comps_b)
        union_size = len(comps_a | comps_b)

        rows.append([
            repo_id,
            state_id,
            tool_a,
            tool_b,
            len(comps_a),
            len(comps_b),
            union_size,
            round(jaccard, 4) if jaccard is not None else None,
            all_tools_present
        ])

    return rows

def compute_jaccard_dataset(output_file: str, min_stars: int, max_workers: int, filter_repo_comps: bool = False, names_only: bool = False):
    print("Computing Jaccard csv...")
    print(f"The expected SBOMs for each repository are: {', '.join(EXPECTED_SBOMS)}")

    con = get_db()
    cur = con.cursor()

    query = """
    SELECT
        r.id as repo_id,
        r.stars,
        s.repository_state_id,
        s.id as sbom_id,
        s.type,
        s.origin_type,
        sr.raw,
        c.name as tool_name
    FROM sboms s
    JOIN sbom_raw sr ON sr.sbom_id = s.id
    JOIN repository_states rs ON s.repository_state_id = rs.id
    JOIN repositories r ON rs.repository_id = r.id
    LEFT JOIN sbom_creators sc ON sc.sbom_id = s.id
    LEFT JOIN creators c ON c.id = sc.creator_id AND c.type = 'tool'
    WHERE r.stars >= ?
    ORDER BY s.repository_state_id, s.id;
    """
    
    # Get total row count for progress bar
    count_query = """
    SELECT COUNT(*) as count
    FROM sboms s
    JOIN sbom_raw sr ON sr.sbom_id = s.id
    JOIN repository_states rs ON s.repository_state_id = rs.id
    JOIN repositories r ON rs.repository_id = r.id
    LEFT JOIN sbom_creators sc ON sc.sbom_id = s.id
    LEFT JOIN creators c ON c.id = sc.creator_id AND c.type = 'tool'
    WHERE r.stars >= ?
    """

    print("Querying DB...")

    cur.execute(count_query, (min_stars,))
    total_rows = cur.fetchone()["count"]
    
    cur.execute(query, (min_stars,))

    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)

        # write header
        writer.writerow([
            "repo_id",
            "repo_state_id",
            "tool_a",
            "tool_b",
            "count_a",
            "count_b",
            "union_size",
            "jaccard",
            "all_tools_present"
        ])

        # process sboms for each repo
        current_state = None
        current_repo = None

        # Keep track of SBOM ids too
        # because GitHub SBOMs can have two entries per tool (protobome / None + download origin)
        current_sbom_id = None
        current_sbom_rows = []

        # buffer for tools and their components for the current repo
        buffer = {}

        futures = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            with tqdm(total=total_rows, desc="Processing rows", unit=" rows") as process_pbar:
                for row in cur:
                    sbom_id = row["sbom_id"]
                    state_id = row["repository_state_id"]
                    repo_id = row["repo_id"]

                    if current_sbom_id is not None and sbom_id != current_sbom_id:
                        # aviod processing SBOMs twice (github)
                        # only process (add to buffer) when sbom_id changes
                        process_sbom(current_sbom_rows, buffer, filter_repo_comps=filter_repo_comps, names_only=names_only)
                        current_sbom_rows = []

                    if current_state is not None and state_id != current_state:
                        # state changed, process the previous state and reset buffer
                        future = executor.submit(process_buffer, current_repo, current_state, dict(buffer)) # copy buffer for thread safety
                        futures.append(future)

                        buffer = {}

                    current_state = state_id
                    current_sbom_id = sbom_id
                    current_repo = repo_id

                    # all rows with same sbom id
                    current_sbom_rows.append(row)
                    process_pbar.update(1)

                # last sbom and repo state
                if current_sbom_rows:
                    process_sbom(current_sbom_rows, buffer, filter_repo_comps=filter_repo_comps)

                if buffer:
                    future = executor.submit(process_buffer, current_repo, current_state, dict(buffer)) # copy buffer for thread safety
                    futures.append(future)
            
            # collect results
            with tqdm(total=len(futures), desc="Writing results", unit="repo") as results_pbar:
                for future in as_completed(futures):
                    try:
                        rows = future.result()
                        writer.writerows(rows)
                    except Exception as e:
                        logging.exception(f"Worker failed: {e}")
                    finally:
                        results_pbar.update(1)

    cur.close()
    con.close()

def plot_mean_median_comp_bar_chart(mean_jaccards: dict = None, median_jaccards: dict = None):
    if not mean_jaccards and not median_jaccards:
        print("No mean or median values provided for plotting.")
        return

    both = bool(mean_jaccards) and bool(median_jaccards)
    data = mean_jaccards if mean_jaccards else median_jaccards
    label = "Mean" if mean_jaccards else "Median"

    if both:
        all_pairs = sorted(
            set(mean_jaccards.keys()) | set(median_jaccards.keys()),
            key=lambda p: mean_jaccards.get(p, (0,))[0],
        )
        pair_labels = [f"{TOOL_DISPLAY_NAMES.get(tool_a, tool_a)} vs {TOOL_DISPLAY_NAMES.get(tool_b, tool_b)}" for (tool_a, tool_b) in all_pairs] # use display names
        mean_vals = [mean_jaccards.get(p, (float("nan"), 0)) for p in all_pairs]
        median_vals = [median_jaccards.get(p, (float("nan"), 0)) for p in all_pairs]

        n = len(all_pairs)
        bar_height = 0.35
        y = np.arange(n)

        fig_height = max(4.8, n * 0.9)
        fig, ax = plt.subplots(figsize=(8.5, fig_height))

        mean_bars = ax.barh(
            y + bar_height / 2,
            [v for v, _ in mean_vals],
            height=bar_height,
            color="#4C78A8",
            edgecolor=PLOT_STYLE["edge_color"],
            linewidth=0.6,
            label="Mean",
        )
        median_bars = ax.barh(
            y - bar_height / 2,
            [v for v, _ in median_vals],
            height=bar_height,
            color="#F5C518",
            edgecolor=PLOT_STYLE["edge_color"],
            linewidth=0.6,
            label="Median",
        )

        ax.set_yticks(y)
        ax.set_yticklabels(pair_labels)
        ax.set_title("Mean and Median Similarity by Tool Pair", fontsize=PLOT_STYLE["title_size"], weight="bold", pad=10)
        ax.legend(fontsize=11)

        for bar, (value, count) in zip(mean_bars, mean_vals):
            if not math.isnan(value):
                ax.text(value + 0.01, bar.get_y() + bar.get_height() / 2,
                        f"{value:.3f} (n={count})", va="center", ha="left",
                        fontsize=11, color=PLOT_STYLE["edge_color"])
        for bar, (value, count) in zip(median_bars, median_vals):
            if not math.isnan(value):
                ax.text(value + 0.01, bar.get_y() + bar.get_height() / 2,
                        f"{value:.3f} (n={count})", va="center", ha="left",
                        fontsize=11, color=PLOT_STYLE["edge_color"])

        filename = "mean_median_jaccard.png"
    else:
        pair_data = sorted(data.items(), key=lambda x: x[1][0])
        pair_labels = [f"{TOOL_DISPLAY_NAMES.get(tool_a, tool_a)} vs {TOOL_DISPLAY_NAMES.get(tool_b, tool_b)}" for (tool_a, tool_b), _ in pair_data]
        values_with_counts = [vc for _, vc in pair_data]

        fig_height = max(4.8, len(pair_labels) * 0.45)
        fig, ax = plt.subplots(figsize=(8.5, fig_height))

        bars = ax.barh(
            pair_labels,
            [v for v, _ in values_with_counts],
            color="#4C78A8",
            edgecolor=PLOT_STYLE["edge_color"],
            linewidth=0.6,
        )

        ax.set_title(f"{label} Similarity by Tool Pair", fontsize=PLOT_STYLE["title_size"], weight="bold", pad=10)

        for bar, (value, count) in zip(bars, values_with_counts):
            ax.text(value + 0.01, bar.get_y() + bar.get_height() / 2,
                    f"{value:.3f} (n={count})", va="center", ha="left",
                    fontsize=11, color=PLOT_STYLE["edge_color"])

        filename = "mean_jaccard.png" if mean_jaccards else "median_jaccard.png"

    ax.set_xlabel("Mean and Median Jaccard Similarity" if both else f"{label} Jaccard Similarity", fontsize=PLOT_STYLE["font_size"])
    ax.set_ylabel("Tool Pair", fontsize=PLOT_STYLE["font_size"])
    ax.set_xlim(0, 1)
    ax.set_xticks(np.linspace(0, 1, 11))
    ax.tick_params(axis="both", labelsize=11)
    ax.grid(axis="x", color=PLOT_STYLE["grid_color"], linewidth=0.6, alpha=0.8)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.invert_yaxis()

    fig.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, filename), dpi=DPI)
    plt.close(fig)

def plot_jaccard_histograms(jaccard_values: dict, pair_order: list = None):
    if pair_order:
        pairs = [(pair, jaccard_values[pair]) for pair in pair_order if pair in jaccard_values]
    else:
        pairs = list(jaccard_values.items())
    n = len(pairs)

    rows = 3
    cols = math.ceil(n / rows)

    fig, axes = plt.subplots(rows, cols, figsize=(10, rows * 3))

    axes = axes.flatten()

    for ax, ((tool_a, tool_b), values) in zip(axes, pairs):
        if not values:
            continue

        bins = np.linspace(0, 1, 11)  # 10 bins → 11 edges
        ax.hist(
            values,
            bins=bins,
            color=PLOT_STYLE["bar_color"],
            edgecolor=PLOT_STYLE["edge_color"],
            linewidth=0.6,
        )

        ax.set_title(f"{TOOL_DISPLAY_NAMES.get(tool_a, tool_a)} vs {TOOL_DISPLAY_NAMES.get(tool_b, tool_b)}\n(n={len(values)})", fontsize=10)
        ax.set_xlim(0, 1)
        ax.set_xticks(np.linspace(0, 1, 6))
        ax.tick_params(axis="both", labelsize=9)
        ax.grid(axis="y", color=PLOT_STYLE["grid_color"], linewidth=0.6, alpha=0.8)
        ax.set_axisbelow(True)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

    # Remove unused subplots
    for i in range(len(pairs), len(axes)):
        fig.delaxes(axes[i])

    fig.suptitle(
        "Distribution of Jaccard Similarities by Tool Pair",
        fontsize=PLOT_STYLE["title_size"],
        weight="bold",
    )
    fig.supxlabel("Jaccard Similarity", fontsize=PLOT_STYLE["font_size"])
    fig.supylabel("Frequency", fontsize=PLOT_STYLE["font_size"])

    fig.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "jaccard_histograms.png"), dpi=DPI)

    plt.close(fig)

def write_repo_overview_csv(output_file: str, repo_rows: list, lang_rows: list, total_repos: int):
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "name", "stars", "size", "repo_count", "total_repos"])
        for r in repo_rows:
            writer.writerow(["repo", r["name"], r["stars"], r["size"], "", ""])
        for r in lang_rows:
            writer.writerow(["language", r["name"], "", "", r["repo_count"], total_repos])
    print(f"Saved: {output_file}")


def read_repo_overview_csv(csv_file: str):
    repo_rows = []
    lang_rows = []
    total_repos = 0

    with open(csv_file, "r", newline="") as f:
        for row in csv.DictReader(f):
            if row["type"] == "repo":
                repo_rows.append({"name": row["name"], "stars": int(row["stars"]), "size": int(row["size"])})
            elif row["type"] == "language":
                lang_rows.append({"name": row["name"], "repo_count": int(row["repo_count"])})
                total_repos = int(row["total_repos"])

    sorted_by_stars = sorted(repo_rows, key=lambda r: r["stars"], reverse=True)
    sorted_by_size  = sorted(repo_rows, key=lambda r: r["size"],  reverse=True)
    stars          = [r["stars"] for r in sorted_by_stars]
    names_by_stars = [r["name"]  for r in sorted_by_stars]
    sizes          = [r["size"]  for r in sorted_by_size]
    names_by_size  = [r["name"]  for r in sorted_by_size]

    return stars, sizes, names_by_stars, names_by_size, lang_rows, total_repos


def _print_repo_overview(stars, sizes, names_by_stars, names_by_size, lang_rows, total_repos):
    avg_stars    = np.mean(stars)
    median_stars = np.median(stars)
    max_stars    = np.max(stars)
    avg_size     = np.mean(sizes)
    median_size  = np.median(sizes)
    max_size     = np.max(sizes)

    print(f"=== Repository Overview ===")
    print(f"Total repositories: {total_repos}")
    print(f"\nStar counts (n={len(stars)}):")
    print(f"  Average : {avg_stars:,.1f}")
    print(f"  Median  : {median_stars:,.1f}")
    print(f"  Maximum : {max_stars:,.1f}")
    print(f"  Most starred repository o_O : {names_by_stars[0]} ({max_stars} stars)")
    print(f"\nRepository sizes in KB (n={len(sizes)}):")
    print(f"  Average : {avg_size:,.1f}")
    print(f"  Median  : {median_size:,.1f}")
    print(f"  Maximum : {max_size:,.1f}")
    print(f"  Biggest repository by size o_O : {names_by_size[0]} ({max_size / 1000000} GB)")
    print(f"\nTop 10 programming languages (% of repos with that language):")
    for row in lang_rows:
        pct = row["repo_count"] / total_repos * 100
        print(f"  {row['name']:<20} {pct:5.1f}%  ({row['repo_count']} repos)")


def repo_overview(generate_plots: bool = True, output_file: str = None, csv_file: str = None, show_dominant_languages: bool = False):
    if csv_file:
        print(f"Reading repo overview from {csv_file}...")
        stars, sizes, names_by_stars, names_by_size, lang_rows, total_repos = read_repo_overview_csv(csv_file)
        _print_repo_overview(stars, sizes, names_by_stars, names_by_size, lang_rows, total_repos)
        if show_dominant_languages:
            print()
            top_language_avg_percentage()
        if generate_plots:
            print("\nGenerating repository overview plots...")
            plot_repo_overview(stars, sizes, lang_rows, total_repos)
        else:
            print("\nSkipping plot generation (--no-plots).")
        return

    con = get_db()
    cur = con.cursor()

    cur.execute("SELECT COUNT(*) as count FROM repositories")
    total_repos = cur.fetchone()["count"]

    cur.execute("SELECT name, stars, size FROM repositories WHERE stars IS NOT NULL AND size IS NOT NULL")
    repo_rows = cur.fetchall()

    cur.execute("""
        SELECT l.name, COUNT(DISTINCT rl.repository_id) as repo_count
        FROM repository_languages rl
        JOIN languages l ON l.id = rl.language_id
        GROUP BY l.name
        ORDER BY repo_count DESC
        LIMIT 10
    """)
    lang_rows = cur.fetchall()

    cur.close()
    con.close()

    sorted_by_stars = sorted(repo_rows, key=lambda r: r["stars"], reverse=True)
    sorted_by_size  = sorted(repo_rows, key=lambda r: r["size"],  reverse=True)
    stars          = [r["stars"] for r in sorted_by_stars]
    names_by_stars = [r["name"]  for r in sorted_by_stars]
    sizes          = [r["size"]  for r in sorted_by_size]
    names_by_size  = [r["name"]  for r in sorted_by_size]

    _print_repo_overview(stars, sizes, names_by_stars, names_by_size, lang_rows, total_repos)

    if show_dominant_languages:
        print()
        top_language_avg_percentage()

    if output_file:
        write_repo_overview_csv(output_file, repo_rows, lang_rows, total_repos)

    if generate_plots:
        print("\nGenerating repository overview plots...")
        plot_repo_overview(stars, sizes, lang_rows, total_repos)
    else:
        print("\nSkipping plot generation (--no-plots).")


def plot_repo_overview(stars: list, sizes: list, lang_rows: list, total_repos: int):
    # Box plot for stars
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.boxplot(stars, vert=False, patch_artist=True,
               boxprops=dict(facecolor=PLOT_STYLE["bar_color"], color=PLOT_STYLE["edge_color"]),
               medianprops=dict(color="white", linewidth=2),
               whiskerprops=dict(color=PLOT_STYLE["edge_color"]),
               capprops=dict(color=PLOT_STYLE["edge_color"]),
               flierprops=dict(marker="o", markerfacecolor=PLOT_STYLE["bar_color"],
                               markeredgecolor=PLOT_STYLE["edge_color"], markersize=3, alpha=0.4))
    ax.set_xlabel("Stars", fontsize=PLOT_STYLE["font_size"])
    ax.set_title("Distribution of Repository Star Counts", fontsize=PLOT_STYLE["title_size"], weight="bold")
    ax.set_yticks([])
    ax.grid(axis="x", color=PLOT_STYLE["grid_color"], linewidth=0.6, alpha=0.8)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "repo_stars_boxplot.png"), dpi=DPI)
    plt.close(fig)

    # Box plot for repo sizes
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.boxplot(sizes, vert=False, patch_artist=True,
               boxprops=dict(facecolor=PLOT_STYLE["bar_color"], color=PLOT_STYLE["edge_color"]),
               medianprops=dict(color="white", linewidth=2),
               whiskerprops=dict(color=PLOT_STYLE["edge_color"]),
               capprops=dict(color=PLOT_STYLE["edge_color"]),
               flierprops=dict(marker="o", markerfacecolor=PLOT_STYLE["bar_color"],
                               markeredgecolor=PLOT_STYLE["edge_color"], markersize=3, alpha=0.4))
    ax.set_xlabel("Size (KB)", fontsize=PLOT_STYLE["font_size"])
    ax.set_title("Distribution of Repository Sizes", fontsize=PLOT_STYLE["title_size"], weight="bold")
    ax.set_yticks([])
    ax.grid(axis="x", color=PLOT_STYLE["grid_color"], linewidth=0.6, alpha=0.8)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "repo_sizes_boxplot.png"), dpi=DPI)
    plt.close(fig)

    # Bar chart for top 10 languages
    lang_names = [r["name"] for r in lang_rows]
    lang_pcts = [r["repo_count"] / total_repos * 100 for r in lang_rows]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.barh(lang_names[::-1], lang_pcts[::-1],
                   color=PLOT_STYLE["bar_color"], edgecolor=PLOT_STYLE["edge_color"], linewidth=0.6)
    for bar, pct in zip(bars, lang_pcts[::-1]):
        ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                f"{pct:.1f}%", va="center", ha="left", fontsize=9, color=PLOT_STYLE["edge_color"])
    ax.set_xlabel("% of Repositories", fontsize=PLOT_STYLE["font_size"])
    ax.set_title("Top 10 Programming Languages", fontsize=PLOT_STYLE["title_size"], weight="bold")
    ax.grid(axis="x", color=PLOT_STYLE["grid_color"], linewidth=0.6, alpha=0.8)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "repo_languages.png"), dpi=DPI)
    plt.close(fig)

    print(f"Saved: repo_stars_boxplot.png, repo_sizes_boxplot.png, repo_languages.png")


def top_language_avg_percentage():
    con = get_db()
    cur = con.cursor()

    # Monster Query
    cur.execute("""
        WITH top_language_per_repo AS (
            SELECT
                repository_id,
                language_id,
                percentage,
                RANK() OVER (PARTITION BY repository_id ORDER BY percentage DESC) AS rnk
            FROM repository_languages
        ),
        top_repos AS (
            SELECT repository_id, language_id, percentage
            FROM top_language_per_repo
            WHERE rnk = 1
        ),
        top_ten_languages AS (
            SELECT language_id, COUNT(*) AS repo_count
            FROM top_repos
            GROUP BY language_id
            ORDER BY repo_count DESC
            LIMIT 10
        )
        SELECT
            l.name AS language,
            ttl.repo_count,
            ROUND(AVG(tr.percentage), 2) AS avg_percentage_when_top
        FROM top_ten_languages ttl
        JOIN top_repos tr ON tr.language_id = ttl.language_id
        JOIN languages l ON l.id = ttl.language_id
        GROUP BY ttl.language_id, l.name, ttl.repo_count
        ORDER BY ttl.repo_count DESC
    """)
    # Note on ties: RANK() is used, so if two languages share the exact same percentage
    # in a repo, both get rnk = 1 and both are counted as the top language for that
    # repo. Swap RANK() for ROW_NUMBER() for a strict single winner
    rows = cur.fetchall()

    cur.close()
    con.close()

    print("=== Top 10 Languages: Avg. Percentage When Dominant ===")
    print(f"{'Language':<20} {'Repos (top)':>12} {'Avg. % when top':>16}")
    print("-" * 50)
    for row in rows:
        print(f"{row['language']:<20} {row['repo_count']:>12,} {row['avg_percentage_when_top']:>15.2f}%")


def plot_sbom_overview(agg: dict, side: str = None):
    """Plot stacked bar charts for SBOM type distributions.

    side: None → both panels; 'spdx' → SPDX only; 'cdx' → CycloneDX only.
    Single-side plots use a wide, vertically compact layout for academic papers.
    """
    SPDX_KEYS = ("syft_spdx", "trivy_spdx", "gh_spdx")
    CDX_KEYS  = ("syft_cdx",  "trivy_cdx")

    spdx_data = {k: agg["by_category"][k]["rel_types"]      for k in SPDX_KEYS}
    cdx_data  = {k: agg["by_category"][k]["component_types"] for k in CDX_KEYS}

    show_spdx = side != "cdx"
    show_cdx  = side != "spdx"

    if show_spdx and show_cdx:
        max_bars = max(len(spdx_data), len(cdx_data))
    elif show_spdx:
        max_bars = len(spdx_data)
    else:
        max_bars = len(cdx_data)

    def _stacked_barh(ax, tool_data, title):
        # smallest total first → appears at the top
        tools = sorted(tool_data, key=lambda k: sum(tool_data[k].values()))

        # type order: descending global frequency
        all_types = sorted(
            {t for d in tool_data.values() for t in d},
            key=lambda t: -sum(d.get(t, 0) for d in tool_data.values()),
        )

        palette = plt.cm.tab10.colors
        type_color = {t: palette[i % len(palette)] for i, t in enumerate(all_types)}

        n = len(tools)
        # scale bar height so bars fill the same vertical space regardless of bar count
        bar_height = 0.6 * (max_bars / n)
        offset = max_bars - n          # push bars to the top when fewer than max_bars
        y = list(range(offset, offset + n))
        lefts = [0] * n

        for type_name in all_types:
            vals = [tool_data[tool].get(type_name, 0) for tool in tools]
            ax.barh(y, vals, left=lefts, height=bar_height,
                    label=type_name, color=type_color[type_name],
                    edgecolor=PLOT_STYLE["edge_color"], linewidth=0.4)
            lefts = [l + v for l, v in zip(lefts, vals)]

        # total label at the end of each bar
        for yi, total in zip(y, lefts):
            if total:
                ax.text(total * 1.005, yi, f"{total:,}",
                        va="center", ha="left", fontsize=PLOT_STYLE["font_size"],
                        color=PLOT_STYLE["edge_color"])

        ax.set_yticks(y)
        ax.set_yticklabels(tools, fontsize=PLOT_STYLE["font_size"])
        # normalise y-axis range so both subplots use the same vertical space
        ax.set_ylim(-0.5, max_bars - 0.5)
        ax.set_title(title, fontsize=PLOT_STYLE["title_size"], weight="bold", pad=8)
        ax.set_xlabel("Count", fontsize=PLOT_STYLE["font_size"])
        ax.grid(axis="x", color=PLOT_STYLE["grid_color"], linewidth=0.6, alpha=0.8)
        ax.set_axisbelow(True)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.tick_params(axis="both", labelsize=PLOT_STYLE["font_size"])
        ax.legend(fontsize=PLOT_STYLE["font_size"], loc="lower right", framealpha=0.8)

    if show_spdx and show_cdx:
        fig, (ax_spdx, ax_cdx) = plt.subplots(1, 2, figsize=(14, 5))
        _stacked_barh(ax_spdx, spdx_data, "SPDX Relationship Types by Tool")
        _stacked_barh(ax_cdx,  cdx_data,  "CycloneDX Component Types by Tool")
    elif show_spdx:
        fig, ax = plt.subplots(1, 1, figsize=(10, 3.5))
        _stacked_barh(ax, spdx_data, "SPDX Relationship Types by Tool")
    else:
        fig, ax = plt.subplots(1, 1, figsize=(10, 3.5))
        _stacked_barh(ax, cdx_data, "CycloneDX Component Types by Tool")

    fig.tight_layout()
    out_path = os.path.join(OUT_DIR, "sbom_overview_types.png")
    fig.savefig(out_path, dpi=DPI)
    plt.close(fig)
    print(f"Saved: sbom_overview_types.png")


def write_sbom_overview_csv(output_file: str, agg: dict):
    CDX_KEYS  = ("syft_cdx",  "trivy_cdx")
    SPDX_KEYS = ("syft_spdx", "trivy_spdx", "gh_spdx")

    def _s(values, pct=False):
        if not values:
            return None, None, None
        f = 100 if pct else 1
        return np.mean(values) * f, np.median(values) * f, np.max(values) * f

    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["category", "metric", "subkey", "value"])

        writer.writerow(["_global", "total",        "", agg["total"]])
        writer.writerow(["_global", "parse_errors", "", agg["parse_errors"]])
        for fmt, n in agg["by_format"].items():
            writer.writerow(["_global", "by_format", fmt, n])
        for metric, values, pct in [
            ("raw_size_bytes",       agg["raw_sizes_bytes"],  False),
            ("component_count",      agg["component_counts"], False),
            ("purl_coverage_pct",    agg["purl_coverage"],    True),
            ("license_coverage_pct", agg["license_coverage"], True),
        ]:
            mean, median, mx = _s(values, pct)
            if mean is not None:
                writer.writerow(["_global", metric, "mean",   f"{mean:.2f}"])
                writer.writerow(["_global", metric, "median", f"{median:.2f}"])
                writer.writerow(["_global", metric, "max",    f"{mx:.2f}"])

        for cat in list(CDX_KEYS) + list(SPDX_KEYS):
            cd = agg["by_category"][cat]
            writer.writerow([cat, "n_sboms", "", len(cd["component_counts"])])
            for metric, values, pct in [
                ("component_count",      cd["component_counts"], False),
                ("purl_coverage_pct",    cd["purl_coverage"],    True),
                ("license_coverage_pct", cd["license_coverage"], True),
            ]:
                mean, median, mx = _s(values, pct)
                if mean is not None:
                    writer.writerow([cat, metric, "mean",   f"{mean:.2f}"])
                    writer.writerow([cat, metric, "median", f"{median:.2f}"])
                    writer.writerow([cat, metric, "max",    f"{mx:.2f}"])
            writer.writerow([cat, "duplicate_one_name_sboms", "", cd["duplicate_one_name_sboms"]])
            for metric, values in [
                ("duplicate_names_amount_sboms", cd["duplicate_names_amount_sboms"]),
                ("duplicate_total_amount_sboms", cd["duplicate_total_amount_sboms"]),
            ]:
                mean, median, mx = _s(values, False)
                if mean is not None:
                    writer.writerow([cat, metric, "mean",   f"{mean:.2f}"])
                    writer.writerow([cat, metric, "median", f"{median:.2f}"])
                    writer.writerow([cat, metric, "max",    f"{mx:.2f}"])

            if cat in CDX_KEYS:
                writer.writerow([cat, "has_root_component", "", cd["has_root_component"]])
                writer.writerow([cat, "has_dependencies",   "", cd["has_dependencies"]])
                for metric, values, pct in [
                    ("cpe_coverage_pct",        cd["cpe_coverage"],           True),
                    ("dep_edge_count",           cd["dep_edge_counts"],        False),
                    ("deps_per_node",            cd["deps_per_node"],          False),
                    ("components_in_graph_pct",  cd["components_in_graph_frac"], True),
                    ("leaf_node_pct",            cd["leaf_node_frac"],         True),
                ]:
                    mean, median, mx = _s(values, pct)
                    if mean is not None:
                        writer.writerow([cat, metric, "mean",   f"{mean:.2f}"])
                        writer.writerow([cat, metric, "median", f"{median:.2f}"])
                        writer.writerow([cat, metric, "max",    f"{mx:.2f}"])
                for t, n in cd["component_types"].items():
                    writer.writerow([cat, "component_type", t, n])

            elif cat in SPDX_KEYS:
                writer.writerow([cat, "has_relationships", "", cd["has_relationships"]])
                writer.writerow([cat, "has_describes",     "", cd["has_describes"]])
                for metric, values, pct in [
                    ("rel_count",               cd["rel_counts"],               False),
                    ("pkgs_covered_pct",         cd["pkgs_covered_frac"],        True),
                    ("components_in_graph_pct",  cd["components_in_graph_frac"], True),
                    ("leaf_node_pct",            cd["leaf_node_frac"],           True),
                ]:
                    mean, median, mx = _s(values, pct)
                    if mean is not None:
                        writer.writerow([cat, metric, "mean",   f"{mean:.2f}"])
                        writer.writerow([cat, metric, "median", f"{median:.2f}"])
                        writer.writerow([cat, metric, "max",    f"{mx:.2f}"])
                for t, n in cd["rel_types"].items():
                    writer.writerow([cat, "rel_type", t, n])

    print(f"Saved: {output_file}")


def read_sbom_overview_csv(csv_file: str):
    CATS = ("syft_cdx", "trivy_cdx", "syft_spdx", "trivy_spdx", "gh_spdx")
    COUNTERS = {"has_root_component", "has_dependencies", "has_relationships", "has_describes", "duplicate_one_name_sboms"}

    summary = {
        "total": 0, "parse_errors": 0, "by_format": {}, "global_stats": {},
        "by_category": {
            cat: {"n_sboms": 0, "stats": {}, "rel_types": {}, "component_types": {},
                  "has_root_component": 0, "has_dependencies": 0,
                  "has_relationships": 0, "has_describes": 0,
                  "duplicate_one_name_sboms": 0,
                  "duplicate_names_amount_sboms": [],
                  "duplicate_total_amount_sboms": []}
            for cat in CATS
        },
    }

    with open(csv_file, "r", newline="") as f:
        for row in csv.DictReader(f):
            cat, metric, subkey, value = row["category"], row["metric"], row["subkey"], row["value"]
            if cat == "_global":
                if metric == "total":
                    summary["total"] = int(value)
                elif metric == "parse_errors":
                    summary["parse_errors"] = int(value)
                elif metric == "by_format":
                    summary["by_format"][subkey] = int(value)
                else:
                    summary["global_stats"].setdefault(metric, {})[subkey] = value
            elif cat in summary["by_category"]:
                cd = summary["by_category"][cat]
                if metric == "n_sboms":
                    cd["n_sboms"] = int(value)
                elif metric in COUNTERS:
                    cd[metric] = int(value)
                elif metric == "rel_type":
                    cd["rel_types"][subkey] = int(value)
                elif metric == "component_type":
                    cd["component_types"][subkey] = int(value)
                else:
                    cd["stats"].setdefault(metric, {})[subkey] = value

    return summary


def print_sbom_overview_summary(summary: dict):
    CATEGORY_DISPLAY = {
        "gh_spdx":    "github_spdx",
        "trivy_spdx": "trivy_spdx",
        "syft_spdx":  "syft_spdx",
        "trivy_cdx":  "trivy_cyclonedx",
        "syft_cdx":   "syft_cyclonedx",
    }

    def _g(stats, metric):
        s = stats.get(metric, {})
        return s.get("mean", "n/a"), s.get("median", "n/a"), s.get("max", "n/a")

    gs = summary["global_stats"]
    print("=== SBOM Content Analysis ===")
    print(f"Total SBOMs parsed   : {summary['total']:,}")
    print(f"Parse errors         : {summary['parse_errors']:,}")
    print(f"\nBy format:")
    for fmt, n in summary["by_format"].items():
        print(f"  {fmt:<10} {n:>8,}")
    print(f"\n--- Per-SBOM metrics (mean / median / max) ---")
    m, med, mx = _g(gs, "raw_size_bytes")
    print(f"Raw size (bytes)     : {m} / {med} / {mx}")
    m, med, mx = _g(gs, "component_count")
    print(f"Component count      : {m} / {med} / {mx}")
    m, med, mx = _g(gs, "purl_coverage_pct")
    print(f"PURL coverage        : {m}% / {med}% / {mx}%")
    m, med, mx = _g(gs, "license_coverage_pct")
    print(f"License coverage     : {m}% / {med}% / {mx}%")

    for cdx_key in ("syft_cdx", "trivy_cdx"):
        display = CATEGORY_DISPLAY[cdx_key]
        cd = summary["by_category"][cdx_key]
        n_sboms = cd["n_sboms"]
        print(f"\n--- {display} (n={n_sboms:,}) ---")
        m, med, mx = _g(cd["stats"], "component_count")
        print(f"Component count      : {m} / {med} / {mx}")
        print(f"Duplicate SBOMs      : {cd['duplicate_one_name_sboms']:,}")
        m, med, mx = _g(cd["stats"], "duplicate_names_amount_sboms")
        print(f"Dup. names / SBOM    : {m} / {med} / {mx}")
        m, med, mx = _g(cd["stats"], "duplicate_total_amount_sboms")
        print(f"Dup. total / SBOM    : {m} / {med} / {mx}")
        m, med, mx = _g(cd["stats"], "purl_coverage_pct")
        print(f"PURL coverage        : {m}% / {med}% / {mx}%")
        m, med, mx = _g(cd["stats"], "license_coverage_pct")
        print(f"License coverage     : {m}% / {med}% / {mx}%")
        m, med, mx = _g(cd["stats"], "cpe_coverage_pct")
        print(f"CPE coverage         : {m}% / {med}% / {mx}%")
        if n_sboms:
            print(f"Has root component   : {cd['has_root_component']:,} ({cd['has_root_component']/n_sboms*100:.1f}%)")
            print(f"Has dependencies     : {cd['has_dependencies']:,} ({cd['has_dependencies']/n_sboms*100:.1f}%)")
        m, med, mx = _g(cd["stats"], "dep_edge_count")
        print(f"Dep. edges           : {m} / {med} / {mx}")
        m, med, mx = _g(cd["stats"], "deps_per_node")
        print(f"Avg. dependsOn/node  : {m} / {med} / {mx}")
        m, med, mx = _g(cd["stats"], "components_in_graph_pct")
        print(f"Components in graph  : {m}% / {med}% / {mx}%")
        m, med, mx = _g(cd["stats"], "leaf_node_pct")
        print(f"Leaf node fraction   : {m}% / {med}% / {mx}%")
        if cd["component_types"]:
            print(f"Component types:")
            for t, n in sorted(cd["component_types"].items(), key=lambda x: -x[1]):
                print(f"  {t:<20} {n:>10,}")

    for spdx_key in ("syft_spdx", "trivy_spdx", "gh_spdx"):
        display = CATEGORY_DISPLAY[spdx_key]
        sd = summary["by_category"][spdx_key]
        n_sboms = sd["n_sboms"]
        print(f"\n--- {display} (n={n_sboms:,}) ---")
        m, med, mx = _g(sd["stats"], "component_count")
        print(f"Component count      : {m} / {med} / {mx}")
        print(f"Duplicate SBOMs      : {sd['duplicate_one_name_sboms']:,}")
        m, med, mx = _g(sd["stats"], "duplicate_names_amount_sboms")
        print(f"Dup. names / SBOM    : {m} / {med} / {mx}")
        m, med, mx = _g(sd["stats"], "duplicate_total_amount_sboms")
        print(f"Dup. total / SBOM    : {m} / {med} / {mx}")
        m, med, mx = _g(sd["stats"], "purl_coverage_pct")
        print(f"PURL coverage        : {m}% / {med}% / {mx}%")
        m, med, mx = _g(sd["stats"], "license_coverage_pct")
        print(f"License coverage     : {m}% / {med}% / {mx}%")
        if n_sboms:
            print(f"Has relationships    : {sd['has_relationships']:,} ({sd['has_relationships']/n_sboms*100:.1f}%)")
            print(f"Has DESCRIBES rel.   : {sd['has_describes']:,} ({sd['has_describes']/n_sboms*100:.1f}%)")
        m, med, mx = _g(sd["stats"], "rel_count")
        print(f"Relationships/SBOM   : {m} / {med} / {mx}")
        m, med, mx = _g(sd["stats"], "pkgs_covered_pct")
        print(f"Packages in rels.    : {m}% / {med}% / {mx}%")
        m, med, mx = _g(sd["stats"], "components_in_graph_pct")
        print(f"Components in graph  : {m}% / {med}% / {mx}%")
        m, med, mx = _g(sd["stats"], "leaf_node_pct")
        print(f"Leaf node fraction   : {m}% / {med}% / {mx}%")
        if sd["rel_types"]:
            print(f"Relationship types:")
            for t, n in sorted(sd["rel_types"].items(), key=lambda x: -x[1]):
                print(f"  {t:<25} {n:>10,}")


def sbom_overview(generate_plots: bool = True, output_file: str = None, csv_file: str = None, side: str = None):
    if csv_file:
        print(f"Reading SBOM overview from {csv_file}...")
        summary = read_sbom_overview_csv(csv_file)
        print_sbom_overview_summary(summary)
        if generate_plots:
            print("\nGenerating SBOM overview plot...")
            plot_sbom_overview(summary, side=side)
        else:
            print("\nSkipping plot generation (--no-plots).")
        return


    con = get_db()
    cur = con.cursor()

    cur.execute("""
        SELECT s.id, s.type, s.origin_type, sr.raw,
               (SELECT c.name FROM sbom_creators sc
                JOIN creators c ON c.id = sc.creator_id
                WHERE sc.sbom_id = s.id AND c.type = 'tool'
                LIMIT 1) AS tool_name
        FROM sboms s
        JOIN sbom_raw sr ON sr.sbom_id = s.id
        ORDER BY s.id
    """)

    CATEGORY_DISPLAY = {
        "gh_spdx":    "github_spdx",
        "trivy_spdx": "trivy_spdx",
        "syft_spdx":  "syft_spdx",
        "trivy_cdx":  "trivy_cyclonedx",
        "syft_cdx":   "syft_cyclonedx",
    }

    agg = {
        "total": 0,
        "parse_errors": 0,
        "by_format": {},
        "raw_sizes_bytes": [],
        # component-level
        "component_counts": [],
        "purl_coverage": [],
        "license_coverage": [],
        # per-category (tool × format)
        "by_category": {
            cat: {
                "component_counts": [], "purl_coverage": [], "license_coverage": [],
                "duplicate_one_name_sboms": 0,
                "duplicate_names_amount_sboms": [],
                "duplicate_total_amount_sboms": [],
                # CDX-specific (populated for trivy_cdx / syft_cdx)
                "cpe_coverage": [], "has_root_component": 0, "has_dependencies": 0,
                "dep_edge_counts": [], "deps_per_node": [],
                "components_in_graph_frac": [], "leaf_node_frac": [],
                "component_types": {},
                # SPDX-specific (populated for trivy_spdx / syft_spdx / gh_spdx)
                "has_relationships": 0, "rel_counts": [], "rel_types": {},
                "pkgs_covered_frac": [], "has_describes": 0,
            }
            for cat in CATEGORY_DISPLAY
        },
    }

    for row in tqdm(cur, desc="Parsing SBOMs", unit=" sboms"):
        agg["total"] += 1
        fmt = normalize_format(row["type"])
        agg["by_format"][fmt] = agg["by_format"].get(fmt, 0) + 1
        agg["raw_sizes_bytes"].append(len(row["raw"]))#.encode("utf-8")))
        #agg["raw_sizes_bytes"].append(sum(sys.getsizeof(item) for item in row["raw"]))

        try:
            sbom = json.loads(row["raw"])
        except json.JSONDecodeError:
            agg["parse_errors"] += 1
            continue

        label = normalize_tool_label(row)

        if fmt == "cdx":
            comps = sbom.get("components") or []
            n = len(comps)
            agg["component_counts"].append(n)
            duplicate_name_count, duplicate_total_count = count_duplicate_component_stats(sbom, fmt)
            cat_data = agg["by_category"].get(label)
            if cat_data is not None:
                cat_data["duplicate_names_amount_sboms"].append(duplicate_name_count)
                cat_data["duplicate_total_amount_sboms"].append(duplicate_total_count)
                if duplicate_name_count > 0:
                    cat_data["duplicate_one_name_sboms"] += 1

            if n:
                purl_hits = sum(1 for c in comps if c.get("purl"))
                lic_hits  = sum(1 for c in comps if c.get("licenses"))
                cpe_hits  = sum(1 for c in comps if c.get("cpe"))
                agg["purl_coverage"].append(purl_hits / n)
                agg["license_coverage"].append(lic_hits / n)
                if cat_data is not None:
                    cat_data["component_counts"].append(n)
                    cat_data["purl_coverage"].append(purl_hits / n)
                    cat_data["license_coverage"].append(lic_hits / n)
                    cat_data["cpe_coverage"].append(cpe_hits / n)
            elif cat_data is not None:
                cat_data["component_counts"].append(n)

            for comp in comps:
                t = comp.get("type", "unknown")
                if cat_data is not None:
                    cat_data["component_types"][t] = cat_data["component_types"].get(t, 0) + 1

            if sbom.get("metadata", {}).get("component"):
                if cat_data is not None:
                    cat_data["has_root_component"] += 1

            deps = sbom.get("dependencies") or []
            if deps:
                total_edges = sum(len(d.get("dependsOn") or []) for d in deps)
                refs_in_graph = {d["ref"] for d in deps}
                comp_refs = {c.get("bom-ref") for c in comps if c.get("bom-ref")}
                leaf_count = sum(1 for d in deps if not d.get("dependsOn"))
                if cat_data is not None:
                    cat_data["has_dependencies"] += 1
                    cat_data["dep_edge_counts"].append(total_edges)
                    cat_data["deps_per_node"].append(total_edges / len(deps))
                    if comp_refs:
                        cat_data["components_in_graph_frac"].append(len(refs_in_graph & comp_refs) / len(comp_refs))
                    cat_data["leaf_node_frac"].append(leaf_count / len(deps))
            else:
                cat_data["dep_edge_counts"].append(0)

        elif fmt == "spdx":
            pkgs = sbom.get("packages") or []
            n = len(pkgs)
            agg["component_counts"].append(n)
            duplicate_name_count, duplicate_total_count = count_duplicate_component_stats(sbom, fmt)
            cat_data = agg["by_category"].get(label)
            if cat_data is not None:
                cat_data["duplicate_names_amount_sboms"].append(duplicate_name_count)
                cat_data["duplicate_total_amount_sboms"].append(duplicate_total_count)
                if duplicate_name_count > 0:
                    cat_data["duplicate_one_name_sboms"] += 1

            if n:
                purl_hits = sum(
                    1 for p in pkgs
                    if any(r.get("referenceType") == "purl" for r in (p.get("externalRefs") or []))
                )
                lic_hits = sum(
                    1 for p in pkgs
                    if p.get("licenseConcluded") not in (None, "NOASSERTION", "NONE")
                )
                agg["purl_coverage"].append(purl_hits / n)
                agg["license_coverage"].append(lic_hits / n)
                if cat_data is not None:
                    cat_data["component_counts"].append(n)
                    cat_data["purl_coverage"].append(purl_hits / n)
                    cat_data["license_coverage"].append(lic_hits / n)
            elif cat_data is not None:
                cat_data["component_counts"].append(n)

            rels = sbom.get("relationships") or []
            if rels:
                pkg_ids = {p["SPDXID"] for p in pkgs if "SPDXID" in p}
                covered = set()
                has_describes = False
                depends_on_sources = set()
                depends_on_nodes = set()
                for rel in rels:
                    rt = rel.get("relationshipType", "unknown")
                    covered.add(rel.get("spdxElementId"))
                    covered.add(rel.get("relatedSpdxElement"))
                    if rt == "DESCRIBES":
                        has_describes = True
                    if rt == "DEPENDS_ON":
                        src = rel.get("spdxElementId")
                        tgt = rel.get("relatedSpdxElement")
                        if src:
                            depends_on_sources.add(src)
                            depends_on_nodes.add(src)
                        if tgt:
                            depends_on_nodes.add(tgt)
                    if rt == "DEPENDENCY_OF":
                        # DEPENDENCY_OF is the inverse of DEPENDS_ON: src depends on tgt is expressed
                        # as tgt DEPENDENCY_OF src, so the dependency direction is reversed — tgt is
                        # the dependant (source) and src is the leaf (target).
                        src = rel.get("spdxElementId")
                        tgt = rel.get("relatedSpdxElement")
                        if tgt:
                            depends_on_sources.add(tgt)
                            depends_on_nodes.add(tgt)
                        if src:
                            depends_on_nodes.add(src)

                if cat_data is not None:
                    cat_data["has_relationships"] += 1
                    cat_data["rel_counts"].append(len(rels))
                    for rel in rels:
                        rt = rel.get("relationshipType", "unknown")
                        cat_data["rel_types"][rt] = cat_data["rel_types"].get(rt, 0) + 1
                    if has_describes:
                        cat_data["has_describes"] += 1
                    if pkg_ids:
                        cat_data["pkgs_covered_frac"].append(len(covered & pkg_ids) / len(pkg_ids))
                    if depends_on_nodes:
                        leaf_nodes = depends_on_nodes - depends_on_sources
                        cat_data["leaf_node_frac"].append(len(leaf_nodes) / len(depends_on_nodes))
                        if pkg_ids:
                            cat_data["components_in_graph_frac"].append(len(depends_on_nodes & pkg_ids) / len(pkg_ids))

    cur.close()
    con.close()

    def _stats(values, pct=False):
        if not values:
            return "n/a", "n/a", "n/a"
        factor = 100 if pct else 1
        return (f"{np.mean(values)*factor:.2f}",
                f"{np.median(values)*factor:.2f}",
                f"{np.max(values)*factor:.2f}")

    total = agg["total"]

    print("=== SBOM Content Analysis ===")
    print(f"Total SBOMs parsed   : {total:,}")
    print(f"Parse errors         : {agg['parse_errors']:,}")
    print(f"\nBy format:")
    for fmt, n in agg["by_format"].items():
        print(f"  {fmt:<10} {n:>8,}")

    print(f"\n--- Per-SBOM metrics (mean / median / max) ---")
    m, med, mx = _stats(agg["raw_sizes_bytes"])
    print(f"Raw size (bytes)     : {m} / {med} / {mx}")
    m, med, mx = _stats(agg["component_counts"])
    print(f"Component count      : {m} / {med} / {mx}")
    m, med, mx = _stats(agg["purl_coverage"], pct=True)
    print(f"PURL coverage        : {m}% / {med}% / {mx}%")
    m, med, mx = _stats(agg["license_coverage"], pct=True)
    print(f"License coverage     : {m}% / {med}% / {mx}%")

    # Per-tool CycloneDX sections
    for cdx_key in ("syft_cdx", "trivy_cdx"):
        display = CATEGORY_DISPLAY[cdx_key]
        cd = agg["by_category"][cdx_key]
        n_sboms = len(cd["component_counts"])
        print(f"\n--- {display} (n={n_sboms:,}) ---")
        m, med, mx = _stats(cd["component_counts"])
        print(f"Component count      : {m} / {med} / {mx}")
        print(f"Duplicate SBOMs      : {cd['duplicate_one_name_sboms']:,}")
        m, med, mx = _stats(cd["duplicate_names_amount_sboms"])
        print(f"Dup. names / SBOM    : {m} / {med} / {mx}")
        m, med, mx = _stats(cd["duplicate_total_amount_sboms"])
        print(f"Dup. total / SBOM    : {m} / {med} / {mx}")
        m, med, mx = _stats(cd["purl_coverage"], pct=True)
        print(f"PURL coverage        : {m}% / {med}% / {mx}%")
        m, med, mx = _stats(cd["license_coverage"], pct=True)
        print(f"License coverage     : {m}% / {med}% / {mx}%")
        m, med, mx = _stats(cd["cpe_coverage"], pct=True)
        print(f"CPE coverage         : {m}% / {med}% / {mx}%")
        if n_sboms:
            print(f"Has root component   : {cd['has_root_component']:,} ({cd['has_root_component']/n_sboms*100:.1f}%)")
            print(f"Has dependencies     : {cd['has_dependencies']:,} ({cd['has_dependencies']/n_sboms*100:.1f}%)")
        m, med, mx = _stats(cd["dep_edge_counts"])
        print(f"Dep. edges           : {m} / {med} / {mx}")
        m, med, mx = _stats(cd["deps_per_node"])
        print(f"Avg. dependsOn/node  : {m} / {med} / {mx}")
        m, med, mx = _stats(cd["components_in_graph_frac"], pct=True)
        print(f"Components in graph  : {m}% / {med}% / {mx}%")
        m, med, mx = _stats(cd["leaf_node_frac"], pct=True)
        print(f"Leaf node fraction   : {m}% / {med}% / {mx}%")
        if cd["component_types"]:
            print(f"Component types:")
            for t, n in sorted(cd["component_types"].items(), key=lambda x: -x[1]):
                print(f"  {t:<20} {n:>10,}")

    # Per-tool SPDX sections
    for spdx_key in ("syft_spdx", "trivy_spdx", "gh_spdx"):
        display = CATEGORY_DISPLAY[spdx_key]
        sd = agg["by_category"][spdx_key]
        n_sboms = len(sd["component_counts"])
        print(f"\n--- {display} (n={n_sboms:,}) ---")
        m, med, mx = _stats(sd["component_counts"])
        print(f"Component count      : {m} / {med} / {mx}")
        print(f"Duplicate SBOMs      : {sd['duplicate_one_name_sboms']:,}")
        m, med, mx = _stats(sd["duplicate_names_amount_sboms"])
        print(f"Dup. names / SBOM    : {m} / {med} / {mx}")
        m, med, mx = _stats(sd["duplicate_total_amount_sboms"])
        print(f"Dup. total / SBOM    : {m} / {med} / {mx}")
        m, med, mx = _stats(sd["purl_coverage"], pct=True)
        print(f"PURL coverage        : {m}% / {med}% / {mx}%")
        m, med, mx = _stats(sd["license_coverage"], pct=True)
        print(f"License coverage     : {m}% / {med}% / {mx}%")
        if n_sboms:
            print(f"Has relationships    : {sd['has_relationships']:,} ({sd['has_relationships']/n_sboms*100:.1f}%)")
            print(f"Has DESCRIBES rel.   : {sd['has_describes']:,} ({sd['has_describes']/n_sboms*100:.1f}%)")
        m, med, mx = _stats(sd["rel_counts"])
        print(f"Relationships/SBOM   : {m} / {med} / {mx}")
        m, med, mx = _stats(sd["pkgs_covered_frac"], pct=True)
        print(f"Packages in rels.    : {m}% / {med}% / {mx}%")
        m, med, mx = _stats(sd["components_in_graph_frac"], pct=True)
        print(f"Components in graph  : {m}% / {med}% / {mx}%")
        m, med, mx = _stats(sd["leaf_node_frac"], pct=True)
        print(f"Leaf node fraction   : {m}% / {med}% / {mx}%")
        if sd["rel_types"]:
            print(f"Relationship types:")
            for t, n in sorted(sd["rel_types"].items(), key=lambda x: -x[1]):
                print(f"  {t:<25} {n:>10,}")

    if output_file:
        write_sbom_overview_csv(output_file, agg)

    if generate_plots:
        print("\nGenerating SBOM overview plot...")
        plot_sbom_overview(agg, side=side)
    else:
        print("\nSkipping plot generation (--no-plots).")


def compute_jaccard_stats(csv_file: str, generate_plots: bool = True, min_union_size: int = 0):
    if not os.path.isfile(csv_file):
        print(f"CSV file not found: {csv_file}")
        return
    
    with open(csv_file, "r") as f:
        reader = csv.DictReader(f)

        total_repo_ids = set()
        total_repo_state_ids = set()
        complete_repo_ids = set()
        complete_repo_state_ids = set()

        jaccard_values = {}
        for row in tqdm(reader, desc="Processing Jaccard CSV", unit="row"):
            repo_id = row["repo_id"]
            repo_state_id = row["repo_state_id"]

            if repo_id:
                total_repo_ids.add(repo_id)
            if repo_state_id:
                total_repo_state_ids.add(repo_state_id)

            if not int(row["all_tools_present"]) == 1:
                continue

            if repo_id:
                complete_repo_ids.add(repo_id)
            if repo_state_id:
                complete_repo_state_ids.add(repo_state_id)

            tool_a = row["tool_a"]
            tool_b = row["tool_b"]

            count_a = int(row["count_a"])
            count_b = int(row["count_b"])
            union_size = int(row["union_size"])

            j = row["jaccard"]

            pair = (tool_a, tool_b)

            if union_size < min_union_size: # exclude pairs whose union is smaller than this threshold
                continue

            if j and (count_a > 0 and count_b > 0): # only consider pairs where both tools found components
                if pair not in jaccard_values:
                    jaccard_values[pair] = []

                jaccard_values[pair].append(float(j))

    print(f"\nTotal repositories in CSV: {len(total_repo_ids)}")
    print(f"Total repository states in CSV: {len(total_repo_state_ids)}")
    print(f"Repositories with complete SBOM set: {len(complete_repo_ids)}")
    print(f"Repository states with complete SBOM set: {len(complete_repo_state_ids)}")

    if not jaccard_values:
        print("No Jaccard values found in the CSV.")
        return
    
    means = {}
    medians = {}
    
    print("\nMean and Median Jaccard similarity for each tool pair:")
    for pair, jaccard_list in jaccard_values.items():
        sum_jaccard = sum(jaccard_list)
        count = len(jaccard_list)

        avg_jaccard = sum_jaccard / count
        median_jaccard = np.median(jaccard_list)
        print(f"{TOOL_DISPLAY_NAMES.get(pair[0], pair[0])} vs {TOOL_DISPLAY_NAMES.get(pair[1], pair[1])}: mean {avg_jaccard:.4f}, median {median_jaccard:.4f} (based on {count} repos)")

        means[pair] = (avg_jaccard, count)
        medians[pair] = (median_jaccard, count)

    if generate_plots:
        print("\nGenerating three plots for Adrian...")
        print("\nGenerating mean bar chart...")
        plot_mean_median_comp_bar_chart(mean_jaccards=means)

        print("Generating median bar chart...")
        plot_mean_median_comp_bar_chart(median_jaccards=medians)

        print("Generating mean and median comparison bar chart...")
        plot_mean_median_comp_bar_chart(mean_jaccards=means, median_jaccards=medians)

        print("Generating Jaccard histograms...")
        mean_sorted_pairs = [pair for pair, _ in sorted(means.items(), key=lambda x: x[1][0])] # to display the histograms in the same order as the mean bars
        plot_jaccard_histograms(jaccard_values, pair_order=mean_sorted_pairs)
    else:
        print("\nSkipping plot generation (--no-plots).")

def arguments(parser):
    parser.description = "SBOM-Dataset analysis"

    parser.add_argument("--image-dpi", type=int, required=False, help=f"default DPI of all result figures is {DPI}")
    parser.add_argument("--out-dir", type=str, required=False, help=f"directory for results (default (cwd): {OUT_DIR})")

    subparsers = parser.add_subparsers(title="subcommands",
                                       description="valid subcommands for sbom database analysis",
                                       help='additional help available with `<subcommand> -h` or `<subcommand> --help`',
                                       dest="analysis_subparser")

    sbomqs_parser = subparsers.add_parser("sbomqs-analysis", description="Compute dataset metrics based on sbomqs data", help="Compute dataset metrics based on sbomqs data")
    sbomqs_parser.add_argument("--creators", type=str, nargs='+', required=True, help="SBOM-Creators for which average sbomqs scores should be aggregated")

    jaccard_parser = subparsers.add_parser("compute-jaccard",
                                           description="Compute pairwise Jaccard similarities across SBOM tools per repository state and write them to a CSV file",
                                           help="Compute pairwise Jaccard similarities and write CSV")
    
    jaccard_parser.add_argument("-o", "--output", type=str, required=True)
    jaccard_parser.add_argument("--log-file", type=str, required=False, help="Log file.", default = "./analysis.log")
    jaccard_parser.add_argument("--min-stars", type=int, required=False, default=0, help="Minimum number of stars for repositories to be included (default: 0)")
    jaccard_parser.add_argument("--max-workers", type=int, required=False, default=16)
    jaccard_parser.add_argument("--filter-repo-comps", action="store_true", help="Filter out repository-level components (For Trivy and Syft) like the repository itself and .github/workflow files from the Jaccard computation")
    jaccard_parser.add_argument("--names-only", action="store_true", help="Compare component names only, ignoring versions")

    jaccard_stat_parser = subparsers.add_parser("jaccard-stats",
                                                description="Read a Jaccard CSV, report summary statistics, and optionally generate plot images",
                                                help="Summarize Jaccard CSV (means) and optionally plot means and histograms")

    jaccard_stat_parser.add_argument("--csv-file", type=str, required=True, help="File containing Jaccard similarities (generated by compute-jaccard)")
    jaccard_stat_parser.add_argument("--no-plot", action="store_true", help="Disable plot generation")
    jaccard_stat_parser.add_argument("--union-size", type=int, required=False, default=0, help="Minimum union size (count_a + count_b - intersection) for a tool pair to be included (default: 0, i.e. no filtering)")

    repo_overview_parser = subparsers.add_parser("repo-overview",
                                                 description="Print repository statistics (count, stars, size, top languages) and generate overview plots",
                                                 help="Print repo stats and optionally generate box plots and language chart")
    repo_overview_parser.add_argument("--no-plot", action="store_true", help="Disable plot generation")
    repo_overview_parser.add_argument("-o", "--output", type=str, required=False, help="Write results to CSV file")
    repo_overview_parser.add_argument("--csv-file", type=str, required=False, help="Read results from CSV (skips DB query)")
    repo_overview_parser.add_argument("--dominant-languages", action="store_true",
                                      help="Print a table of the most dominant programming languages (top language per repo, with avg. percentage when dominant)")

    sbom_overview_parser = subparsers.add_parser("sbom-overview",
                          description="Stream and parse raw SBOM JSON to report component counts, PURL/license/CPE coverage, dependency graph metrics (CycloneDX), and relationship metrics (SPDX)",
                          help="Analyze raw SBOM JSON content")
    sbom_overview_parser.add_argument("--no-plot", action="store_true", help="Disable plot generation")
    sbom_overview_parser.add_argument("-o", "--output", type=str, required=False, help="Write results to CSV file")
    sbom_overview_parser.add_argument("--csv-file", type=str, required=False, help="Read results from CSV (skips DB query)")
    sbom_overview_parser.add_argument("--side", type=str, choices=["cdx", "spdx"], required=False,
                                      help="Plot only one format side: 'cdx' (CycloneDX) or 'spdx'. Omit for both.")

def main(args):
    global DPI, OUT_DIR

    if not os.path.exists("sboms.db"):
        sys.exit("Did not find Database! Use the scraper to aquire some data first!")

    if (dpi := args.image_dpi):
        DPI = dpi

    if (out_dir := args.out_dir):
        OUT_DIR = out_dir

    if args.analysis_subparser == "sbomqs-analysis":
        sbomqs(args.creators)

    if args.analysis_subparser == "compute-jaccard":
        logging.basicConfig(filename=args.log_file, level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

        logging.info("Starting Jaccard computation")

        compute_jaccard_dataset(args.output, args.min_stars, args.max_workers, filter_repo_comps=args.filter_repo_comps, names_only=args.names_only)

        logging.info("Finished Jaccard computation")

    if args.analysis_subparser == "jaccard-stats":
        compute_jaccard_stats(args.csv_file, generate_plots=not args.no_plot, min_union_size=args.union_size)

    if args.analysis_subparser == "repo-overview":
        repo_overview(generate_plots=not args.no_plot,
                      output_file=args.output,
                      csv_file=args.csv_file,
                      show_dominant_languages=args.dominant_languages)

    if args.analysis_subparser == "sbom-overview":
        sbom_overview(generate_plots=not args.no_plot,
                      output_file=args.output,
                      csv_file=args.csv_file,
                      side=args.side)
