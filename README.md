# SBOM Database 

This tool allows creating an SBOM dataset for GitHub repositories. Given a list of repositories the tool is able to collect the GitHub Dependency Graph SBOMs as well as capture general information about the repositories themselves. Furthermore, external SBOM generators can be integrated into this tool to generate SBOMs for all captured repositories.

The general functionality of this tool is split into 4 main modules:
1) [Scraper](#scraper)
2) [Generator](#generator)
3) [Scoring](#scoring)
4) [Analysis](#analysis)

All dependencies needed to run this tool are listed in `./requirements.txt`.

Basic usage:
```
sbom.py --help
```

Help page:
```
usage: sbom.py [-h] [--update-db] {scrape,generate,analyze,score} ...

options:
  -h, --help            show this help message and exit
  --update-db           update the database and quit (update is also always performed by subcommands)

subcommands:
  valid subcommands for scraping repositories, generating sboms and data analysis

  {scrape,generate,analyze,score}
                        additional help available with `<subcommand> -h` or `<subcommand> --help`
```

The database schema is defined by the `<order>.sql` files in the `./db/` directory. All `.sql` files are applied in order to the database on creation. When updating the database, the current database version is first checked via `pragma user_version;` with only the missing updates being applied in order.

### 1) Scraper

The scraper (see `./sbom.py scrape --help`) is responsible for collecting data from different datasources. A datasource is a queriable "*forge*" of public software/packages/dependencies/libraries and so on. The scraper can be configured to collect Github repositories and Gitub generated sboms from a supported *forge*.

Support for a forge is provided through `./scraper/ecosystem_support/` which contain helper functions for each *forge*. Currently available *forges* are:
- [crates.io](https://crates.io/) (**Rust**)
- [pypi](https://pypi.org/) (**Python**)

Example (creates a database (if not existent) and adds at most 100 repositories from [crates.io](https://crates.io/), with no particular order):
```
./sbom.py scrape --source-ecosystem Rust --limit 100
```

The created database resides in the root directory and is called `sboms.db`. If you already have a valid database (e.g. downloaded as part of our research) you can simply copy it to the root directory and rename it accordingly.

### 2) Generator

The generator (see `./sbom.py generate --help`) is responsible for generating additional SBOMs from a set of supported tools for github repositories stored in the current SBOM dataset (obtained by `./sbom.py scrape`). SBOMs are generated in a clean podman container to isolate SBOM creation as much as possibel from other processes and data. The repositories are polled on a by need basis, which means that the database stores only references (aka. the url) to the real repositories. This was done because materialization of all repos stored in the database is way to costly, but this approach also comes with the possibility that repositories may become unavailable as time progresses.

Currently supported SBOM generators are:
- [Trivy](https://github.com/aquasecurity/trivy)
- [Syft](https://github.com/anchore/syft)
- [cdxgen](https://github.com/cdxgen/cdxgen)

Example ([Trivy](https://github.com/aquasecurity/trivy)):
```
./sbom.py generate --sbom-generator trivy --num-workers 8
```

Example ([Syft](https://github.com/anchore/syft)):
```
./sbom.py generate --sbom-generator syft --num-workers 8
```

### 3) Scoring

The scoring module (see `./sbom.py score --help`) adds [sbomqs](https://github.com/interlynk-io/sbomqs) assessments of all contained SBOMs to the database.

Example:
```
./sbom.py score --num-workers 8
```


### 4) Analysis

The analysis module (see `./sbom.py analyze --help`) provides a wide variety of automated analyses on the database.

Example ([sbomqs](https://github.com/interlynk-io/sbomqs) average scores per sbom format and generator):
```
./sbom.py analyze sbomqs-analysis GitHub syft trivy
```

Example (compute pairwise jaccard similarities between SBOMs for the same repository with additional plotting of diagrams):
```
./sbom.py analyze compute-jaccard --max-workers 8 -o ./jaccard.csv
./sbom.py analyze jaccard-stats --csv-file ./jaccard.csv
```

