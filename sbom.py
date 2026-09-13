#!/usr/bin/env python3

import argparse
from scraper.scraper import arguments as scraper_arguments, main as scraper_main
from generator.gen_sbom import arguments as generator_arguments, main as generator_main
from analysis.analyze import arguments as analyzer_arguments, main as analyzer_main
from scoring.score import arguments as scoring_arguments, main as scoring_main

from utilities.utils import *

def scrape(args):
    scraper_main(args)

def generate(args):
    generator_main(args)

def analyze(args):
    analyzer_main(args)

def score(args):
    scoring_main(args)

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--update-db", action="store_true", help="update the database and quit (update is also always performed by subcommands)")

    subparsers = parser.add_subparsers(title="subcommands",
                                       description="valid subcommands for scraping repositories, generating sboms and data analysis",
                                       help='additional help available with `<subcommand> -h` or `<subcommand> --help`',
                                       dest="subparser")

    scraper_parser = subparsers.add_parser("scrape")
    scraper_arguments(scraper_parser)

    generator_parser = subparsers.add_parser("generate")
    generator_arguments(generator_parser)

    analyzer_parser = subparsers.add_parser("analyze")
    analyzer_arguments(analyzer_parser)

    scoring_parser = subparsers.add_parser("score")
    scoring_arguments(scoring_parser)

    args = parser.parse_args()

    init_db()

    # initializing the database performs updates automatically
    if args.update_db:
        sys.exit(0)

    # print usage of command if no further args were provided
    if (fn := globals().get(args.subparser)):
        fn(args)
    else:
        parser.print_usage()

if __name__ == "__main__":
    main()
