"""CLI entry point for waffy-learn."""

import argparse
import sys
from pathlib import Path

from .capture import AccessLogCapture, HarCapture
from .config import LearnConfig
from .profiler import ProfileBuilder


def main():
    parser = argparse.ArgumentParser(
        prog="waffy-learn",
        description="waffy traffic learning engine — analyze traffic to build whitelist rules",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # learn from access log
    log_parser = subparsers.add_parser("from-log", help="Learn from nginx access log")
    log_parser.add_argument("log_file", type=Path, help="Path to nginx access log")
    log_parser.add_argument("--format", choices=["json", "text"], default="json",
                            help="Log format (default: json)")
    log_parser.add_argument("--output", "-o", type=Path, default=Path("./profiles"),
                            help="Output directory for profile YAML files")
    log_parser.add_argument("--min-samples", type=int, default=100,
                            help="Minimum requests per location before profiling")

    # learn from HAR file
    har_parser = subparsers.add_parser("from-har", help="Learn from HAR file")
    har_parser.add_argument("har_file", type=Path, help="Path to HAR file")
    har_parser.add_argument("--output", "-o", type=Path, default=Path("./profiles"),
                            help="Output directory for profile YAML files")
    har_parser.add_argument("--min-samples", type=int, default=5,
                            help="Minimum requests per location (lower for HAR)")

    # status
    subparsers.add_parser("status", help="Show learning status")

    args = parser.parse_args()

    if args.command == "from-log":
        return cmd_from_log(args)
    elif args.command == "from-har":
        return cmd_from_har(args)
    elif args.command == "status":
        return cmd_status(args)

    return 1


def cmd_from_log(args) -> int:
    config = LearnConfig(
        profile_output_dir=args.output,
        min_samples=args.min_samples,
    )

    capture = AccessLogCapture(args.log_file, log_format=args.format)
    builder = ProfileBuilder(config)

    print(f"Reading access log: {args.log_file}")
    count = 0
    for sample in capture.read_samples():
        builder.add_sample(sample)
        count += 1
        if count % 10000 == 0:
            print(f"  processed {count} requests...")

    print(f"Total requests processed: {count}")
    print(f"Locations discovered: {len(builder.locations)}")

    print("\nRunning type inference...")
    builder.analyze()

    print(f"Exporting profiles to: {args.output}")
    written = builder.export_yaml(args.output)
    for path in written:
        print(f"  wrote {path}")

    print(f"\nDone. {len(written)} profile(s) generated.")
    print("Next: review profiles, then run waffy-compile to generate binary rules.")
    return 0


def cmd_from_har(args) -> int:
    config = LearnConfig(
        profile_output_dir=args.output,
        min_samples=args.min_samples,
    )

    capture = HarCapture(args.har_file)
    builder = ProfileBuilder(config)

    print(f"Reading HAR file: {args.har_file}")
    count = 0
    for sample in capture.read_samples():
        builder.add_sample(sample)
        count += 1

    print(f"Total requests: {count}")
    print(f"Locations: {len(builder.locations)}")

    builder.analyze()

    written = builder.export_yaml(args.output)
    for path in written:
        print(f"  wrote {path}")

    print(f"\n{len(written)} profile(s) generated.")
    return 0


def cmd_status(args) -> int:
    print("waffy Learning Status")
    print("(not yet implemented — will show learning progress for daemon mode)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
