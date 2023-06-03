#!/usr/bin/python

"""Monitors a fuzzing session and once in a while generates a BB coverage report.

@m4drat - 2023
"""

import os
import json
import time
import shutil
import argparse
import subprocess
from pathlib import Path
from merge_coverage_traces import merge_coverage_files
from typing import List


def generate_coverage_trace(
    wtf: Path, target_fuzzer: str, coverage_reports_dir: Path, inputs_dir: Path
) -> bool:
    """Generate a BB coverage trace for a given testcase.

    Args:
        wtf (Path): Path to the WTF binary
        target_fuzzer (str): Name of the target fuzzer
        coverage_reports_dir (Path): Path where to store the generated coverage trace
        inputs_dir (Path): Path to the testcases directory

    Returns:
        bool: True if coverage traces were generated successfully, False otherwise
    """

    # Generate coverage trace
    p = subprocess.run(
        [
            wtf,
            "run",
            "--name",
            target_fuzzer,
            "--backend=bochscpu",
            "--state=state",
            f"--input={inputs_dir.absolute()}",
            f"--trace-path={coverage_reports_dir}",
            "--trace-type=cov",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )

    return p.returncode == 0


def generate_coverage_traces(
    wtf: Path, target_fuzzer: str, coverage_traces_dir: Path, new_testcases: set
) -> List[Path]:
    """Generate BB coverage traces for new testcases.

    Args:
        wtf (Path): Path to the WTF binary
        target_fuzzer (str): Name of the target fuzzer
        coverage_traces_dir (Path): Path where to store the generated coverage traces
        new_testcases (set): Set of new testcases

    Returns:
        List[Path]: List of generated coverage traces
    """

    coverage_traces: List[Path] = []

    if len(new_testcases) == 0:
        return coverage_traces

    # Copy new testcases to the inputs directory
    testcases_dir = Path(".") / "monitor-inputs"
    testcases_dir.mkdir(exist_ok=True)

    for testcase in new_testcases:
        shutil.copy2(testcase, testcases_dir)

        coverage_report_path = coverage_traces_dir / f"{testcase.name}.trace"
        coverage_traces.append(coverage_report_path)

    if generate_coverage_trace(wtf, target_fuzzer, coverage_traces_dir, testcases_dir) is not True:
        print(f'Failed to generate coverage traces for "{testcases_dir}"')

    # Remove copied testcases
    shutil.rmtree(testcases_dir)

    return coverage_traces


def monitor_coverage(
    wtf: Path,
    target_fuzzer: str,
    coverage_traces: Path,
    aggregated_coverage: Path,
    output: Path,
    monitor_interval: int,
):
    """Monitor a fuzzing session and once in a while generate a BB coverage report.

    Args:
        wtf (Path): Path to the WTF binary
        target_fuzzer (str): Name of the target fuzzer
        coverage_traces (Path): Path where to store generated coverage traces
        aggregated_coverage (Path): Path where to store the aggregated coverage trace
        output (Path): Path to the stats output file
        monitor_interval (int): Interval in seconds between each stats update
    """

    aggregated_coverage.touch()
    processed_outputs: set = set()
    merged_coverage: set = set()

    stats = {
        "stats": [
            {
                "timestamp": time.time(),
                "coverage": 0,
                "crashes": 0,
            }
        ]
    }

    while True:
        outputs = set(Path(".").glob("outputs/*"))
        new_outputs = outputs - processed_outputs

        time_to_generate_coverage_start = time.time()
        new_coverage_traces = generate_coverage_traces(
            wtf, target_fuzzer, coverage_traces, new_outputs
        )
        time_to_generate_coverage_end = time.time()
        time_to_generate_coverage = time_to_generate_coverage_end - time_to_generate_coverage_start

        timestamp = time.time()

        time_to_merge_coverage_start = time.time()
        if len(new_coverage_traces) > 0:
            merged_coverage = merge_coverage_files(
                [aggregated_coverage] + new_coverage_traces, True
            )
        coverage_delta = len(merged_coverage) - stats["stats"][-1]["coverage"]
        time_to_merge_coverage_end = time.time()
        time_to_merge_coverage = time_to_merge_coverage_end - time_to_merge_coverage_start

        total_crashes = len(list(Path(".").glob("crashes/*")))
        crashes_delta = total_crashes - stats["stats"][-1]["crashes"]

        print(
            f"[{time.ctime(timestamp)}] Coverage: {len(merged_coverage)} (+{coverage_delta}), Crashes: {total_crashes} (+{crashes_delta}), Testcases: {len(outputs)} +({len(new_outputs)}), Time to generate coverage: {time_to_generate_coverage:.2f}s, Time to merge coverage: {time_to_merge_coverage:.2f}s"
        )

        entry = {
            "timestamp": timestamp,
            "coverage": len(merged_coverage),
            "crashes": total_crashes,
        }
        stats["stats"].append(entry)

        with open(output, "w", encoding="ascii") as stats_file:
            json.dump(stats, stats_file, indent=4)

        # Update set of processed outputs
        processed_outputs.update(new_outputs)

        # Update aggregated coverage
        if len(new_coverage_traces) > 0:
            aggregated_coverage.write_text("\n".join(merged_coverage))

        time.sleep(monitor_interval)


def main():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--wtf",
        type=Path,
        help="Path to the WTF binary",
        required=True,
    )
    p.add_argument(
        "--target-dir",
        type=Path,
        help="Path to the target directory",
        required=True,
    )
    p.add_argument(
        "--target-fuzzer",
        type=str,
        help="Name of the target fuzzer",
        required=True,
    )
    p.add_argument(
        "--coverage-traces-dir",
        type=Path,
        help="Relative path where to store the coverage traces",
        default="monitor-coverage-traces",
    )
    p.add_argument(
        "--aggregated-coverage",
        type=Path,
        help="Relative path where to store the aggregated coverage trace",
        default="aggregated_coverage.trace",
    )
    p.add_argument(
        "--output",
        type=Path,
        help="Relative path to the stats output file",
        default="bb_coverage.json",
    )
    p.add_argument(
        "--monitor-interval",
        type=int,
        help="Interval in seconds between two stats updates",
        default=30,
    )
    args = p.parse_args()

    if not args.wtf.exists():
        print(f"WTF binary {args.wtf} does not exist")
        exit(1)

    if not args.target_dir.exists():
        print(f"Target directory {args.target_dir} does not exist")
        exit(1)

    # Make sure we are in the target directory
    os.chdir(args.target_dir)

    # Remove previous artifacts
    if args.aggregated_coverage.exists():
        args.aggregated_coverage.unlink()

    if args.coverage_traces_dir.exists():
        shutil.rmtree(args.coverage_traces_dir)

    if not args.coverage_traces_dir.exists():
        args.coverage_traces_dir.mkdir()

    monitor_coverage(
        args.wtf,
        args.target_fuzzer,
        args.coverage_traces_dir,
        args.aggregated_coverage,
        args.output,
        args.monitor_interval,
    )


if __name__ == "__main__":
    main()
