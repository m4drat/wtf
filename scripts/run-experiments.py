from subprocess import Popen, PIPE, DEVNULL, TimeoutExpired
import argparse
import pathlib
import yaml
import os
import shutil
import time

WTF_SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent


def run_coverage_monitor(fuzzer_name: str):
    wtf_bin = "wtf.exe" if os.name == "nt" else "wtf"
    return Popen(
        [
            "py",
            "-3",
            WTF_SCRIPTS_DIR / "monitor-bb-coverage.py",
            "--wtf",
            wtf_bin,
            "--target-dir=.",
            f"--target-fuzzer={fuzzer_name}",
            "--monitor-interval=10",
        ],
        stdout=None,
        stderr=None,
        bufsize=1,
        universal_newlines=True,
    )


def run_configuration(configuration_name: pathlib.Path):
    return Popen(
        [
            "py",
            "-3",
            WTF_SCRIPTS_DIR / "run-configuration.py",
            f"{configuration_name}",
        ],
        stdout=DEVNULL,
        stderr=DEVNULL,
    )


def execute_experiment_round(
    exp_round: int,
    results_dir: pathlib.Path,
    round_duration: int,
    fuzzing_config: pathlib.Path,
    fuzzer_name: str,
):
    coverage_monitor = run_coverage_monitor(fuzzer_name)
    configuration_executor = run_configuration(fuzzing_config)

    try:
        if configuration_executor.wait(round_duration) != 0:
            print("Configuration executor failed")
            exit(1)
    except TimeoutExpired:
        print("Round finished, killing processes")
        configuration_executor.kill()
        coverage_monitor.kill()

    # Save the results
    os.rename(
        "bb_coverage.json", results_dir / f"bb-coverage-{exp_round}-{fuzzing_config.stem}.json"
    )

    # Clean up
    outputs_dir = pathlib.Path("./outputs")
    shutil.rmtree(outputs_dir, ignore_errors=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    crashes_dir = pathlib.Path("./crashes")
    shutil.rmtree(crashes_dir, ignore_errors=True)
    crashes_dir.mkdir(parents=True, exist_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "exp_config",
        type=pathlib.Path,
        help="Path to the experiment configuration file",
    )
    parser.add_argument(
        "target_fuzzer",
        type=str,
        help="Name of the target fuzzer",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove crashes and outputs directories before starting the experiment",
    )
    parser.add_argument(
        "--overwrite-results",
        action="store_true",
        help="Overwrite existing results directory",
    )
    args = parser.parse_args()

    with open(args.exp_config, "r", encoding="ascii") as conf_stream:
        try:
            config = yaml.safe_load(conf_stream)
        except yaml.YAMLError as exc:
            print(exc)
            exit(1)

    results_dir = pathlib.Path(config.get("results-dir", "experiment-results")).resolve()
    round_duration = config.get("round-duration", 24 * 60 * 60)
    base_config = pathlib.Path(config.get("base-config", None)).resolve()
    alternative_config = pathlib.Path(config.get("alternative-config", None)).resolve()

    # Check if outputs/crahes directories are not empty
    outputs_dir = pathlib.Path("./outputs")
    crashes_dir = pathlib.Path("./crashes")

    if args.cleanup:
        shutil.rmtree(outputs_dir, ignore_errors=True)
        outputs_dir.mkdir(parents=True, exist_ok=True)

        shutil.rmtree(crashes_dir, ignore_errors=True)
        crashes_dir.mkdir(parents=True, exist_ok=True)

    if len(list(outputs_dir.glob("*"))) > 0 or len(list(crashes_dir.glob("*"))) > 0:
        print("Outputs/crashes directories are not empty")
        exit(1)

    if args.overwrite_results and results_dir.exists():
        print(f"Removing existing results directory {results_dir}")
        shutil.rmtree(results_dir, ignore_errors=True)

    if results_dir.exists():
        print(f"Results directory {results_dir} already exists")
        exit(1)

    results_dir.mkdir(parents=True, exist_ok=True)

    for exp_round in range(config.get("rounds", 1)):
        print(f"Starting experiment round {exp_round + 1}")

        # Execute the experiment round (base)
        execute_experiment_round(
            exp_round,
            results_dir,
            round_duration,
            base_config,
            args.target_fuzzer,
        )

        # Execute the experiment round (alternative)
        execute_experiment_round(
            exp_round,
            results_dir,
            round_duration,
            alternative_config,
            args.target_fuzzer,
        )


if __name__ == "__main__":
    main()
