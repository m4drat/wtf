from scipy.stats import norm

import seaborn as sns
import matplotlib.pyplot as plt
import argparse as ap
import pandas as pd
import pathlib
import yaml
import json


def load_single_result(result_file: pathlib.Path) -> pd.DataFrame:
    dataframe = pd.read_json(result_file)["stats"]
    timestamps = [ts["timestamp"] for ts in dataframe]
    coverage = [cov["coverage"] for cov in dataframe]
    crashes = [crash["crashes"] for crash in dataframe]
    dataframe = pd.DataFrame(
        {
            f"timestamp-{result_file.stem}": timestamps,
            f"coverage-{result_file.stem}": coverage,
            f"crashes-{result_file.stem}": crashes,
        }
    )
    return dataframe


def load_results(results_dir: pathlib.Path, base: str, alternative: str) -> pd.DataFrame:
    dataframe = pd.DataFrame()
    for result in results_dir.glob("*.json"):
        result_df = load_single_result(result)
        dataframe = pd.concat([dataframe, result_df], axis=1)

    return dataframe


def load_experiment_config(exp_config: pathlib.Path) -> tuple:
    with open(exp_config, "r", encoding="ascii") as conf_stream:
        try:
            config = yaml.safe_load(conf_stream)
        except yaml.YAMLError as exc:
            print(exc)
            exit(1)

    results_dir = pathlib.Path(config.get("results-dir", "experiment-results")).resolve()
    base_config = pathlib.Path(config.get("base-config", None)).stem
    alternative_config = pathlib.Path(config.get("alternative-config", None)).stem

    return (results_dir, base_config, alternative_config)


def do_stats(results: pd.DataFrame, base: str, alternative: str):
    pass


def plot_results(results: pd.DataFrame, base: str, alternative: str):
    sns.set_theme(style="darkgrid")

    IGNORE_FIRST_N = 10

    base_mean = results.loc[
        IGNORE_FIRST_N:, results.columns.str.contains(f"coverage-bb-coverage-.*-{base}")
    ].mean(axis=1)
    base_std = results.loc[
        IGNORE_FIRST_N:, results.columns.str.contains(f"coverage-bb-coverage-.*-{base}")
    ].std(axis=1)

    alt_mean = results.loc[
        IGNORE_FIRST_N:, results.columns.str.contains(f"coverage-bb-coverage-.*-{alternative}")
    ].mean(axis=1)
    alt_std = results.loc[
        IGNORE_FIRST_N:, results.columns.str.contains(f"coverage-bb-coverage-.*-{alternative}")
    ].std(axis=1)

    plt.figure(dpi=300)

    ax = sns.lineplot(
        data=pd.DataFrame({"no-laf": base_mean, "laf": alt_mean}),
    )
    ax.fill_between(
        results.index[IGNORE_FIRST_N:], base_mean - base_std, base_mean + base_std, alpha=0.2
    )
    ax.fill_between(
        results.index[IGNORE_FIRST_N:], alt_mean - alt_std, alt_mean + alt_std, alpha=0.2
    )

    # base_runs = [name for name in results.columns if base in name]
    # alt_runs = [name for name in results.columns if alternative in name]

    plt.figure()

    COV_ENTRY_N = 200

    sns.boxplot(
        data=pd.DataFrame(
            {
                "no-laf": results.loc[
                    COV_ENTRY_N, results.columns.str.contains(f"coverage-bb-coverage-.*-{base}")
                ],
                "laf": results.loc[
                    COV_ENTRY_N,
                    results.columns.str.contains(f"coverage-bb-coverage-.*-{alternative}"),
                ],
            }
        ),
    )

    plt.show()


def main():
    parser = ap.ArgumentParser()
    parser.add_argument(
        "exp_config",
        type=pathlib.Path,
        help="Path to the experiment configuration file",
    )
    args = parser.parse_args()

    results_dir, base_config, alternative_config = load_experiment_config(args.exp_config)
    results = load_results(results_dir, base_config, alternative_config)
    do_stats(results, base_config, alternative_config)
    plot_results(results, base_config, alternative_config)


if __name__ == "__main__":
    main()
