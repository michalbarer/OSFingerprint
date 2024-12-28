import logging
import time
from random import randint
from typing import List, Optional

import click
import pandas as pd
from more_itertools import take
from tabulate import tabulate

from src.os_detect import run_tests, compare_results_to_db
from src.utils.port_scanner import port_scanner

Logger = logging.getLogger(__name__)

@click.command()
@click.option('--host', '-h', required=True, type=click.STRING, help='The target host (IP address).')
@click.option('--open-ports', '-op', required=False, type=click.INT, multiple=True, help='List of open ports.')
@click.option('--closed-ports', '-cp', required=False, type=click.INT, multiple=True, help='List of closed ports.')
@click.option('--skip-common-ports', '-s', is_flag=True, default=False, help='Skip common ports scan if open and closed ports are provided.')
@click.option('--limit-open-ports', '-lop', default=3, type=click.INT, help='Limit of open ports to scan (default: 3).')
@click.option('--num-results', '-n', default=10, type=click.INT, help='Number of top results to show (default: 10).')
@click.option('--verbose', '-v', is_flag=True, default=False, help='Enable verbose mode.')
def os_fingerprint(host, open_ports, closed_ports, skip_common_ports ,limit_open_ports, num_results, verbose):
    open_ports = list(open_ports)
    closed_ports = list(closed_ports)
    run_osfp(host, open_ports, closed_ports, skip_common_ports ,limit_open_ports, num_results, verbose)


def run_osfp(host: str, open_ports: Optional[List[int]] = None, closed_ports: Optional[List[int]] = None,
             skip_common_ports=False, limit_open_ports: int = 3, num_results: int = 10, verbose: bool = False):
    if verbose:
        Logger.setLevel(logging.INFO)
    else:
        Logger.setLevel(logging.ERROR)

    port_scan_start_time = time.time()
    click.echo('Start scanning ports...')
    result = port_scanner(host, open_ports, closed_ports, skip_common_ports)
    elapsed_time = time.time() - port_scan_start_time
    click.echo(f'Done scanning ports in {elapsed_time:.2f} seconds...')

    validated_open_ports, validated_closed_ports = result
    if verbose:
        click.echo(f'Open ports: {validated_open_ports}')
        click.echo(f'Closed ports: {validated_closed_ports}')

    if not validated_open_ports and not validated_closed_ports:
        click.secho("No ports found.", fg='red')
        raise click.Abort()

    closed_port = validated_closed_ports[0] if validated_closed_ports else randint(1024, 65535)
    open_ports = take(limit_open_ports, validated_open_ports)

    os_scores = []
    for open_port in open_ports:
        click.echo(f'Running tests for open port {open_port} and closed port {closed_port}...')
        test_results = run_tests(host, open_port, closed_port)

        if test_results:
            if verbose:
                click.echo(f'Test results for open port {open_port}:')
                print_nested_dict(test_results)
            os_scores.append(compare_results_to_db(test_results, 2*num_results))

    os_scores = _combine_scores(os_scores, num_results)
    click.echo(tabulate(os_scores, headers='keys', tablefmt='grid'))


def print_nested_dict(nested_dict: dict):
    for section, tests in nested_dict.items():
        click.secho(f"\n{section}:", fg="cyan", bold=True)  # Section header
        for key, value in tests.items():
            click.secho(f"  {key}: ", fg="blue", nl=False)
            click.secho(f"{value}", fg="green")
    click.echo("\n")


def _combine_scores(scores_data: List[dict], top: int = 10) -> pd.DataFrame:
    """
    Combines scores from multiple dictionaries into a single DataFrame.
    Calculates the average score for each OS and returns the top `N` entries sorted by score.

    Args:
        scores_data (List[dict]): A list of dictionaries where keys are OS names and values are scores.
        top (int): Number of top entries to return. Defaults to 10.

    Returns:
        pd.DataFrame: DataFrame containing the top `N` operating systems and their average scores.
    """
    records = []
    for sublist in scores_data:
        for os, score in sublist.items():
            records.append({'os': os, 'score': score})

    df = pd.DataFrame(records)

    average_scores = (
        df.groupby('os', as_index=False)['score']
        .mean()
        .sort_values(by='score', ascending=False)
    )
    top_scores = average_scores.head(top)

    return top_scores.to_dict(orient='records')


if __name__ == '__main__':
    # run_osfp(
    #     host='scanme.nmap.org', open_ports=[22, 80], closed_ports=[21, 8000, 8080], skip_common_ports=True, num_results=10, verbose=True
    # )
    # run_osfp(
    #     host='10.100.102.38', open_ports=[4200], closed_ports=[21, 8000, 8080], skip_common_ports=False,
    #     num_results=10, verbose=True
    # )
    run_osfp(
        host='ynet.co.il', skip_common_ports=False,
        num_results=10, verbose=True
    )