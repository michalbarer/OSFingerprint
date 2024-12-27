import logging
import time
from typing import List

import click

from src.os_detect import run_tests, compare_results_to_db
from src.utils.port_scanner import port_scanner

Logger = logging.getLogger(__name__)

@click.command()
@click.option('--host', '-h', required=True, type=click.STRING, help='The target host (IP address).')
@click.option('--open-ports', '-op', required=False, type=click.INT, multiple=True, help='List of open ports.')
@click.option('--closed-ports', '-cp', required=False, type=click.INT, multiple=True, help='List of closed ports.')
@click.option('--num-results', '-n', default=10, type=click.INT, help='Number of top results to show (default: 10).')
@click.option('--verbose', '-v', is_flag=True, default=False, help='Enable verbose mode.')
def os_fingerprint(host, open_ports, closed_ports, num_results, verbose):
    open_ports = list(open_ports)
    closed_ports = list(closed_ports)
    run_osfp(host, open_ports, closed_ports, num_results, verbose)


def run_osfp(host: str, open_ports: List[int], closed_ports: List[int], num_results: int = 10, verbose: bool = False):
    if verbose:
        Logger.setLevel(logging.INFO)
    else:
        Logger.setLevel(logging.ERROR)

    port_scan_start_time = time.time()
    click.echo('Start scanning ports...')
    result = port_scanner(host, open_ports, closed_ports)
    elapsed_time = time.time() - port_scan_start_time
    click.echo(f'Done scanning ports in {elapsed_time:.2f} seconds...')

    validated_open_ports, validated_closed_ports = result
    if verbose:
        click.echo(f'Open ports: {validated_open_ports}')
        click.echo(f'Closed ports: {validated_closed_ports}')

    click.echo('Done scanning ports...')

    if not validated_open_ports and not validated_closed_ports:
        click.secho("No ports found.", fg='red')
        raise click.Abort()

    click.echo('Start running probes and tests...')
    test_results = run_tests(host, open_ports, closed_ports)
    click.echo('Done running probes and tests...')

    if test_results:
        # if verbose:
        #     click.echo('Results:')
        #     click.echo(results)
        click.echo('Start comparing results to database...')
        os_scores = compare_results_to_db(test_results, num_results)
        click.echo('Done comparing results to database...')
        click.secho(f"Top {num_results} matching Operating Systems:")
        for os, score in os_scores:
            click.secho(f"{os}: {score}")

if __name__ == '__main__':
    run_osfp(
        host='scanme.nmap.org', open_ports=[22, 80], closed_ports=[21, 8000, 8080], num_results=10, verbose=False
    )