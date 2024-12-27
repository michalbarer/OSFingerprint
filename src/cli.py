import logging
from typing import List

import click

from os_detect import run_tests, compare_results_to_db
from src.utils.port_scanner import port_scanner, logger

@click.command()
@click.option('--host', '-h', required=True, type=str, help='The target host (IP address).')
@click.option('--open-ports', '-op', required=False, type=List[int], help='List of open ports.')
@click.option('--closed-ports', '-cp', required=False, type=List, help='List of closed ports.')
@click.option('--start-port', '-sp', required=False, type=click.IntRange(0, 65535), help='Start of the port range.')
@click.option('--end-port', '-ep', required=False, type=click.IntRange(0, 65535), help='End of the port range.')
@click.option('--time-limit', '-l', default=30, type=int, help='Time limit for the port scan in seconds (default: 30).')
@click.option('--num-results', '-n', default=10, type=int, help='Number of top results to show (default: 10).')
@click.option('--verbose', '-v', is_flag=True, default=False, help='Enable verbose mode.')
def os_fingerprint(host, open_ports, closed_ports, start_port, end_port, time_limit, num_results, verbose):
    if verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.ERROR)

    port_range = range(start_port, end_port + 1)
    click.echo('Start scanning ports...')
    result = port_scanner(host, port_range, time_limit)
    open_ports, closed_ports = result
    click.echo('Done scanning ports...')

    if not open_ports and not closed_ports:
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
