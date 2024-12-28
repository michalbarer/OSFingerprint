from itertools import cycle
from shutil import get_terminal_size
from threading import Thread
from time import sleep, time
import click


class LoaderAnimation:
    def __init__(self, desc="Loading...", end="Done!", timeout=0.1, color="cyan", elapsed_time=False):
        """
        A loader-like context manager with Click's secho for styled output.

        Args:
            desc (str, optional): The loader's description. Defaults to "Loading...".
            end (str, optional): Final print. Defaults to "Done!".
            timeout (float, optional): Sleep time between prints. Defaults to 0.1.
            color (str, optional): Color for the description text. Defaults to "cyan".
        """
        self.desc = desc
        self.end = end
        self.timeout = timeout
        self.color = color
        self.add_elapsed_time = elapsed_time

        self._thread = Thread(target=self._animate, daemon=True)
        self.steps = ["⢿", "⣻", "⣽", "⣾", "⣷", "⣯", "⣟", "⡿"]
        self.done = False
        self.start_time = None
        self.end_time = None

    def start(self):
        self.start_time = time()  # Record start time
        self._thread.start()
        return self

    def _animate(self):
        for c in cycle(self.steps):
            if self.done:
                break
            # Using click.secho for styled text
            cols = get_terminal_size((80, 20)).columns
            print("\r" + " " * cols, end="", flush=True)  # Clear the line
            click.secho(f"\r{self.desc} {c}", nl=False, fg=self.color)
            sleep(self.timeout)

    def __enter__(self):
        self.start()

    def stop(self):
        self.done = True
        self.end_time = time()
        elapsed = self.end_time - self.start_time
        cols = get_terminal_size((80, 20)).columns
        print("\r" + " " * cols, end="", flush=True)

        elapsed_time_str = ""
        if self.add_elapsed_time:
            elapsed_time_str = f" (Elapsed time: {elapsed:.2f} seconds)"
        click.secho(f"\r{self.end} {elapsed_time_str}", fg=self.color, bold=True)

    def __exit__(self, exc_type, exc_value, tb):
        self.stop()
