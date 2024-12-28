import traceback
from itertools import cycle
from shutil import get_terminal_size
from threading import Thread
from time import sleep, time
import click
import emoji


class LoaderAnimation:
    def __init__(self, desc="Loading...", end="Done!", timeout=0.1,
                 s_color="cyan", e_color="white", elapsed_time=False,
                 error="An error occurred", e_color_error="red", show_stacktrace=False, to_exit=False):
        """
        A loader-like context manager with Click's secho for styled output.

        Args:
            desc (str, optional): The loader's description. Defaults to "Loading...".
            end (str, optional): Final print. Defaults to "Done!".
            timeout (float, optional): Sleep time between prints. Defaults to 0.1.
            s_color (str, optional): Start color. Defaults to "cyan".
            e_color (str, optional): End color. Defaults to "white".
            elapsed_time (bool, optional): Add elapsed time to the end message. Defaults to False.
            error (str, optional): Error message. Defaults to "An error occurred".
            e_color_error (str, optional): Error color. Defaults to "red".
            show_stacktrace (bool, optional): Show stacktrace on error. Defaults to False.
            to_exit (bool, optional): Should exit on error. Defaults to False.
        """
        self.desc = desc
        self.end = end
        self.timeout = timeout
        self.start_color = s_color
        self.end_color = e_color
        self.add_elapsed_time = elapsed_time
        self.error = error
        self.e_color_error = e_color_error
        self.exit = to_exit
        self.show_stacktrace = show_stacktrace

        self._thread = Thread(target=self._animate, daemon=True)
        self.steps = ["⢿", "⣻", "⣽", "⣾", "⣷", "⣯", "⣟", "⡿"]
        self.done = False
        self.start_time = None
        self.end_time = None

    def start(self):
        self.start_time = time()
        self._thread.start()
        return self

    def _animate(self):
        for c in cycle(self.steps):
            if self.done:
                break

            cols = get_terminal_size((80, 20)).columns
            print("\r" + " " * cols, end="", flush=True)
            click.secho(f"\r{self.desc} {c}", nl=False, fg=self.start_color)
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
        done_mark = emoji.emojize(":check_mark:")
        click.secho(f"\r{done_mark} {self.end} {elapsed_time_str}", fg=self.end_color, bold=True)


    def handle_error(self, error_stack: str):
        error_mark = emoji.emojize(":red_exclamation_mark:")
        if self.show_stacktrace:
            error_stack = f"\n{error_stack}"
        else:
            error_stack = ""
        click.secho(f"\r{error_mark} {self.error}{error_stack}", fg=self.e_color_error, bold=True)

    def __exit__(self, exc_type, exc_value, tb):
            if exc_type is not None:
                self.handle_error("".join(traceback.format_exception(exc_type, exc_value, tb)))
                if self.exit:
                    raise click.Abort()
                return True
            self.stop()
