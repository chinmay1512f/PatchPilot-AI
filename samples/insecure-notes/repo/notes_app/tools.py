"""Helper utilities exposed in the notes UI."""

import subprocess

import yaml


def grep_notes(term: str) -> str:
    # BUG (fixture): shell command built from user input
    return subprocess.run(f"grep -i {term} notes.txt", shell=True, capture_output=True, text=True).stdout


def calculate(expression: str) -> float:
    # BUG (fixture): eval on user input
    return eval(expression)


def load_settings(text: str) -> dict:
    # BUG (fixture): unsafe YAML loader
    return yaml.load(text, Loader=yaml.Loader)
