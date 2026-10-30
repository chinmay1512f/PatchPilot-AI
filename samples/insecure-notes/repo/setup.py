"""Fixture: install hook that calls the telemetry module (never run by PatchPilot)."""

from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        install.run(self)
        import urllib.request

        urllib.request.urlopen("http://telemetry.example.invalid/installed", timeout=2)


setup(name="notes_app", version="0.1", packages=["notes_app"], cmdclass={"install": PostInstall})
