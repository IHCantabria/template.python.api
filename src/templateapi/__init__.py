"""Template"""

import toml

with open("pyproject.toml") as f:
    config = toml.load(f)

version = config["project"]["version"]

__version__ = version

from dotenv import load_dotenv

load_dotenv()
