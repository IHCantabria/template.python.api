"""Template"""

import os
import logging
import tomli
from dotenv import load_dotenv

# Versión del paquete
with open("pyproject.toml", "rb") as f:
    config = tomli.load(f)

version = config["project"]["version"]

__version__ = version


# Cargamos variables de entorno y verificamos su existencia
load_dotenv()

env_vars = ["ENVIRONMENT", "LOG_DIR"]
no_env_vars = []
for ev in env_vars:
    if os.getenv(ev) is None:
        logging.error("No se ha encontrado la variable de entorno %s", ev)
        no_env_vars.append(ev)
if len(no_env_vars):
    raise Exception(
        f"ERROR: No se ha encontrado la variable de entorno {','.join(no_env_vars)} "
    )
