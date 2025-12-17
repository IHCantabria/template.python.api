"""Template"""

import os

import tomli
from dotenv import load_dotenv
import logging.config  # Importa explícitamente logging.config
from opentelemetry._logs import set_logger_provider, get_logger_provider
from opentelemetry.exporter.otlp.proto.http._log_exporter import (
    OTLPLogExporter,
)
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource

# Cargamos variables de entorno PRIMERO
load_dotenv()

# Versión del paquete
with open("pyproject.toml", "rb") as f:
    config = tomli.load(f)

version = config["project"]["version"]

__version__ = version


# Configuración de logging con OpenTelemetry

try:
    # Verificar si ya existe un LoggerProvider configurado
    existing_provider = get_logger_provider()
    if isinstance(existing_provider, LoggerProvider):
        logger_provider = existing_provider
    else:
        # Establecer el nivel de log
        # La biblioteca tiene un bug que ignora la variable OTEL_LOG_LEVEL
        # por lo que tenemos que añadirlo de manera manual con estas líneas
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        log_level_numeric = getattr(logging, log_level, logging.INFO)
        logging.basicConfig(level=log_level_numeric)

        # Creamos el objeto provider y opcionalmente le podemos añadir un UUID
        # para filtrar en SEQ con @Resource.service.instance.id="codigo-uuid"
        logger_provider = LoggerProvider(
            resource=Resource.create(
                {
                    "service.instance.id": "template.python.api",
                }
            ),
        )
        set_logger_provider(logger_provider)

        # Creamos el exportador para enviar los logs al servidor
        # Las variables de entorno OTEL_EXPORTER_OTLP_* se leen automáticamente
        exporter = OTLPLogExporter(
            endpoint=os.getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"),
            headers={
                "X-Seq-ApiKey": os.getenv(
                    "OTEL_EXPORTER_OTLP_HEADERS", ""
                ).replace("X-Seq-ApiKey=", "")
            },
        )
        logger_provider.add_log_record_processor(
            BatchLogRecordProcessor(exporter)
        )

        # Añadimos el hander al logger
        handler = LoggingHandler(logger_provider=logger_provider)
        logging.getLogger("urllib3.connectionpool").setLevel(logging.INFO)
        logging.getLogger("numba.core").setLevel(logging.INFO)
        logging.getLogger().addHandler(handler)


except Exception as e:
    logging.basicConfig(level=logging.DEBUG)
    logging.error(
        "No se ha arrancado bien la configuración de open telemetry: %s", e
    )
    if "logger_provider" in locals():
        logger_provider.shutdown()


# Verificamos la existencia de variables de entorno requeridas
logging.debug("Cargando variables de entorno")
env_vars = [
    "ENVIRONMENT",
    "LOG_DIR",
    "OTEL_SERVICE_NAME",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
    "LOG_LEVEL",
]
no_env_vars = []
for ev in env_vars:
    if os.getenv(ev) is None:
        logging.error("No se ha encontrado la variable de entorno %s", ev)
        no_env_vars.append(ev)
if len(no_env_vars):
    raise Exception(
        f"ERROR: No se ha encontrado la variable de entorno {','.join(no_env_vars)} "
    )
