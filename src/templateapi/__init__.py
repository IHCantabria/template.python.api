"""Template"""

import logging
import os

import tomli
from dotenv import load_dotenv
from opentelemetry._logs import set_logger_provider, get_logger_provider
from opentelemetry.exporter.otlp.proto.http._log_exporter import (
    OTLPLogExporter,
)
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource

# Cargamos variables de entorno PRIMERO (sin mensajes verbose)
load_dotenv(verbose=False)

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
        # Establecer el nivel de log desde la variable de entorno
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        log_level_numeric = getattr(logging, log_level, logging.INFO)

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

        # Configurar el handler de OpenTelemetry con el nivel correcto
        handler = LoggingHandler(
            level=log_level_numeric, logger_provider=logger_provider
        )

        # Configurar logging con el handler de OpenTelemetry
        logging.basicConfig(
            level=log_level_numeric,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.StreamHandler(),  # Para consola
                handler,  # Para OpenTelemetry/SEQ
            ],
        )

        # Silenciar logs verbosos de librerías de terceros
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("passlib").setLevel(logging.INFO)


except Exception as e:
    logging.basicConfig(level=logging.DEBUG)
    logging.error(
        "No se ha arrancado bien la configuración de open telemetry: %s", e
    )
    if "logger_provider" in locals():
        logger_provider.shutdown()


# Verificamos la existencia de variables de entorno requeridas
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
