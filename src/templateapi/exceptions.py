"""Excepciones personalizadas para la aplicación."""


class ConfigurationError(Exception):
    """Error en la configuración de la aplicación.

    Se lanza cuando falta una variable de entorno requerida
    o cuando hay un error en la configuración inicial.
    """

    pass


class MissingEnvironmentVariableError(ConfigurationError):
    """Error cuando faltan variables de entorno requeridas.

    Args:
        missing_vars: Lista de nombres de variables de entorno faltantes
    """

    def __init__(self, missing_vars: list[str]):
        self.missing_vars = missing_vars
        super().__init__(
            f"Variables de entorno faltantes: {', '.join(missing_vars)}"
        )
