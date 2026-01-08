import os
import pytest
from unittest.mock import patch
from templatelib.template import Template
from templateapi.exceptions import MissingEnvironmentVariableError


@pytest.mark.parametrize(
    "value1, value2, expected",
    [(1, 1, 2), (2, 2, 4), (3, 2, 5), (4, 2, 6), (5, 7, 12)],
)
def test_sum(value1, value2, expected):
    template = Template()
    assert template.sum(value1, value2) == expected


def test_missing_environment_variable():
    """Test que verifica que se lanza excepción cuando falta una variable de entorno."""
    from templateapi import validate_required_env_vars
    
    # Mockeamos os.getenv para que retorne None para LOG_LEVEL
    with patch('templateapi.os.getenv') as mock_getenv:
        # Configuramos el mock para que retorne None solo para LOG_LEVEL
        def getenv_side_effect(key, default=None):
            if key == "LOG_LEVEL":
                return None
            # Para otras variables, retornamos un valor dummy
            return "dummy_value"
        
        mock_getenv.side_effect = getenv_side_effect
        
        # Verificamos que se lanza la excepción correcta
        with pytest.raises(MissingEnvironmentVariableError) as exc_info:
            validate_required_env_vars()
        
        # Verificamos que la variable faltante está en el listado
        assert "LOG_LEVEL" in exc_info.value.missing_vars
        assert "LOG_LEVEL" in str(exc_info.value)


def test_missing_multiple_environment_variables():
    """Test que verifica el manejo de múltiples variables faltantes."""
    from templateapi import validate_required_env_vars
    
    # Mockeamos os.getenv para que retorne None para varias variables
    with patch('templateapi.os.getenv') as mock_getenv:
        def getenv_side_effect(key, default=None):
            if key in ["LOG_LEVEL", "ENVIRONMENT", "LOG_DIR"]:
                return None
            return "dummy_value"
        
        mock_getenv.side_effect = getenv_side_effect
        
        with pytest.raises(MissingEnvironmentVariableError) as exc_info:
            validate_required_env_vars()
        
        # Verificamos que todas las variables faltantes están en el listado
        assert "LOG_LEVEL" in exc_info.value.missing_vars
        assert "ENVIRONMENT" in exc_info.value.missing_vars
        assert "LOG_DIR" in exc_info.value.missing_vars
        assert len(exc_info.value.missing_vars) == 3
