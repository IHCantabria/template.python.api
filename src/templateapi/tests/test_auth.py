import os
from pathlib import Path
import sys
import pytest
from fastapi.testclient import TestClient
from jose import jwt
from datetime import timedelta


# Asumiendo que el archivo principal se llama main.py
# Ajusta la siguiente línea con el nombre correcto de tu archivo
sys.path.insert(0, Path(__file__).resolve().parent.parent.as_posix())
from templateapi.api.demo_auth import (
    fake_users_db,
    create_access_token,
    get_password_hash,
    SECRET_KEY,
    ALGORITHM,
    verify_password,
)
from templateapi.main import app

client = TestClient(app, raise_server_exceptions=False)

# -------------------- TESTS UNITARIOS --------------------


def test_verify_password():
    """Test para la función de verificación de contraseña"""
    # Hash conocido para la contraseña "secret"
    known_hash = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"

    # Contraseña correcta
    assert verify_password("secret", known_hash)

    # Contraseña incorrecta
    assert not verify_password("wrong_password", known_hash)


def test_get_password_hash():
    """Test para la función de generación de hash de contraseña"""
    hashed_password = get_password_hash("testpassword")
    # Verificar que el hash tenga el formato correcto de bcrypt
    assert hashed_password.startswith("$2b$")
    # Verificar que el hash funcione para la verificación
    assert verify_password("testpassword", hashed_password)


def test_create_access_token():
    """Test para la función de creación de token de acceso"""
    # Crear token sin expiración específica
    token = create_access_token(data={"sub": "testuser"})
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert payload["sub"] == "testuser"
    assert "exp" in payload

    # Crear token con expiración específica
    delta = timedelta(minutes=30)
    token = create_access_token(data={"sub": "testuser"}, expires_delta=delta)
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert payload["sub"] == "testuser"
    assert "exp" in payload


# -------------------- TESTS DE INTEGRACIÓN --------------------


def test_login_for_access_token():
    """Test para el endpoint de login OAuth2"""
    # Credenciales correctas
    password = os.getenv("TEST_PASSWORD")
    response = client.post(
        "/auth/login/token",
        data={"username": "juanperez", "password": password},
    )
    assert response.status_code == 200
    token_data = response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"

    # Credenciales incorrectas - usuario inexistente
    response = client.post(
        "/auth/login/token",
        data={"username": "nonexistent", "password": password},
    )
    assert response.status_code == 401

    # Credenciales incorrectas - contraseña incorrecta
    response = client.post(
        "/auth/login/token",
        data={"username": "juanperez", "password": "wrongpassword"},
    )
    assert response.status_code == 401


def test_login_json():
    """Test para el endpoint de login JSON"""
    # Obtener contraseña de test desde variable de entorno o usar valor por defecto
    password = os.getenv("TEST_PASSWORD", "secret")

    # Credenciales correctas
    response = client.post(
        "/auth/login",
        json={"username": "juanperez", "password": password},
    )
    assert response.status_code == 200
    token_data = response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"

    # Credenciales incorrectas
    response = client.post(
        "/auth/login",
        json={"username": "juanperez", "password": "wrongpassword"},
    )
    assert response.status_code == 401


def test_protected_endpoint_with_token():
    """Test para acceder a un endpoint protegido con token válido"""
    # Primero obtener un token
    password = os.getenv("TEST_PASSWORD", "secret")
    response = client.post(
        "/auth/login",
        json={"username": "juanperez", "password": password},
    )
    token = response.json()["access_token"]

    # Usar el token para acceder al endpoint protegido
    response = client.get(
        "/auth/protected-resource/",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Este es un recurso protegido"
    assert data["user"] == "juanperez"


def test_protected_endpoint_without_token():
    """Test para verificar que no se puede acceder sin token"""
    response = client.get("/auth/protected-resource/")
    assert response.status_code == 401


def test_protected_endpoint_with_invalid_token():
    """Test para verificar que no se puede acceder con token inválido"""
    response = client.get(
        "/auth/protected-resource/",
        headers={"Authorization": "Bearer invalidtoken"},
    )
    assert response.status_code == 401


def test_get_user_me():
    """Test para obtener información del usuario autenticado"""
    # Primero obtener un token
    password = os.getenv("TEST_PASSWORD", "secret")
    response = client.post(
        "/auth/login",
        json={"username": "juanperez", "password": password},
    )
    token = response.json()["access_token"]

    # Usar el token para obtener información del usuario
    response = client.get(
        "/auth/users/me/", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    user_data = response.json()
    assert user_data["username"] == "juanperez"
    assert user_data["full_name"] == "Juan Pérez"
    assert user_data["email"] == "juanperez@example.com"
    assert user_data["enabled"]


# -------------------- CONFIGURACIÓN DEL TEST --------------------


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Configuración para pruebas que necesitan una base de datos de prueba"""
    # Aquí puedes configurar una base de datos de prueba si es necesario
    # Para este ejemplo usamos la base de datos fake en memoria

    # Configuración antes de las pruebas
    original_db = fake_users_db.copy()

    yield  # Esto es donde se ejecutarán las pruebas

    # Limpieza después de las pruebas
    fake_users_db.clear()
    fake_users_db.update(original_db)


# -------------------- FIN DE LOS TESTS --------------------
