import os
from pathlib import Path
import sys
import pytest
from fastapi.testclient import TestClient
from jose import jwt
from datetime import timedelta
from unittest.mock import patch, MagicMock

# Asumiendo que el archivo principal se llama main.py
# Ajusta la siguiente línea con el nombre correcto de tu archivo
sys.path.insert(0, Path(__file__).resolve().parent.parent.as_posix())
from templateapi.api.demo_auth import (
    router,
    fake_users_db,
    create_access_token,
    get_password_hash,
    SECRET_KEY,
    ALGORITHM,
    verify_password,
)

client = TestClient(router)

# -------------------- TESTS UNITARIOS --------------------


def test_verify_password():
    """Test para la función de verificación de contraseña"""
    # Contraseña correcta
    assert (
        verify_password(
            "secret",
            "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        )
        == True
    )

    # Contraseña incorrecta
    assert (
        verify_password(
            "wrong_password",
            "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        )
        == False
    )


def test_get_password_hash():
    """Test para la función de generación de hash de contraseña"""
    hashed_password = get_password_hash("testpassword")
    # Verificar que el hash tenga el formato correcto de bcrypt
    assert hashed_password.startswith("$2b$")
    # Verificar que el hash funcione para la verificación
    assert verify_password("testpassword", hashed_password) == True


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
    response = client.post(
        "/login/token",
        data={"username": "johndoe", "password": "secret"},
    )
    assert response.status_code == 200
    token_data = response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"

    # Credenciales incorrectas - usuario inexistente
    response = client.post(
        "/login/token",
        data={"username": "nonexistent", "password": "secret"},
    )
    assert response.status_code == 401

    # Credenciales incorrectas - contraseña incorrecta
    response = client.post(
        "/login/token",
        data={"username": "johndoe", "password": "wrongpassword"},
    )
    assert response.status_code == 401


def test_login_json():
    """Test para el endpoint de login JSON"""
    # Credenciales correctas
    response = client.post(
        "/login",
        json={"username": "johndoe", "password": "secret"},
    )
    assert response.status_code == 200
    token_data = response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"

    # Credenciales incorrectas
    response = client.post(
        "/login",
        json={"username": "johndoe", "password": "wrongpassword"},
    )
    assert response.status_code == 401


def test_protected_endpoint_with_token():
    """Test para acceder a un endpoint protegido con token válido"""
    # Primero obtener un token
    response = client.post(
        "/login",
        json={"username": "johndoe", "password": "secret"},
    )
    token = response.json()["access_token"]

    # Usar el token para acceder al endpoint protegido
    response = client.get(
        "/protected-resource/", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Este es un recurso protegido"
    assert data["user"] == "johndoe"


def test_protected_endpoint_without_token():
    """Test para verificar que no se puede acceder sin token"""
    response = client.get("/protected-resource/")
    assert response.status_code == 401


def test_protected_endpoint_with_invalid_token():
    """Test para verificar que no se puede acceder con token inválido"""
    response = client.get(
        "/protected-resource/",
        headers={"Authorization": "Bearer invalidtoken"},
    )
    assert response.status_code == 401


def test_get_user_me():
    """Test para obtener información del usuario autenticado"""
    # Primero obtener un token
    response = client.post(
        "/login",
        json={"username": "johndoe", "password": "secret"},
    )
    token = response.json()["access_token"]

    # Usar el token para obtener información del usuario
    response = client.get(
        "/users/me/", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    user_data = response.json()
    assert user_data["username"] == "johndoe"
    assert user_data["full_name"] == "John Doe"
    assert user_data["email"] == "johndoe@example.com"
    assert user_data["disabled"] == False


# Si tienes endpoints admin ocultos, puedes probarlos también
def test_admin_endpoints():
    """Test para endpoints administrativos ocultos"""
    # Primero obtener un token
    response = client.post(
        "/login",
        json={"username": "johndoe", "password": "secret"},
    )
    token = response.json()["access_token"]

    # Probar el endpoint admin para listar usuarios
    response = client.get(
        "/admin/users", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    users = response.json()
    assert (
        len(users) >= 1
    )  # Al menos el usuario johndoe debe estar en la lista
    assert any(user["username"] == "johndoe" for user in users)

    # Probar el endpoint admin para resetear contraseña
    response = client.post(
        "/admin/reset-password/johndoe",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert "éxito" in response.json()["message"]


# Test para endpoint que requiere token pero usuario no tiene permiso (no es admin)
@patch("main.api.demo_auth.fake_users_db")
def test_admin_access_denied(mock_db):
    """Test para verificar que un usuario no admin no puede acceder a endpoints admin"""
    # Crear un usuario no admin en la base de datos mockeada
    mock_db.get.return_value = {
        "username": "regularuser",
        "full_name": "Regular User",
        "email": "regular@example.com",
        "hashed_password": get_password_hash("regular123"),
        "disabled": False,
    }

    # Mockear la función get_user para que devuelva el usuario regular
    with patch(
        "main.get_user",
        return_value=MagicMock(
            username="regularuser",
            full_name="Regular User",
            email="regular@example.com",
            disabled=False,
        ),
    ):
        # Crear un token válido para el usuario regular
        token = create_access_token(data={"sub": "regularuser"})

        # Intentar acceder a un endpoint admin
        response = client.get(
            "/admin/users", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403  # Forbidden

        # Intentar resetear una contraseña
        response = client.post(
            "/admin/reset-password/johndoe",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403  # Forbidden


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
