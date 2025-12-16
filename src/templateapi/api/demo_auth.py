from fastapi import (
    Depends,
    HTTPException,
    status,
    APIRouter,
)
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    APIKeyHeader,
)
from fastapi.openapi.utils import get_openapi

from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional

# Configuración de seguridad
SECRET_KEY = "tu_clave_secreta_aqui_cambiame"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# Modelos para datos
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    enabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


class LoginRequest(BaseModel):
    username: str
    password: str


# Base de datos ficticia de usuarios
fake_users_db = {
    "juanperez": {
        "username": "juanperez",
        "full_name": "Juan Pérez",
        "email": "juanperez@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "secret"
        "enabled": True,
    }
}

# Configuración de esquemas de seguridad
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login/token", auto_error=False
)
api_key_scheme = APIKeyHeader(name="Authorization", auto_error=False)

# Utilidades para manejo de contraseñas y tokens
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


router = APIRouter()


# Funciones auxiliares
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    return token_data


async def get_current_user(
    oauth2_token: Optional[str] = Depends(oauth2_scheme),
    api_key: Optional[str] = Depends(api_key_scheme),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Verificar si tenemos token de OAuth2
    if oauth2_token:
        token_data = decode_token(oauth2_token)
        user = get_user(fake_users_db, username=token_data.username)
        if user is None:
            raise credentials_exception
        return user

    # Verificar si tenemos API key
    if api_key:
        # Comprobar si la API key tiene el formato "Bearer <token>"
        if api_key.startswith("Bearer "):
            token = api_key.replace("Bearer ", "")
            token_data = decode_token(token)
            user = get_user(fake_users_db, username=token_data.username)
            if user is None:
                raise credentials_exception
            return user

    # Si no hay token válido, lanzar excepción
    raise credentials_exception


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
):
    if not current_user.enabled:
        raise HTTPException(status_code=400, detail="Usuario inactivo")
    return current_user


# Endpoints
@router.post("/login/token", response_model=Token, include_in_schema=False)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    user = authenticate_user(
        fake_users_db, form_data.username, form_data.password
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/login", response_model=Token)
async def login_json(login_data: LoginRequest):
    user = authenticate_user(
        fake_users_db, login_data.username, login_data.password
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos",
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@router.get("/")
async def root():
    return {"message": "API con autenticación dual por token"}


@router.get("/protected-resource/")
async def protected_resource(
    current_user: User = Depends(get_current_active_user),
):
    return {
        "message": "Este es un recurso protegido",
        "user": current_user.username,
    }


# Configuración personalizada de Swagger OpenAPI
def custom_openapi():
    if router.openapi_schema:
        return router.openapi_schema

    openapi_schema = get_openapi(
        title="API con Autenticación Dual",
        version="1.0.0",
        description="Una API con dos métodos de autenticación: OAuth2 y Bearer Token directo",
        routes=router.routes,
    )

    # Definir los dos esquemas de seguridad
    openapi_schema["components"]["securitySchemes"] = {
        "OAuth2PasswordBearer": {
            "type": "oauth2",
            "flows": {"password": {"tokenUrl": "/login/token", "scopes": {}}},
        },
        "APIKeyHeader": {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "Ingresa el token con formato: **Bearer tu_token**",
        },
    }

    # Aplicar seguridad global
    openapi_schema["security"] = [
        {"OAuth2PasswordBearer": []},
        {"APIKeyHeader": []},
    ]

    router.openapi_schema = openapi_schema
    return router.openapi_schema


router.openapi = custom_openapi

# Para ejecutar: uvicorn nombre_archivo:app --reload
