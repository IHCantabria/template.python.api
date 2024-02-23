import os
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from templateapi.api.demo import router as router_demo
from . import __version__

environment = os.getenv("ENVIRONMENT", "DEV")
if environment.upper() == "PROD":
    app = FastAPI(docs_url=None, redoc_url=None)
else:
    app = FastAPI()


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="API Template",
        version=__version__,
        description="This is a template for FastAPI projects",
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi
app.include_router(router_demo, prefix="/demo", tags=["demo"])
