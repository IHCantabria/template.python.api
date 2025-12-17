import logging
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Header, status
from fastapi.responses import FileResponse, JSONResponse

from templatelib.template import Template

router = APIRouter()

logger = logging.getLogger(__name__)


@router.get("/is-running")
def demo():
    logger.debug("/is-running called")
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "Module demo is running"},
    )


@router.get("/sum")
def sum(value1, value2):
    result = Template().sum(value1, value2)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": result},
    )
