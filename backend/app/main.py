"""FastAPI entry point."""
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.db import init_db
from app.routers import analyze, upload
from app.schemas import ApiException, Envelope, fail, ok
from app.routers import analyze, baselines, findings, upload


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


app = FastAPI(title=settings.app_name, version=settings.tool_version, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(ApiException)
async def _api_exc(_req: Request, exc: ApiException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content=fail(exc.code, exc.message).model_dump())


@app.exception_handler(StarletteHTTPException)
async def _http_exc(_req: Request, exc: StarletteHTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content=fail("http_error", str(exc.detail)).model_dump())


@app.exception_handler(RequestValidationError)
async def _validation_exc(_req: Request, exc: RequestValidationError) -> JSONResponse:
    msg = "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors())
    return JSONResponse(status_code=422, content=fail("validation_error", msg).model_dump())


@app.exception_handler(Exception)
async def _unhandled(_req: Request, _exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=500, content=fail("internal_error", "Unexpected server error.").model_dump())


@app.get("/api/health", response_model=Envelope)
def health() -> Envelope:
    return ok({"status": "alive", "tool_version": settings.tool_version})


...
app.include_router(upload.router)
app.include_router(analyze.router)
app.include_router(findings.router)
app.include_router(baselines.router)