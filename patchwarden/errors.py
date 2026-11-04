"""One error shape for every endpoint: {"error": "<code>", "message": "<plain language>"}.

Handlers never echo request input back (it may hold a password) and never
send a stack trace to the client.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = logging.getLogger(__name__)


class AppError(Exception):
    def __init__(self, status_code: int, code: str, message: str, headers: dict[str, str] | None = None):
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.headers = headers


def error_body(code: str, message: str) -> dict[str, str]:
    return {"error": code, "message": message}


_HTTP_DEFAULTS = {
    400: ("bad_request", "The request could not be understood."),
    401: ("unauthorized", "Please log in first."),
    403: ("forbidden", "You do not have access to this."),
    404: ("not_found", "We could not find that."),
    405: ("method_not_allowed", "That action is not allowed here."),
    413: ("too_large", "That upload is too large."),
    429: ("too_many_requests", "Too many requests. Please wait and try again."),
}


_INTERNAL = error_body("internal_error", "Something went wrong on our side. Please try again.")


class CatchAllMiddleware:
    """Turns any unhandled exception into the JSON error shape.

    Starlette's own Exception handler re-raises so the server logs the full
    traceback, and exception text can carry request input. Catching here
    means only the exception type and route are ever logged.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception as exc:  # noqa: BLE001 - this is the last line of defence
            log.error("Unhandled %s on %s %s", type(exc).__name__, scope.get("method"), scope.get("path"))
            if not started:
                await JSONResponse(_INTERNAL, status_code=500)(scope, receive, send)


def install_error_handlers(app: FastAPI) -> None:
    app.add_middleware(CatchAllMiddleware)

    @app.exception_handler(AppError)
    async def _app_error(_request: Request, exc: AppError):
        return JSONResponse(error_body(exc.code, exc.message), status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_request: Request, exc: StarletteHTTPException):
        code, message = _HTTP_DEFAULTS.get(exc.status_code, ("error", "Something went wrong."))
        return JSONResponse(error_body(code, message), status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_request: Request, exc: RequestValidationError):
        # Name the fields, never their values.
        fields = sorted({str(err["loc"][-1]) for err in exc.errors() if err.get("loc")})
        message = "Some fields are missing or invalid"
        message += f": {', '.join(fields)}." if fields else "."
        return JSONResponse(error_body("invalid_request", message), status_code=422)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        # Log the exception type and route only: exception text can carry input.
        log.error("Unhandled %s on %s %s", type(exc).__name__, request.method, request.url.path)
        return JSONResponse(_INTERNAL, status_code=500)
