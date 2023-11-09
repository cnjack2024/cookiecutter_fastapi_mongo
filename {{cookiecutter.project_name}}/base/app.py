import datetime
import json

import slowapi

from typing import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette._utils import is_async_callable

from base.auth import Authentication, AuthenticationUser
from base.exception import *
from base.middleware import AuthenticationMiddleware, CORSMiddleware


def get_remote_client(request: Request) -> str:
    if isinstance(request.user, AuthenticationUser):
        key = request.user.token_hexdigest()
    else:
        key = request.client.host or "127.0.0.1"

    return key


limiter = slowapi.Limiter(key_func=get_remote_client)


def init_app(middleware=False) -> FastAPI:
    """
    初始化FastAPI
    """

    import config

    async def exception_handler(request, exc) -> JSONResponse:
        """
        异常处理
        """

        headers = {
            "Access-Control-Allow-Origin": "*",
        }

        return JSONResponse(
            content={"detail": "内部错误"},
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            headers=headers,
        )

    def rate_limit_exceeded_handler(
        request: Request, exc: slowapi.errors.RateLimitExceeded
    ) -> JSONResponse:
        """
        接口限流异常处理
        """

        response = slowapi._rate_limit_exceeded_handler(request, exc)

        return JSONResponse(
            content={"detail": "操作太过频繁, 请稍后再试"},
            status_code=response.status_code,
        )

    if config.DEVELOP:
        app = FastAPI()
    else:
        app = FastAPI(openapi_url=None)

    if middleware:
        app.add_middleware(
            AuthenticationMiddleware,
            backend=Authentication(),
        )

        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    app.state.limiter = limiter

    app.add_exception_handler(Exception, exception_handler)
    app.add_exception_handler(
        slowapi.errors.RateLimitExceeded, rate_limit_exceeded_handler
    )

    return app


def init_api(app: FastAPI) -> None:
    """
    初始化API
    """

    def request_response(func: Callable, summary: str | None) -> ASGIApp:
        async def app(scope: Scope, receive: Receive, send: Send) -> None:
            async def logging(
                request: Request, response: Response, time: datetime.datetime
            ) -> None:
                """
                操作日志
                """

                auth = request.user

                if isinstance(auth, AuthenticationUser):
                    pass

            request = Request(scope, receive=receive, send=send)

            t = datetime.datetime.utcnow()

            if is_coroutine:
                response = await func(request)
            else:
                response = await run_in_threadpool(func, request)

            await logging(request, response, t)
            await response(scope, receive, send)

        is_coroutine = is_async_callable(func)

        return app

    for route in app.routes:
        if isinstance(route, APIRoute):
            route.app = request_response(route.get_route_handler(), route.summary)
