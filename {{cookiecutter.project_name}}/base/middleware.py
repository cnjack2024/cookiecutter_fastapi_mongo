from fastapi.middleware.cors import CORSMiddleware
from fastapi.requests import HTTPConnection
from fastapi.responses import JSONResponse, Response
from starlette.middleware import authentication


class AuthenticationMiddleware(authentication.AuthenticationMiddleware):
    """
    用户认证
    """

    @staticmethod
    def default_on_error(conn: HTTPConnection, exc: Exception) -> Response:
        return JSONResponse(
            content={"detail": exc.msg},
            status_code=exc.status_code,
        )
