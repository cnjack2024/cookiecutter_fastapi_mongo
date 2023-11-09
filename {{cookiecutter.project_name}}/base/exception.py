from starlette.authentication import AuthenticationError
from starlette.exceptions import HTTPException
from starlette.status import *


HTTP_461_TOKEN_EXPIRED = 461


class AuthenticationError(AuthenticationError):
    def __init__(self, msg: str = "认证失败"):
        self.msg = msg
        self.status_code = HTTP_401_UNAUTHORIZED


class AuthenticationForbidden(AuthenticationError):
    def __init__(self, msg: str = "禁止访问"):
        self.msg = msg
        self.status_code = HTTP_403_FORBIDDEN


class AuthenticationExpired(AuthenticationError):
    def __init__(self, msg: str = "认证过期"):
        self.msg = msg
        self.status_code = HTTP_461_TOKEN_EXPIRED
