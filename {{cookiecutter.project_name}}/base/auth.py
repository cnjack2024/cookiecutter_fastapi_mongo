import hashlib

from pathlib import Path
from typing import Any

from fastapi import Request
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    BaseUser,
)

from base.exception import *
from base.redis import Redis
from base.util import decode_token


class Authentication(AuthenticationBackend):
    """
    用户认证
    """

    async def authenticate(self, request: Request) -> AuthCredentials | None:
        if Path(request.scope.get("path")).name in (
            "docs",
            "openapi.json",
            "login",
            "smscode",
        ):
            return None

        if "/login/" in request.scope.get("path"):
            return None

        token = await self.authenticate_token(request)

        if not token:
            return None

        try:
            id, scope, data = decode_token(token)
        except HTTPException as exc:
            if exc.status_code == HTTP_461_TOKEN_EXPIRED:
                raise AuthenticationExpired()
            else:
                raise AuthenticationError()

        with Redis() as conn:
            sha = hashlib.sha256(token.encode()).hexdigest()

            if not conn.get(sha):
                raise AuthenticationExpired()

        auth = AuthenticationUser(request, id, scope, data, token)

        if not auth.get_user():
            raise AuthenticationError()

        return AuthCredentials([scope]), auth

    async def authenticate_token(self, request: Request) -> str | None:
        token = request.headers.get("token")

        return token


class AuthenticationUser(BaseUser):
    """
    认证用户
    """

    def __init__(
        self, request: Request, id: int | str, scope: str, data: dict, token: str
    ):
        self.request = request
        self.id = str(id)
        self.scope = scope
        self.data = data
        self.token = token
        self.user = None

    @property
    def is_authenticated(self) -> bool:
        if self.user:
            return True
        else:
            return False

    @property
    def display_name(self) -> str:
        return ":".join((self.id, self.scope))

    def get_user(self) -> Any:
        from models import AdminUser

        if self.user:
            return self.user

        if self.scope in ("admin",):
            self.user = AdminUser.objects(id=self.id).first()
        else:
            pass

        return self.user

    def token_hexdigest(self) -> str:
        return hashlib.sha256(self.token.encode()).hexdigest()

    def enforce(self) -> bool:
        """
        权限检查
        """

        from models import PermissionRule

        if self.is_authenticated:
            subs = []

            if self.scope in ("admin",):
                if self.user.super_admin:
                    subs.append("admin")
                else:
                    for role in self.user.get_current_roles():
                        subs.append(f"{self.scope}:{role}")

            enforcer = PermissionRule.enforcer()

            return PermissionRule.enforce(
                enforcer, subs, self.request.get("path"), self.request.get("method")
            )

        return False


def authentication(
    auth: AuthenticationUser, scope: str, permission: bool = False
) -> Any:
    """
    用户认证
    """

    if not auth.is_authenticated:
        raise HTTPException(
            detail="未认证用户",
            status_code=HTTP_401_UNAUTHORIZED,
        )

    if scope:
        if auth.scope != scope:
            raise HTTPException(
                detail="认证失败",
                status_code=HTTP_401_UNAUTHORIZED,
            )

    if permission:
        if not auth.enforce():
            raise HTTPException(
                detail="禁止访问",
                status_code=HTTP_403_FORBIDDEN,
            )

    with Redis() as conn:
        conn.set(auth.token_hexdigest(), auth.id, 30 * 60)

    return auth.user
