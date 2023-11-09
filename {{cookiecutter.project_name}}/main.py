from fastapi import Request, Response

from app import admin
from base.app import init_app
from base.exception import *


app = init_app(True)


app.mount("/api/admin", admin)


@app.get(
    "/storage/{path:path}",
    summary="获取文件",
)
async def storage(request: Request, path: str) -> Response:
    """
    获取文件
    """

    from base.models import StorageField

    content = StorageField.content_from_url(str(request.url))

    if content is None:
        raise HTTPException(
            detail="未知文件",
            status_code=HTTP_400_BAD_REQUEST,
        )

    return Response(content)
