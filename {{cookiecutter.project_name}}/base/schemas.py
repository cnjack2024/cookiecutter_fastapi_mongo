import datetime
import decimal

import mongoengine
import pydantic

from pathlib import Path
from typing import Annotated, Any, List, Self

from base.util import localtime


DateTimeType = Annotated[
    datetime.datetime,
    pydantic.BeforeValidator(lambda v: localtime(v).datetime if v else None),
]

TimeType = Annotated[
    datetime.time,
    pydantic.BeforeValidator(lambda v: localtime(v).datetime.timetz() if v else None),
]


class BaseModel(pydantic.BaseModel):
    """
    模型
    """

    model_config = pydantic.ConfigDict(
        json_encoders={
            datetime.datetime: (lambda dt: dt.strftime("%Y-%m-%d %H:%M:%S")),
            datetime.time: (lambda t: t.strftime("%H:%M:%S")),
        }
    )

    def dict(self, exclude_none: bool = False) -> dict:
        """
        转换为dict
        """

        data = {}

        for k, v in self.model_dump(exclude_none=exclude_none).items():
            if isinstance(v, str):
                v = v.strip()

            data[k] = v

        return data

    @classmethod
    def from_obj(cls, obj: Any, excludes: list[str] | None = None) -> Self:
        """
        从obj创建
        """

        from base.models import Document

        if isinstance(obj, Document):
            object = cls.model_validate(
                obj.dict(excludes=excludes, exclude_foreignkey=True)
            )
        elif isinstance(obj, pydantic.BaseModel):
            object = cls.model_validate(obj.model_dump())
        else:
            object = cls.model_validate(obj)

        return object


# ----------------------------------------------------------
#
#                           扩展模型
#
# ----------------------------------------------------------


class ChoiceModel(BaseModel):
    """
    Choice
    """

    code: int | str
    value: str

    @classmethod
    def from_obj(cls, obj: Any) -> Self:
        """
        从obj创建
        """

        from base.models import ChoiceField

        object = None

        if isinstance(obj, ChoiceField):
            object = cls(code=obj.code, value=obj.value)
        elif isinstance(obj, tuple | list):
            object = cls(code=obj[0], value=obj[1])
        else:
            object = cls.model_validate(obj)

        return object


class PaginationArgsModel(BaseModel):
    """
    分页参数
    """

    page: int
    limit: int

    def _offset(self) -> int:
        """
        offset
        """

        self.page = max(self.page, 1)

        return (self.page - 1) * self._limit()

    def _limit(self) -> int:
        """
        limit
        """

        self.limit = min(max(self.limit, 1), 200)

        return self.limit

    def queryset(self, queryset: mongoengine.QuerySet) -> mongoengine.QuerySet:
        """
        构建查询条件
        """

        if self._offset() >= queryset.count():
            return queryset.none()

        return queryset.limit(self._limit()).skip(self._offset())


class PaginationModel(BaseModel):
    """
    分页
    """

    count: int = 0
    num_pages: int = 0
    data: list[Any] = []

    def init(
        self,
        queryset: mongoengine.QuerySet | None,
        limit: int,
        count: int | None = None,
    ) -> None:
        """
        初始化
        """

        if count is not None:
            self.count = count
        else:
            self.count = queryset.count()

        self.num_pages = self.count // limit

        if self.count % limit > 0:
            self.num_pages += 1

        self.data = []


class ListModel(BaseModel):
    """
    列表
    """

    count: int = 0
    data: list[Any] = []

    def update(self) -> None:
        """
        更新数据
        """

        self.count = len(self.data)


class NameModel(BaseModel):
    """
    ID NAME模型
    """

    id: int | str
    name: str


class SuccessModel(BaseModel):
    """
    成功
    """

    success: bool = True
    data: dict | None = None


class FileModel(BaseModel):
    """
    文件
    """

    path: str


class LoginSuccessModel(BaseModel):
    """
    登录成功
    """

    token: str


class PasswordLoginArgsModel(BaseModel):
    """
    密码登录参数
    """

    username: str
    password: str


class PasswordUpdateModel(BaseModel):
    """
    密码更新
    """

    password: str
    new_password: str
