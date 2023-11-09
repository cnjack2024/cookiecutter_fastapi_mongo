import datetime
import json
import os
import shutil

import bson
import httpx
import mongoengine
import ulid

from pathlib import Path
from typing import Any, Self
from urllib.parse import urlparse

from mongoengine.base import BaseField
from mongoengine.fields import *

from base.exception import *
from base.util import now, localtime, make_url, sha256_hmac


class Document(mongoengine.Document):
    """
    文档
    """

    meta = {
        "abstract": True,
    }

    def __setattr__(self, name: str, value: Any) -> None:
        """
        设置属性
        """

        if name in self._fields:
            if isinstance(value, str):
                value = value.strip()

                if hasattr(self._fields[name], "max_length"):
                    value = value[: self._fields[name].max_length]

        super().__setattr__(name, value)

    def dict(
        self,
        excludes: list[str] | None = None,
        exclude_foreignkey: bool = False,
        exclude_none: bool = False,
    ) -> dict:
        """
        转换为dict
        """

        data = {}

        for key in self._fields:
            if excludes:
                if key in excludes:
                    continue

            if exclude_foreignkey:
                if isinstance(
                    self._fields[key],
                    ReferenceField | CachedReferenceField | GenericReferenceField,
                ):
                    continue

                if isinstance(self._fields[key], ListField):
                    if isinstance(
                        self._fields[key].field,
                        ReferenceField | CachedReferenceField | GenericReferenceField,
                    ):
                        continue

            value = getattr(self, key)

            if value is None:
                if not exclude_none:
                    data[key] = None

                continue

            if isinstance(value, Document):
                value = str(value.id)

            if isinstance(value, bson.ObjectId):
                value = str(value)

            if isinstance(value, StorageBaseField):
                value = value.path

            if hasattr(value, "dict"):
                value = value.dict()

            data[key] = value

        return data

    def from_data(
        self, data: dict, excludes: list[str] | None = None, exclude_none: bool = False
    ) -> None:
        """
        从dict更新
        """

        for key in self._fields:
            if key not in data:
                continue

            if excludes:
                if key in excludes:
                    continue

            if self._fields[key].primary_key:
                continue

            if isinstance(
                self._fields[key],
                ReferenceField | CachedReferenceField | GenericReferenceField,
            ):
                continue

            if isinstance(self._fields[key], ListField):
                if isinstance(
                    self._fields[key].field,
                    ReferenceField | CachedReferenceField | GenericReferenceField,
                ):
                    continue

            value = data.get(key)

            if value is None:
                if not exclude_none:
                    setattr(self, key, None)

                continue

            if isinstance(value, str):
                value = value.strip()

                if isinstance(self._fields[key], ObjectIdField | ReferenceField):
                    value = bson.ObjectId(value)

            setattr(self, key, value)

    def validate_data(self) -> None:
        """
        数据校验
        """

    @classmethod
    def _build_index_specs(cls, meta_indexes: list) -> list:
        """
        构建索引
        """

        index_specs = super()._build_index_specs(meta_indexes)

        for index_spec in index_specs:
            if "name" not in index_spec:
                index_spec["name"] = "idx_{}".format(
                    "_".join("{}_{}".format(*x) for x in index_spec["fields"])
                )

        return index_specs


# ----------------------------------------------------------
#
#                       Document Field
#
# ----------------------------------------------------------


class ChoiceField(BaseField):
    """
    Choice
    """

    def __init__(self, choices: tuple[int, str], value: int | None = None, **kwargs):
        self._choices = choices

        self.code = None
        self.value = None

        choice = self.to_python(value)

        if choice:
            self.code = choice.code
            self.value = choice.value

        super().__init__(**kwargs)

    def __set__(self, instance: Any, value: Any) -> None:
        if isinstance(value, self.__class__):
            value = value.code

        value = self.to_python(value)

        if value is None:
            if self.default is not None:
                value = self.default

                if callable(value):
                    value = value()

                value = self.to_python(value)

        return super().__set__(instance, value)

    def __eq__(self, other: Self | int) -> bool:
        if isinstance(other, self.__class__):
            return (self._choices, self.code) == (other._choices, other.code)

        if isinstance(other, int):
            if self.code:
                return self.code == other

        return False

    def __lt__(self, other: Self | int) -> bool:
        if isinstance(other, self.__class__):
            if self._choices == other._choices:
                return self.code < other.code

        if isinstance(other, int):
            if self.code:
                return self.code < other

        return False

    def __le__(self, other: Self | int) -> bool:
        if isinstance(other, self.__class__):
            if self._choices == other._choices:
                return self.code <= other.code

        if isinstance(other, int):
            if self.code:
                return self.code <= other

        return False

    def __gt__(self, other: Self | int) -> bool:
        return not (self <= other)

    def __ge__(self, other: Self | int) -> bool:
        return not (self < other)

    def __hash__(self) -> int:
        return hash(self.code)

    def __repr__(self) -> str:
        return str((self.code, self.value))

    def dict(self) -> dict:
        return {"code": self.code, "value": self.value}

    def to_mongo(self, value: Self) -> Any:
        return value.code

    def to_python(self, value: int | None) -> Self:
        if isinstance(value, int):
            for _choice in self._choices:
                if _choice[0] == value:
                    choice = self.__class__(self._choices)

                    choice.code = _choice[0]
                    choice.value = _choice[1]

                    return choice

        return None

    def validate(self, value: Self) -> None:
        for choice in self._choices:
            if (value.code, value.value) == tuple(choice):
                return

        self.error(f"{value} is not a valid {self._choices}")


class PasswordField(BaseField):
    """
    密码字段
    """

    def __init__(self, hash: bytes | str | None = None, **kwargs: Any):
        from passlib.context import LazyCryptContext

        self.context = LazyCryptContext(schemes=["pbkdf2_sha512"])

        if isinstance(hash, bytes):
            self.hash = hash
        elif isinstance(hash, str):
            self.hash = self.context.hash(hash).encode()
        else:
            self.hash = None

        super().__init__(**kwargs)

    def __set__(self, instance: Any, value: Any) -> None:
        if isinstance(value, self.__class__):
            value = value.hash

        if value is None:
            if self.default is not None:
                value = self.default

                if callable(value):
                    value = value()

        return super().__set__(instance, self.to_python(self.__class__(value).hash))

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, bytes | None):
            return self.hash == other

        if isinstance(other, self.__class__):
            return self.hash == other.hash

        return self.context.verify(str(other), self.hash)

    def __hash__(self) -> int:
        return hash(self.hash)

    def __repr__(self) -> str:
        return (self.hash or b"").decode()

    def to_mongo(self, value: Self) -> bson.Binary | None:
        if isinstance(value.hash, bytes):
            return bson.Binary(value.hash)

        return None

    def to_python(self, value: bytes | None) -> Self | None:
        if isinstance(value, bytes):
            return self.__class__(value)

        return None


class StorageBaseField(StringField):
    """
    存储字段(基类)
    """

    def __init__(self, path: str | None = None, **kwargs: Any):
        self.session = kwargs.pop("session", None)
        self._path = path

        super().__init__(max_length=254, **kwargs)

    def __set__(self, instance: Any, value: Any) -> None:
        if isinstance(value, self.__class__):
            value = value.path

        if value is None:
            if self.default is not None:
                value = self.default

                if callable(value):
                    value = value()

        return super().__set__(instance, self.to_python(value))

    def __repr__(self) -> str:
        return self.path or ""

    def to_mongo(self, value: Self) -> str | None:
        return value.path

    def to_python(self, value: str | None) -> Self | None:
        if isinstance(value, str):
            return self.__class__(value)

        return None

    def validate(self, value: Self) -> None:
        super().validate(value.path)

    @property
    def path(self) -> str | None:
        if isinstance(self._path, str):
            return urlparse(self._path).path.lstrip("/")

        return None

    @path.setter
    def path(self, path: str | None) -> None:
        self._path = path

    @property
    def url(self) -> str | None:
        return None

    def save(self, content: bytes) -> bool:
        """
        保存文件
        """

        return False

    def delete(self) -> bool:
        """
        删除文件
        """

        return True

    def content(self) -> bytes | None:
        """
        获取文件内容
        """

        return None

    @classmethod
    def content_from_url(cls, url: str) -> bytes | None:
        """
        从URL获取文件内容
        """

        return None

    def get_session(self) -> Any:
        """
        获取存储Session
        """

        return None


class StorageFileField(StorageBaseField):
    """
    存储字段(文件系统)
    """

    def __init__(self, path: str | None = None, **kwargs: Any):
        import config

        if hasattr(config, "STORAGE_DIR"):
            self.base_dir = getattr(config, "STORAGE_DIR")
        else:
            self.base_dir = config.BASE_DIR.joinpath("../storage").resolve()

        super().__init__(path, **kwargs)

    @property
    def url(self) -> str | None:
        import config

        accesskey = ulid.ulid()
        expires = localtime().shift(seconds=config.STORAGE_EXPIRED).int_timestamp
        signature = sha256_hmac(
            make_url(self.path, accesskey=accesskey, expires=expires)
        )

        return make_url(
            "{}{}".format("/storage/", self.path),
            accesskey=accesskey,
            expires=expires,
            signature=signature,
        )

    def save(self, content: bytes) -> bool:
        """
        保存文件
        """

        filename = self.base_dir.joinpath(self.path)

        try:
            filename.parent.mkdir(parents=True, exist_ok=True)

            with open(filename.as_posix(), "wb") as f:
                f.write(content)

            return True
        except Exception:
            pass

        return False

    def delete(self) -> bool:
        """
        删除文件
        """

        filename = self.base_dir.joinpath(self.path)

        try:
            if filename.is_file():
                os.remove(filename.as_posix())
            elif filename.is_dir():
                shutil.rmtree(filename.as_posix())
            else:
                pass

            return True
        except Exception:
            pass

        return False

    def content(self) -> bytes | None:
        """
        获取文件内容
        """

        filename = self.base_dir.joinpath(self.path)

        try:
            if filename.is_file():
                with open(filename.as_posix(), "rb") as f:
                    return f.read()
        except Exception:
            pass

        return None

    @classmethod
    def content_from_url(cls, url: str) -> bytes | None:
        """
        从URL获取文件内容
        """

        from urllib.parse import urlparse, parse_qsl

        r = urlparse(url)

        if r.path.startswith("/storage/"):
            path = r.path.removeprefix("/storage/")
            data = dict(parse_qsl(r.query))

            accesskey = data.get("accesskey", "")
            expires = data.get("expires", "")
            signature = data.get("signature", "")

            if signature != sha256_hmac(
                make_url(path, accesskey=accesskey, expires=expires)
            ):
                raise HTTPException(
                    detail="签名错误",
                    status_code=HTTP_400_BAD_REQUEST,
                )

            try:
                if now() > localtime(int(expires)):
                    raise HTTPException(
                        detail="签名过期",
                        status_code=HTTP_400_BAD_REQUEST,
                    )

                return cls(path).content()
            except Exception:
                raise HTTPException(
                    detail="签名错误",
                    status_code=HTTP_400_BAD_REQUEST,
                )

        return None


class StorageField(StorageFileField):
    """
    存储字段
    """


# ----------------------------------------------------------
#
#                           初始化
#
# ----------------------------------------------------------


def init_database() -> None:
    """
    初始化数据库
    """

    import config

    mongoengine.connect(
        db=config.DATABASE_NAME,
        host=config.DATABASE_URL,
        tz_aware=True,
        tzinfo=config.TIMEZONE,
    )


init_database()
